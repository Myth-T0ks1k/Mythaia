package com.mythaia.desktop.engine

import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** One side of a relayed connection: the proxy server or a direct socket. */
interface Upstream {
    suspend fun send(data: ByteArray)
    /** Null at end of stream. */
    suspend fun receive(): ByteArray?
    fun close()
}

/** Opens upstreams for the local listeners; routing decisions happen inside. */
interface Dialer {
    /** Null when the route blocks this destination. */
    suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream?
    suspend fun dialUdp(host: String, port: Int): Upstream?

    /**
     * True when [host] goes through a protocol whose request should carry the
     * client's first bytes (VLESS, VMess). The listener then confirms the
     * connection before dialling, so the client sends them, and dials with
     * them; see `TunnelConstants.firstDataWaitMs`.
     */
    fun wantsFirstData(host: String): Boolean = false

    /**
     * True when [host] is this machine itself — loopback, link-local or the
     * unspecified address, as a literal or, for a name that would be dialled
     * direct, by resolution. A listener open to the LAN refuses those for
     * its LAN clients: `allowLan` shares the tunnel, not the host's own
     * services.
     */
    suspend fun isThisHost(host: String): Boolean = Router.isThisHostLiteral(host)
}

/** Byte counters the home screen shows. */
class TrafficStats {
    val up = AtomicLong(0)
    val down = AtomicLong(0)
    val connections = AtomicInteger(0)

    fun reset() {
        up.set(0); down.set(0); connections.set(0)
    }
}

/**
 * The local inbound: SOCKS5 (CONNECT and UDP ASSOCIATE) and HTTP (CONNECT
 * and plain forwarding), each port accepting either — the first byte says
 * which. Everything that arrives is handed to the [Dialer].
 */
class LocalProxyServer(private val dialer: Dialer, private val stats: TrafficStats) {
    private val logger = MythaiaLogger("LocalProxy")

    // Blocking socket I/O needs a thread per direction per connection; a
    // cached pool grows with the browser's connection count and shrinks after.
    private val pool = Executors.newCachedThreadPool { r ->
        Thread(r, "mythaia-io").apply { isDaemon = true }
    }
    private val io = pool.asCoroutineDispatcher()

    private var scope: CoroutineScope? = null
    private val listeners = mutableListOf<ServerSocket>()

    // Every accepted socket and UDP relay, so stop() can end them: a blocking
    // read on a pool thread does not notice a cancelled coroutine.
    private val clients: MutableSet<Socket> = ConcurrentHashMap.newKeySet()
    private val relays: MutableSet<DatagramSocket> = ConcurrentHashMap.newKeySet()
    /** Open connections per client address, for the per-host cap when the LAN is let in. */
    private val perClient = ConcurrentHashMap<InetAddress, AtomicInteger>()
    @Volatile private var lastRefusalLog = 0L
    private val running = AtomicBoolean(false)
    @Volatile private var udpEnabled = true
    @Volatile private var bindAddress: InetAddress = InetAddress.getLoopbackAddress()

    val isRunning: Boolean get() = running.get()

    @Throws(IOException::class)
    fun start(socksPort: Int, httpPort: Int, allowLan: Boolean, udp: Boolean) {
        if (running.get()) return
        udpEnabled = udp
        bindAddress = if (allowLan) InetAddress.getByName("0.0.0.0") else InetAddress.getLoopbackAddress()
        val ports = listOf(socksPort, httpPort).distinct().filter { it in 1..65535 }
        val opened = mutableListOf<ServerSocket>()
        try {
            for (port in ports) {
                val server = ServerSocket()
                server.reuseAddress = true
                server.bind(InetSocketAddress(bindAddress, port), 128)
                opened += server
            }
        } catch (e: IOException) {
            opened.forEach { runCatching { it.close() } }
            throw e
        }
        val newScope = CoroutineScope(SupervisorJob() + io)
        scope = newScope
        listeners.clear()
        listeners += opened
        running.set(true)
        for (server in opened) {
            newScope.launch { acceptLoop(server) }
        }
        logger.info("Listening on ${ports.joinToString { "${bindAddress.hostAddress}:$it" }}")
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        listeners.forEach { runCatching { it.close() } }
        listeners.clear()
        clients.forEach { runCatching { it.close() } }
        clients.clear()
        relays.forEach { runCatching { it.close() } }
        relays.clear()
        perClient.clear()
        scope?.cancel()
        scope = null
        logger.info("Stopped")
    }

    private suspend fun acceptLoop(server: ServerSocket) {
        val current = scope ?: return
        while (running.get() && !server.isClosed) {
            val client = try {
                withContext(io) { server.accept() }
            } catch (e: IOException) {
                if (!running.get() || server.isClosed) break
                // A failed accept is not a dead listener: Windows fails one
                // under load (no buffer space, too many sockets) or when a
                // filter driver resets the connection being accepted. Leaving
                // the loop here left the port bound with nobody accepting, the
                // app showing Connected, and the system proxy pointing at it.
                logger.warning("accept on port ${server.localPort}: ${e.message}")
                delay(ACCEPT_RETRY_MS)
                continue
            }
            val remote = client.inetAddress
            if (!admit(client, remote)) {
                runCatching { client.close() }
                continue
            }
            clients += client
            try {
                current.launch {
                    stats.connections.incrementAndGet()
                    try {
                        client.tcpNoDelay = true
                        handle(client)
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        logger.debug("connection: ${e.message ?: e}")
                    } finally {
                        stats.connections.decrementAndGet()
                        clients -= client
                        release(remote)
                        runCatching { client.close() }
                    }
                }
            } catch (e: Throwable) {
                // No thread for it (the system is out of them, or the pool was
                // shut down by stop): the slot it took must not stay taken.
                clients -= client
                release(remote)
                runCatching { client.close() }
                if (e is CancellationException) throw e
                logger.warning("Cannot serve a connection: $e")
                delay(ACCEPT_RETRY_MS)
            }
        }
    }

    /**
     * [Dialer.dial] with a deadline. Nothing reads the client while a dial
     * runs, so a dial that never finished — a server that went silent, a
     * queue of reconnects behind one — held its connection slot for good,
     * until the 1024 slots were gone and the proxy refused everything.
     */
    private suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream? =
        withDeadline { dialer.dial(host, port, initialData) }

    private suspend fun dialUdp(host: String, port: Int): Upstream? =
        withDeadline { dialer.dialUdp(host, port) }

    private suspend fun withDeadline(open: suspend () -> Upstream?): Upstream? {
        // The result lands outside the timeout block: one that arrives just as
        // the deadline passes is closed here instead of leaking.
        var opened: Upstream? = null
        val finished = withTimeoutOrNull(DIAL_TIMEOUT_MS) {
            opened = open()
            true
        }
        if (finished == null) {
            opened?.close()
            throw IOException("no connection within ${DIAL_TIMEOUT_MS / 1000} s")
        }
        return opened
    }

    /**
     * Every connection costs two pool threads for as long as it lives, so
     * there is a ceiling on them, and — once the LAN is let in — one on what
     * a single host may hold, so one misbehaving device cannot take the
     * proxy away from the others. Refusals are logged, but not one per
     * connection: a flood would then be a flood of log lines.
     */
    private fun admit(client: Socket, remote: InetAddress?): Boolean {
        val reason = when {
            clients.size >= MAX_CONNECTIONS -> "$MAX_CONNECTIONS connections open"
            remote == null -> null
            else -> {
                val count = perClient.computeIfAbsent(remote) { AtomicInteger() }
                if (count.incrementAndGet() > MAX_PER_CLIENT && !bindAddress.isLoopbackAddress) {
                    release(remote)
                    "$MAX_PER_CLIENT connections from it already"
                } else null
            }
        } ?: return true
        val now = System.currentTimeMillis()
        if (now - lastRefusalLog > REFUSAL_LOG_INTERVAL_MS) {
            lastRefusalLog = now
            logger.warning("Refusing ${remote?.hostAddress ?: "?"}: $reason")
        }
        return false
    }

    private fun release(remote: InetAddress?) {
        if (remote == null) return
        perClient.computeIfPresent(remote) { _, count -> if (count.decrementAndGet() <= 0) null else count }
    }

    /**
     * Whether [client] may be let at [host]: a client on another machine is
     * refused this machine's own addresses; see [Dialer.isThisHost].
     */
    private suspend fun refusedForLan(client: Socket, host: String): Boolean =
        client.inetAddress?.isLoopbackAddress != true && dialer.isThisHost(host)

    private suspend fun handle(client: Socket) {
        client.soTimeout = HANDSHAKE_TIMEOUT_MS
        val input = client.getInputStream()
        val output = client.getOutputStream()
        val first = withContext(io) { input.read() }
        if (first < 0) return
        when (first) {
            0x05 -> handleSocks5(client, input, output)
            0x04 -> logger.debug("SOCKS4 is not supported")
            else -> handleHttp(client, input, output, first)
        }
    }

    // ------------------------------------------------------------------ SOCKS5

    private suspend fun handleSocks5(client: Socket, input: InputStream, output: OutputStream) {
        val methodCount = readByte(input)
        val methods = readFully(input, methodCount)
        if (!methods.contains(0.toByte())) {
            write(output, byteArrayOf(0x05, 0xFF.toByte()))
            return
        }
        write(output, byteArrayOf(0x05, 0x00))

        val header = readFully(input, 4)
        if (header[0] != 0x05.toByte()) return
        val command = header[1].toInt()
        val (host, port) = readSocksAddress(input, header[3].toInt())

        when (command) {
            CMD_CONNECT -> {
                if (refusedForLan(client, host)) {
                    write(output, socksReply(REP_NOT_ALLOWED))
                    return
                }
                if (dialer.wantsFirstData(host)) {
                    // Confirm first, as Xray's inbounds do, so the client sends
                    // its first bytes and they go out with the request header.
                    // A dial that then fails can only close the connection.
                    write(output, socksReply(REP_SUCCESS))
                    val first = readFirstData(client, input)
                    val upstream = try {
                        dial(host, port, first)
                    } catch (e: Exception) {
                        logger.debug("dial $host:$port failed: ${e.message ?: e}")
                        null
                    } ?: return
                    if (first != null) stats.up.addAndGet(first.size.toLong())
                    client.soTimeout = 0
                    relay(client, input, output, upstream)
                    return
                }
                val upstream = try {
                    dial(host, port, null)
                } catch (e: Exception) {
                    logger.debug("dial $host:$port failed: ${e.message ?: e}")
                    write(output, socksReply(REP_HOST_UNREACHABLE))
                    return
                }
                if (upstream == null) {
                    write(output, socksReply(REP_NOT_ALLOWED))
                    return
                }
                write(output, socksReply(REP_SUCCESS))
                client.soTimeout = 0
                relay(client, input, output, upstream)
            }
            CMD_UDP_ASSOCIATE -> {
                if (!udpEnabled) {
                    write(output, socksReply(REP_COMMAND_NOT_SUPPORTED))
                    return
                }
                udpAssociate(client, input, output)
            }
            else -> write(output, socksReply(REP_COMMAND_NOT_SUPPORTED))
        }
    }

    private suspend fun udpAssociate(client: Socket, input: InputStream, output: OutputStream) {
        val clientIp = client.inetAddress ?: return
        val relaySocket = DatagramSocket(InetSocketAddress(bindAddress, 0))
        relays += relaySocket
        try {
            val bound = relaySocket.localAddress.let { if (it.isAnyLocalAddress) client.localAddress else it }
            val reply = ByteArrayOutputStream().apply {
                write(byteArrayOf(0x05, 0x00, 0x00))
                val addr = bound.address
                write(if (addr.size == 4) 0x01 else 0x04)
                write(addr)
                write(relaySocket.localPort ushr 8)
                write(relaySocket.localPort and 0xFF)
            }.toByteArray()
            write(output, reply)
            client.soTimeout = 0

            coroutineScope {
                val relayJob = launch { udpRelayLoop(relaySocket, clientIp) }
                // The association lives as long as the TCP control connection.
                try {
                    withContext(io) {
                        try {
                            while (input.read() >= 0) { /* clients send nothing here */ }
                        } catch (_: IOException) {
                        }
                    }
                } finally {
                    // Closing the socket is what ends the blocking receive;
                    // cancelling alone would wait for a datagram that never comes.
                    runCatching { relaySocket.close() }
                    relayJob.cancel()
                }
            }
        } finally {
            relays -= relaySocket
            runCatching { relaySocket.close() }
        }
    }

    /**
     * [clientIp] is the address the control connection came from: only
     * datagrams from it are relayed. The port is learned from the first one,
     * since RFC 1928 lets the client announce 0.0.0.0:0 in its request.
     */
    private suspend fun udpRelayLoop(relaySocket: DatagramSocket, clientIp: InetAddress) = coroutineScope {
        val upstreams = ConcurrentHashMap<String, Upstream>()
        val jobs = ConcurrentHashMap<String, Job>()
        val fromLan = !clientIp.isLoopbackAddress
        var clientAddress: SocketAddress? = null
        val buffer = ByteArray(65_535)
        try {
            while (true) {
                val packet = DatagramPacket(buffer, buffer.size)
                withContext(io) { relaySocket.receive(packet) }
                if (packet.address != clientIp) continue
                if (clientAddress == null) clientAddress = packet.socketAddress
                val data = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                if (data.size < 5 || data[2] != 0.toByte()) continue // fragments unsupported
                val parsed = runCatching { parseUdpHeader(data) }.getOrNull() ?: continue
                val (host, port, headerLength) = parsed
                if (fromLan && dialer.isThisHost(host)) continue
                val key = "$host:$port"
                val payload = data.copyOfRange(headerLength, data.size)
                val upstream = upstreams[key] ?: run {
                    val created = try {
                        dialUdp(host, port)
                    } catch (e: Exception) {
                        logger.debug("udp dial $key: ${e.message ?: e}")
                        null
                    } ?: return@run null
                    upstreams[key] = created
                    val header = data.copyOfRange(0, headerLength)
                    val target = clientAddress
                    jobs[key] = launch {
                        try {
                            while (true) {
                                val answer = created.receive() ?: break
                                stats.down.addAndGet(answer.size.toLong())
                                val out = ByteArray(header.size + answer.size)
                                System.arraycopy(header, 0, out, 0, header.size)
                                System.arraycopy(answer, 0, out, header.size, answer.size)
                                withContext(io) { relaySocket.send(DatagramPacket(out, out.size, target)) }
                            }
                        } catch (_: Exception) {
                        } finally {
                            upstreams.remove(key)
                            runCatching { created.close() }
                        }
                    }
                    created
                } ?: continue
                stats.up.addAndGet(payload.size.toLong())
                try {
                    upstream.send(payload)
                } catch (e: Exception) {
                    upstreams.remove(key)
                    jobs.remove(key)?.cancel()
                    runCatching { upstream.close() }
                }
            }
        } catch (_: Exception) {
        } finally {
            jobs.values.forEach { it.cancel() }
            upstreams.values.forEach { runCatching { it.close() } }
        }
    }

    /** host, port and the header length of a SOCKS5 UDP datagram. */
    private fun parseUdpHeader(data: ByteArray): Triple<String, Int, Int>? {
        var offset = 3
        val atyp = data[offset++].toInt()
        val host: String
        when (atyp) {
            0x01 -> {
                if (data.size < offset + 6) return null
                host = InetAddress.getByAddress(data.copyOfRange(offset, offset + 4)).hostAddress
                offset += 4
            }
            0x03 -> {
                val len = data[offset++].toInt() and 0xFF
                if (data.size < offset + len + 2) return null
                host = String(data, offset, len, Charsets.US_ASCII)
                offset += len
            }
            0x04 -> {
                if (data.size < offset + 18) return null
                host = InetAddress.getByAddress(data.copyOfRange(offset, offset + 16)).hostAddress
                offset += 16
            }
            else -> return null
        }
        val port = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
        offset += 2
        return Triple(host, port, offset)
    }

    private suspend fun readSocksAddress(input: InputStream, atyp: Int): Pair<String, Int> {
        val host = when (atyp) {
            0x01 -> InetAddress.getByAddress(readFully(input, 4)).hostAddress
            0x03 -> String(readFully(input, readByte(input)), Charsets.US_ASCII)
            0x04 -> InetAddress.getByAddress(readFully(input, 16)).hostAddress
            else -> throw IOException("bad address type $atyp")
        }
        val portBytes = readFully(input, 2)
        val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
        return host to port
    }

    private fun socksReply(code: Int): ByteArray =
        byteArrayOf(0x05, code.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    // ------------------------------------------------------------------- HTTP

    private suspend fun handleHttp(client: Socket, input: InputStream, output: OutputStream, firstByte: Int) {
        val head = readHead(input, firstByte) ?: return
        val headText = String(head.head, Charsets.ISO_8859_1)
        val lines = headText.split("\r\n").filter { it.isNotEmpty() }
        val requestLine = lines.firstOrNull() ?: return
        val parts = requestLine.split(" ")
        if (parts.size < 3) {
            write(output, httpError(400, "Bad Request"))
            return
        }
        val method = parts[0].uppercase()
        val target = parts[1]
        val version = parts[2]
        val headers = lines.drop(1)

        if (method == "CONNECT") {
            val (host, port) = splitHostPort(target, 443) ?: run {
                write(output, httpError(400, "Bad Request"))
                return
            }
            if (refusedForLan(client, host)) {
                write(output, httpError(403, "Forbidden"))
                return
            }
            if (dialer.wantsFirstData(host)) {
                // As for SOCKS: confirm first, dial with the client's first bytes.
                write(output, "$version 200 Connection established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                val first = readFirstData(client, input, head.remainder)
                val upstream = try {
                    dial(host, port, first)
                } catch (e: Exception) {
                    logger.debug("dial $host:$port failed: ${e.message ?: e}")
                    null
                } ?: return
                if (first != null) stats.up.addAndGet(first.size.toLong())
                client.soTimeout = 0
                relay(client, input, output, upstream)
                return
            }
            val upstream = try {
                dial(host, port, null)
            } catch (e: Exception) {
                logger.debug("dial $host:$port failed: ${e.message ?: e}")
                write(output, httpError(502, "Bad Gateway"))
                return
            }
            if (upstream == null) {
                write(output, httpError(403, "Forbidden"))
                return
            }
            write(output, "$version 200 Connection established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
            client.soTimeout = 0
            if (head.remainder.isNotEmpty()) {
                stats.up.addAndGet(head.remainder.size.toLong())
                upstream.send(head.remainder)
            }
            relay(client, input, output, upstream)
            return
        }

        // Plain HTTP: absolute-form target, or origin-form with a Host header.
        val hostHeader = headers.firstOrNull { it.startsWith("host:", ignoreCase = true) }
            ?.substringAfter(':')?.trim()
        val (host, port, path) = when {
            target.startsWith("http://", ignoreCase = true) -> {
                val rest = target.substring(7)
                val slash = rest.indexOf('/')
                val authority = if (slash >= 0) rest.substring(0, slash) else rest
                val p = if (slash >= 0) rest.substring(slash) else "/"
                val hp = splitHostPort(authority, 80) ?: run {
                    write(output, httpError(400, "Bad Request"))
                    return
                }
                Triple(hp.first, hp.second, p)
            }
            hostHeader != null -> {
                val hp = splitHostPort(hostHeader, 80) ?: run {
                    write(output, httpError(400, "Bad Request"))
                    return
                }
                Triple(hp.first, hp.second, target)
            }
            else -> {
                write(output, httpError(400, "Bad Request"))
                return
            }
        }
        if (refusedForLan(client, host)) {
            write(output, httpError(403, "Forbidden"))
            return
        }

        val forwarded = StringBuilder()
        forwarded.append(method).append(' ').append(path).append(' ').append(version).append("\r\n")
        var hasHost = false
        for (header in headers) {
            val name = header.substringBefore(':').trim().lowercase()
            when (name) {
                "proxy-connection", "proxy-authorization", "connection", "keep-alive" -> continue
                "host" -> hasHost = true
            }
            forwarded.append(header).append("\r\n")
        }
        if (!hasHost) forwarded.append("Host: ").append(if (port == 80) host else "$host:$port").append("\r\n")
        // One request per connection: the upstream stream is not re-parsed here.
        forwarded.append("Connection: close\r\n\r\n")
        val initial = forwarded.toString().toByteArray(Charsets.ISO_8859_1) + head.remainder

        val upstream = try {
            dial(host, port, initial)
        } catch (e: Exception) {
            logger.debug("dial $host:$port failed: ${e.message ?: e}")
            write(output, httpError(502, "Bad Gateway"))
            return
        }
        if (upstream == null) {
            write(output, httpError(403, "Forbidden"))
            return
        }
        stats.up.addAndGet(initial.size.toLong())
        client.soTimeout = 0
        relay(client, input, output, upstream)
    }

    private class Head(val head: ByteArray, val remainder: ByteArray)

    /** Reads up to the blank line; what came after it in the same read is [Head.remainder]. */
    private suspend fun readHead(input: InputStream, firstByte: Int): Head? = withContext(io) {
        val buffer = ByteArrayOutputStream()
        buffer.write(firstByte)
        val chunk = ByteArray(4096)
        while (buffer.size() < MAX_HEAD) {
            val bytes = buffer.toByteArray()
            val end = indexOfBlankLine(bytes)
            if (end >= 0) {
                return@withContext Head(bytes.copyOfRange(0, end + 4), bytes.copyOfRange(end + 4, bytes.size))
            }
            val n = input.read(chunk)
            if (n < 0) return@withContext null
            buffer.write(chunk, 0, n)
        }
        null
    }

    private fun indexOfBlankLine(bytes: ByteArray): Int {
        for (i in 0..bytes.size - 4) {
            if (bytes[i] == '\r'.code.toByte() && bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() && bytes[i + 3] == '\n'.code.toByte()) return i
        }
        return -1
    }

    private fun splitHostPort(authority: String, defaultPort: Int): Pair<String, Int>? {
        val text = authority.trim()
        if (text.isEmpty()) return null
        if (text.startsWith("[")) {
            val close = text.indexOf(']')
            if (close < 0) return null
            val host = text.substring(1, close)
            val port = text.substring(close + 1).removePrefix(":").toIntOrNull() ?: defaultPort
            return host to port
        }
        val colon = text.lastIndexOf(':')
        if (colon < 0 || text.count { it == ':' } > 1) return text to defaultPort
        val port = text.substring(colon + 1).toIntOrNull() ?: return null
        return text.substring(0, colon) to port
    }

    private fun httpError(code: Int, reason: String): ByteArray =
        "HTTP/1.1 $code $reason\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

    // ------------------------------------------------------------------ relay

    /**
     * Copies both ways until either side ends, then closes both. A
     * connection with no bytes either way for [IDLE_TIMEOUT_MS] is closed
     * too: the handshake timeout is off by now, and a client that went away
     * without a FIN would otherwise hold its two pool threads for good.
     */
    private suspend fun relay(client: Socket, input: InputStream, output: OutputStream, upstream: Upstream) {
        try {
            coroutineScope {
                val lastActivity = AtomicLong(System.nanoTime())
                val uplink = launch {
                    val buffer = ByteArray(32 * 1024)
                    try {
                        while (true) {
                            val n = withContext(io) { input.read(buffer) }
                            if (n < 0) break
                            if (n == 0) continue
                            lastActivity.set(System.nanoTime())
                            stats.up.addAndGet(n.toLong())
                            upstream.send(buffer.copyOf(n))
                        }
                    } catch (_: Exception) {
                    }
                }
                val downlink = launch {
                    try {
                        while (true) {
                            val data = upstream.receive() ?: break
                            if (data.isEmpty()) continue
                            lastActivity.set(System.nanoTime())
                            stats.down.addAndGet(data.size.toLong())
                            withContext(io) {
                                output.write(data)
                                output.flush()
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
                val watchdog = launch {
                    while (true) {
                        delay(IDLE_CHECK_MS)
                        if (System.nanoTime() - lastActivity.get() < IDLE_TIMEOUT_MS * 1_000_000L) continue
                        // Closing is what ends the blocking reads on the pool threads.
                        logger.debug("idle for ${IDLE_TIMEOUT_MS / 60_000} min; closing")
                        runCatching { upstream.close() }
                        runCatching { client.close() }
                        break
                    }
                }
                // The proxy protocols carry no half-close, so the connection
                // ends when either direction does — except that a client which
                // finished sending may still be waiting for the answer, so a
                // finished uplink gives the downlink a grace period first.
                try {
                    val uplinkFirst = kotlinx.coroutines.selects.select<Boolean> {
                        uplink.onJoin { true }
                        downlink.onJoin { false }
                    }
                    if (uplinkFirst) {
                        kotlinx.coroutines.withTimeoutOrNull(HALF_CLOSE_GRACE_MS) { downlink.join() }
                    }
                } finally {
                    runCatching { upstream.close() }
                    runCatching { client.close() }
                    uplink.cancel()
                    downlink.cancel()
                    watchdog.cancel()
                }
            }
        } finally {
            runCatching { upstream.close() }
            runCatching { client.close() }
        }
    }

    // ---------------------------------------------------------------- helpers

    /**
     * The client's first bytes after the connection was confirmed, after
     * [already] when some came with the request: read until they are whole
     * (`FirstData`: any non-TLS bytes, or a whole first TLS record), each read
     * waiting at most `TunnelConstants.firstDataWaitMs`. Null when the client
     * sent none in that time (a server-speaks-first protocol) or closed.
     */
    private suspend fun readFirstData(
        client: Socket,
        input: InputStream,
        already: ByteArray = ByteArray(0)
    ): ByteArray? = withContext(io) {
        val first = ByteArrayOutputStream().apply { write(already) }
        val chunk = ByteArray(32 * 1024)
        try {
            while (!com.mythaia.vpn.FirstData.isComplete(first.toByteArray())) {
                client.soTimeout = com.mythaia.vpn.TunnelConstants.firstDataWaitMs.toInt()
                val n = try {
                    input.read(chunk)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
                if (n < 0) break
                first.write(chunk, 0, n)
            }
        } finally {
            client.soTimeout = 0
        }
        first.toByteArray().takeIf { it.isNotEmpty() }
    }

    private suspend fun readByte(input: InputStream): Int = withContext(io) {
        val b = input.read()
        if (b < 0) throw IOException("closed")
        b
    }

    private suspend fun readFully(input: InputStream, count: Int): ByteArray = withContext(io) {
        val out = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(out, read, count - read)
            if (n < 0) throw IOException("closed")
            read += n
        }
        out
    }

    private suspend fun write(output: OutputStream, data: ByteArray) = withContext(io) {
        output.write(data)
        output.flush()
    }

    companion object {
        private const val HANDSHAKE_TIMEOUT_MS = 15_000
        private const val HALF_CLOSE_GRACE_MS = 30_000L
        /** Long enough for an idle-but-alive connection (a WebSocket, an IMAP IDLE) to be left alone. */
        private const val IDLE_TIMEOUT_MS = 10 * 60_000L
        private const val IDLE_CHECK_MS = 30_000L
        private const val MAX_CONNECTIONS = 1024
        /** A dial past this is given up, so its slot is not held for good; see [dial]. */
        private const val DIAL_TIMEOUT_MS = 30_000L
        private const val ACCEPT_RETRY_MS = 500L
        private const val MAX_PER_CLIENT = 256
        private const val REFUSAL_LOG_INTERVAL_MS = 10_000L
        private const val MAX_HEAD = 64 * 1024
        private const val CMD_CONNECT = 1
        private const val CMD_UDP_ASSOCIATE = 3
        private const val REP_SUCCESS = 0
        private const val REP_NOT_ALLOWED = 2
        private const val REP_HOST_UNREACHABLE = 4
        private const val REP_COMMAND_NOT_SUPPORTED = 7
    }
}

/** Whether [address] is a v4 literal; the relay reply needs the family. */
internal fun InetAddress.isV4(): Boolean = this is Inet4Address
