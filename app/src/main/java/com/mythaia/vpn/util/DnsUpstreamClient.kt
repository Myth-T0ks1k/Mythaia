package com.mythaia.vpn.util

import android.net.Network
import com.mythaia.vpn.SocketProtector
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

private val logger = MythaiaLogger("DNS")

/**
 * Asks a resolver of our choosing — plain UDP, DoH, or DoT — and hands back the
 * addresses. Stateless: one question, one socket (or one request), one answer.
 * The cache in front of it is [DnsCache].
 *
 * Every socket is protected and, where the platform allows, bound to the
 * underlying physical network. A DNS socket that went through the tunnel would
 * need DNS to build the tunnel.
 *
 * Ports the iOS `DNSUpstreamClient`, plus DoT, which iOS does not have.
 */
object DnsUpstreamClient {

    /**
     * Long enough for a slow link, short enough that a dead resolver does not
     * hold up the dial behind it.
     */
    const val QUERY_TIMEOUT_MS = 4_000

    /** The largest answer that will not fragment on any real path. */
    private const val UDP_PAYLOAD_SIZE = 1232

    private val random = SecureRandom()

    /** Which record types a lookup asks for. */
    enum class Family { IPV4, BOTH }

    /**
     * The addresses [host] resolves to at [upstream], IPv4 first.
     *
     * Returns an empty list when the resolver is unreachable, answers nonsense,
     * or has nothing — the caller falls back to the system resolver, so a
     * failure here is not worth an exception.
     */
    fun resolve(
        host: String,
        upstream: DnsUpstream,
        network: Network?,
        family: Family = Family.BOTH,
        timeoutMs: Int = QUERY_TIMEOUT_MS
    ): List<String> {
        val types = when (family) {
            Family.IPV4 -> listOf(DnsMessage.TYPE_A)
            Family.BOTH -> listOf(DnsMessage.TYPE_A, DnsMessage.TYPE_AAAA)
        }

        val addresses = ArrayList<String>()
        for (type in types) {
            try {
                addresses += query(host, type, upstream, network, timeoutMs)
            } catch (e: Exception) {
                // One family answering is an answer; NXDOMAIN for the other is
                // normal, and so is a resolver that simply has no AAAA.
                logger.debug("[DNS] $host type=$type via ${upstream.text}: ${e.message ?: e}")
            }
        }

        if (addresses.isEmpty()) {
            logger.warning("[DNS] ${upstream.text} has no address for $host")
        }
        // A resolver answering both families can repeat an address across them.
        return addresses.distinct()
    }

    private fun query(
        host: String,
        type: Int,
        upstream: DnsUpstream,
        network: Network?,
        timeoutMs: Int
    ): List<String> = when (upstream) {
        is DnsUpstream.System -> emptyList()
        is DnsUpstream.Plain -> queryPlain(host, type, upstream, network, timeoutMs)
        is DnsUpstream.Doh -> queryDoh(host, type, upstream, network, timeoutMs)
        is DnsUpstream.Dot -> queryDot(host, type, upstream, network, timeoutMs)
    }

    // MARK: - Plain UDP

    private fun queryPlain(
        host: String,
        type: Int,
        upstream: DnsUpstream.Plain,
        network: Network?,
        timeoutMs: Int
    ): List<String> {
        val id = nextId()
        val message = DnsMessage.makeQuery(host, type, id, UDP_PAYLOAD_SIZE)
            ?: throw IOException("name not encodable: $host")

        val serverAddress = bootstrap(upstream.server, network)
            ?: throw IOException("cannot resolve resolver ${upstream.server}")

        DatagramSocket().use { socket ->
            SocketProtector.protect(socket)
            socket.soTimeout = timeoutMs
            socket.send(DatagramPacket(message, message.size, serverAddress, upstream.port))

            val deadline = System.currentTimeMillis() + timeoutMs
            val buffer = ByteArray(UDP_PAYLOAD_SIZE)
            while (System.currentTimeMillis() < deadline) {
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val response = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                decode(response, id, host)?.let { return it }
                // Null means somebody else's answer on this socket; keep reading.
            }
            throw IOException("timed out")
        }
    }

    // MARK: - DoH

    private fun queryDoh(
        host: String,
        type: Int,
        upstream: DnsUpstream.Doh,
        network: Network?,
        timeoutMs: Int
    ): List<String> {
        // RFC 8484 asks for ID 0 so the request is cacheable.
        val id = 0
        val message = DnsMessage.makeQuery(host, type, id)
            ?: throw IOException("name not encodable: $host")

        val url = URL(upstream.url)
        // Network.openConnection resolves and routes on the physical interface,
        // so the request neither enters the tunnel nor comes back through
        // DnsCache — which is what would make this recurse.
        val connection = (network?.openConnection(url) ?: url.openConnection()) as HttpURLConnection

        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/dns-message")
            connection.setRequestProperty("Accept", "application/dns-message")
            connection.setRequestProperty("User-Agent", com.mythaia.vpn.protocol.ProxyUserAgent.chrome)
            connection.setFixedLengthStreamingMode(message.size)
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.useCaches = false

            connection.outputStream.use { it.write(message) }

            val status = connection.responseCode
            if (status != 200) throw IOException("DoH HTTP $status")

            val response = connection.inputStream.use { it.readBytes() }
            return decode(response, id, host) ?: throw IOException("malformed DoH response")
        } finally {
            connection.disconnect()
        }
    }

    // MARK: - DoT

    /**
     * RFC 7858: the same message as UDP carries, over TLS on 853, each one
     * prefixed with its own two-byte length.
     *
     * This goes through the platform's TLS rather than the app's own
     * [com.mythaia.vpn.protocol.tls.TlsClient]: a resolver is a public
     * certificate-authority endpoint, not a censored one, and the app's client
     * exists to fingerprint a hello the way a browser would — which is the
     * wrong thing to send a DNS resolver.
     */
    private fun queryDot(
        host: String,
        type: Int,
        upstream: DnsUpstream.Dot,
        network: Network?,
        timeoutMs: Int
    ): List<String> {
        val id = nextId()
        val message = DnsMessage.makeQuery(host, type, id)
            ?: throw IOException("name not encodable: $host")

        val serverAddress = bootstrap(upstream.server, network)
            ?: throw IOException("cannot resolve resolver ${upstream.server}")

        // Connect the raw socket first so it can be protected before the
        // handshake writes anything: a TLS socket that dialled through the
        // tunnel would already have looped.
        val raw = Socket()
        try {
            SocketProtector.protect(raw)
            raw.soTimeout = timeoutMs
            raw.connect(InetSocketAddress(serverAddress, upstream.port), timeoutMs)

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val tls = factory.createSocket(raw, upstream.server, upstream.port, true) as SSLSocket
            tls.use { socket ->
                socket.soTimeout = timeoutMs
                // SNI and hostname verification both key off the configured
                // name, not the address it resolved to.
                socket.sslParameters = SSLParameters().apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    if (!DnsCache.isIpAddress(upstream.server)) {
                        serverNames = listOf(SNIHostName(upstream.server))
                    }
                }
                socket.startHandshake()

                val out = socket.outputStream
                out.write(((message.size shr 8) and 0xFF))
                out.write((message.size and 0xFF))
                out.write(message)
                out.flush()

                val input = DataInputStream(socket.inputStream)
                val length = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
                if (length <= 0 || length > 65535) throw IOException("bad DoT length $length")
                val response = ByteArray(length)
                input.readFully(response)

                return decode(response, id, host) ?: throw IOException("DoT identifier mismatch")
            }
        } finally {
            runCatching { if (!raw.isClosed) raw.close() }
        }
    }

    // MARK: - Shared

    /**
     * The resolver's own address.
     *
     * Deliberately the platform resolver on the physical network, never
     * [DnsCache]: DnsCache is the thing calling us, and sending it back here
     * would loop. An address is returned as-is, which is the configuration that
     * needs no bootstrap at all.
     */
    private fun bootstrap(server: String, network: Network?): InetAddress? = try {
        if (network != null) network.getAllByName(server).firstOrNull()
        else InetAddress.getByName(server)
    } catch (e: Exception) {
        logger.warning("[DNS] Cannot resolve resolver $server: ${e.message ?: e}")
        null
    }

    /**
     * Null means "not ours, keep reading". A refusal is an empty answer, not a
     * failure: NXDOMAIN for one family is normal.
     */
    private fun decode(message: ByteArray, id: Int, name: String): List<String>? = try {
        DnsMessage.parseAddresses(message, id)
    } catch (_: DnsMessage.ParseFailure.IdentifierMismatch) {
        null
    } catch (e: DnsMessage.ParseFailure.ServerFailure) {
        logger.debug("[DNS] $name answered with RCODE ${e.rcode}")
        emptyList()
    }

    /** A query ID that an off-path attacker cannot guess. */
    private fun nextId(): Int = random.nextInt(0x10000)
}
