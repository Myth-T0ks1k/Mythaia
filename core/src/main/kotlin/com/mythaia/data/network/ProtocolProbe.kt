package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * A thorough check of one server: an HTTP request through it, optionally a
 * download whose hash is verified, and a UDP round trip — each reported
 * with its own error rather than a single pass/fail.
 *
 * The latency tester answers "how fast"; this answers "what exactly works",
 * which is what a diagnosis (or an interop test against a reference server)
 * needs.
 */
object ProtocolProbe {

    data class Target(
        val httpHost: String = "captive.apple.com",
        val httpPort: Int = 80,
        val httpPath: String = "/",
        /** When set, the body is downloaded and must hash to this (hex SHA-256). */
        val sha256: String? = null,
        val udpHost: String = "8.8.8.8",
        val udpPort: Int = 53,
        /** `dns` sends a query and checks the reply; `echo` expects the payload back. */
        val udpKind: String = "dns"
    )

    data class Report(
        val name: String,
        val protocol: String,
        val http: String,
        val download: String,
        val udp: String
    ) {
        val httpOk: Boolean get() = http.startsWith("OK")
        val udpOk: Boolean get() = udp.startsWith("OK")
    }

    private const val STEP_TIMEOUT_MS = 25_000L

    suspend fun probe(original: ProxyConfiguration, target: Target = Target()): Report = withContext(Dispatchers.IO) {
        val config = resolve(original)
        val label = describe(config)
        if (config.outboundProtocol.isLayer3) {
            val handshake = LatencyTester.test(config)
            val text = if (handshake is LatencyResult.Success) "OK ${handshake.ms}ms handshake" else "FAIL handshake: $handshake"
            return@withContext Report(config.name, label, text, "-", "-")
        }
        val http = step { httpGet(config, target, expectSuccess = target.sha256 == null) }
        val download = if (target.sha256 != null) step { httpGet(config, target, expectSha = target.sha256) } else "-"
        val udp = when (config.outboundProtocol) {
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> "n/a"
            else -> step { udpRoundTrip(config, target) }
        }
        Report(config.name, label, http, download, udp)
    }

    fun describe(config: ProxyConfiguration): String {
        val parts = mutableListOf(config.outboundProtocol.displayName)
        if (config.outboundProtocol == OutboundProtocol.VLESS || config.outboundProtocol == OutboundProtocol.VMESS ||
            config.outboundProtocol == OutboundProtocol.TROJAN
        ) {
            parts += config.transport
            parts += config.security
        }
        val tls = config.tls ?: config.trojanTls
        if (tls?.fragment != null) parts += "fragment"
        config.obfuscation?.let { parts.add(it) }
        config.flow?.let { parts.add(it) }
        return parts.joinToString("/")
    }

    /**
     * Runs one check detached, so a protocol layer that ignores cancellation
     * shows up as "STUCK" in the report instead of hanging the whole probe.
     * The stuck coroutine is cancelled and abandoned; whatever it holds is
     * released when its connection is closed by the timeout path.
     */
    private suspend fun step(block: suspend () -> String): String {
        val started = System.nanoTime()
        val job = detached.async { withTimeout(STEP_TIMEOUT_MS) { block() } }
        val outcome = withTimeoutOrNull(STEP_TIMEOUT_MS + 5_000) {
            runCatching { job.await() }
        }
        if (outcome == null) {
            job.cancel()
            return "FAIL STUCK: no answer and did not cancel within ${STEP_TIMEOUT_MS / 1000 + 5}s"
        }
        return outcome.fold(
            onSuccess = { "OK ${(System.nanoTime() - started) / 1_000_000}ms $it".trim() },
            onFailure = { "FAIL ${it.javaClass.simpleName}: ${it.message?.take(160)}" }
        )
    }

    private val detached = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + Dispatchers.IO)

    private suspend fun httpGet(
        config: ProxyConfiguration,
        target: Target,
        expectSuccess: Boolean = false,
        expectSha: String? = null
    ): String {
        val connection = ProxyClientFactory.connect(config, target.httpHost, target.httpPort)
        try {
            connection.send(
                ("GET ${target.httpPath} HTTP/1.1\r\nHost: ${target.httpHost}\r\nUser-Agent: mythaia-probe\r\n" +
                    "Connection: close\r\n\r\n").toByteArray()
            )
            val started = System.nanoTime()
            val response = readAll(connection, limit = 64L * 1024 * 1024)
            val headerEnd = indexOf(response, CRLF2)
            if (headerEnd < 0) error("no HTTP header in ${response.size} bytes")
            val head = String(response, 0, headerEnd, Charsets.ISO_8859_1)
            val status = head.lineSequence().first()
            val body = response.copyOfRange(headerEnd + 4, response.size)
            if (expectSuccess && !String(body).contains("Success")) {
                error("unexpected body: $status ${String(body).take(60)}")
            }
            if (expectSha != null) {
                val sha = MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }
                if (!sha.equals(expectSha, ignoreCase = true)) error("hash mismatch after ${body.size} bytes ($status)")
                val seconds = (System.nanoTime() - started) / 1e9
                return "${body.size / 1024}KB ${"%.1f".format(body.size / 1024.0 / 1024.0 / seconds)}MB/s"
            }
            return status.substringAfter(' ').take(20)
        } finally {
            connection.cancel()
        }
    }

    private suspend fun readAll(connection: ProxyConnection, limit: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var contentLength = -1L
        var headerEnd = -1
        while (out.size() < limit) {
            val chunk = try {
                connection.receive()
            } catch (e: Exception) {
                if (out.size() > 0) null else throw e
            } ?: break
            out.write(chunk)
            if (headerEnd < 0) {
                val bytes = out.toByteArray()
                headerEnd = indexOf(bytes, CRLF2)
                if (headerEnd >= 0) {
                    val head = String(bytes, 0, headerEnd, Charsets.ISO_8859_1)
                    contentLength = Regex("(?im)^content-length:\\s*(\\d+)").find(head)
                        ?.groupValues?.get(1)?.toLong() ?: -1L
                }
            }
            if (headerEnd >= 0 && contentLength >= 0 && out.size() >= headerEnd + 4 + contentLength) break
        }
        return out.toByteArray()
    }

    private suspend fun udpRoundTrip(config: ProxyConfiguration, target: Target): String {
        val connection = ProxyClientFactory.connectUDP(config, target.udpHost, target.udpPort)
        try {
            val payload = if (target.udpKind == "dns") dnsQuery("example.com")
            else "mythaia-echo-${System.nanoTime()}".toByteArray()
            connection.send(payload)
            val reply = connection.receive() ?: error("closed before reply")
            if (target.udpKind == "dns") {
                if (reply.size < 12 || reply[0] != payload[0] || reply[1] != payload[1]) error("bad DNS reply (${reply.size} bytes)")
                val answers = ((reply[6].toInt() and 0xff) shl 8) or (reply[7].toInt() and 0xff)
                return "dns answers=$answers"
            }
            if (!reply.contentEquals(payload)) error("echo mismatch (${reply.size} bytes)")
            return "echo"
        } finally {
            connection.cancel()
        }
    }

    private fun dnsQuery(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x4d, 0x59, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
        name.split('.').forEach { label -> out.write(label.length); out.write(label.toByteArray()) }
        out.write(byteArrayOf(0, 0, 1, 0, 1))
        return out.toByteArray()
    }

    private fun resolve(config: ProxyConfiguration): ProxyConfiguration {
        fun one(c: ProxyConfiguration): ProxyConfiguration {
            if (c.resolvedIP != null || DnsCache.isIpAddress(c.serverAddress)) return c
            return DnsCache.resolveHost(c.serverAddress)?.let { c.copy(resolvedIP = it) } ?: c
        }
        val chain = config.chain?.map(::one)
        return one(config).let { if (chain != null) it.copy(chain = chain) else it }
    }

    private val CRLF2 = "\r\n\r\n".toByteArray()

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    /**
     * Reads a matrix input file: header lines (`#http host:port/path [sha]`,
     * `#udp host:port dns|echo`, `#only text`, `#insecure`, `#naive11`)
     * followed by a subscription body.
     */
    data class Input(val target: Target, val only: String?, val insecure: Boolean, val naive11: Boolean, val body: ByteArray)

    fun readInput(bytes: ByteArray): Input {
        val text = String(bytes, Charsets.UTF_8)
        var target = Target()
        var only: String? = null
        var insecure = false
        var naive11 = false
        val lines = text.lines()
        var bodyStart = 0
        for ((index, line) in lines.withIndex()) {
            if (!line.startsWith("#")) { bodyStart = index; break }
            bodyStart = index + 1
            val parts = line.trim().split(Regex("\\s+"))
            when (parts[0]) {
                "#http" -> {
                    val hostPort = parts[1].substringBefore('/')
                    target = target.copy(
                        httpHost = hostPort.substringBeforeLast(':'),
                        httpPort = hostPort.substringAfterLast(':').toInt(),
                        httpPath = "/" + parts[1].substringAfter('/', ""),
                        sha256 = parts.getOrNull(2)
                    )
                }
                "#udp" -> target = target.copy(
                    udpHost = parts[1].substringBeforeLast(':'),
                    udpPort = parts[1].substringAfterLast(':').toInt(),
                    udpKind = parts.getOrNull(2) ?: "dns"
                )
                "#only" -> only = line.substringAfter("#only").trim()
                "#insecure" -> insecure = true
                "#naive11" -> naive11 = true
            }
        }
        val body = if (bodyStart == 0) bytes else lines.drop(bodyStart).joinToString("\n").toByteArray()
        return Input(target, only, insecure, naive11, body)
    }

    /** The configurations in an input file, parsed the way the app imports them. */
    fun configurationsOf(fileName: String, input: Input): List<ProxyConfiguration> {
        val configs = when {
            fileName.endsWith(".conf") ->
                listOf(ProxyConfiguration.fromWireGuardConfig(String(input.body, Charsets.UTF_8), fileName.removeSuffix(".conf")))
            input.naive11 -> String(input.body).lines().map { it.trim() }.filter { it.startsWith("https://") }
                .map { ProxyConfiguration.fromUrl(it, OutboundProtocol.NAIVE_HTTP11) }
            else -> SubscriptionFetcher.parse(input.body).configurations
        }
        return configs.filter { input.only == null || it.name.contains(input.only) }
    }
}
