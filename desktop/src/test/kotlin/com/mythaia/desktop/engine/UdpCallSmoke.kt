package com.mythaia.desktop.engine

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.network.ProtocolProbe
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Call-shaped UDP through the core, without the tunnel: for every server in
 * the lab file `MYTHAIA_UDPCALL` (names filtered by `MYTHAIA_UDPCALL_ONLY`,
 * comma-separated substrings), each target in `MYTHAIA_UDPCALL_TARGETS`
 * (default the lab echo's two redirected addresses) gets a 50-packet-per-second
 * STUN stream of small and of 1100-byte packets for six seconds, and the
 * replies, loss and round trips are printed. `10.0.2.2` becomes
 * `MYTHAIA_UDPCALL_HOST` (default 127.0.0.1). Shadowsocks is left out: its
 * UDP goes through the tunnel's own session, not the stream factory.
 */
class UdpCallSmoke {
    @Test
    fun `call shaped udp through every lab server`() = runBlocking {
        val path = System.getenv("MYTHAIA_UDPCALL")
        assumeTrue("MYTHAIA_UDPCALL not set", !path.isNullOrBlank())
        val file = File(path!!).takeIf { it.exists() } ?: File("..", path)
        val host = System.getenv("MYTHAIA_UDPCALL_HOST") ?: "127.0.0.1"
        val only = System.getenv("MYTHAIA_UDPCALL_ONLY")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
        val targets = (System.getenv("MYTHAIA_UDPCALL_TARGETS") ?: "1.2.3.4:9053,5.6.7.8:9053").split(',')

        val input = ProtocolProbe.readInput(String(file.readBytes(), Charsets.UTF_8).replace("10.0.2.2", host).toByteArray())
        CertificatePolicy.setAllowInsecure(input.insecure)
        val configs = ProtocolProbe.configurationsOf(file.name, input)
            .map { if (it.serverAddress == "10.0.2.2") it.copy(serverAddress = host) else it }
            .filter { it.outboundProtocol != OutboundProtocol.SHADOWSOCKS }
            .filter { only.isEmpty() || only.any { o -> it.name.contains(o, ignoreCase = true) } }

        for (config in configs) {
            println("== ${config.name}")
            val lines = targets.flatMap { target -> listOf(64, 1100).map { size -> target to size } }
                .map { (target, size) -> async(Dispatchers.IO) { stream(config, target, size) } }
                .awaitAll()
            lines.sorted().forEach { println("   $it") }
            com.mythaia.vpn.protocol.quic.QuicClientPool.closeAll()
        }
        CertificatePolicy.setAllowInsecure(false)
    }

    private suspend fun stream(config: com.mythaia.data.model.ProxyConfiguration, target: String, size: Int): String {
        val targetHost = target.substringBeforeLast(':')
        val targetPort = target.substringAfterLast(':').toInt()
        val connection = runCatching { ProxyClientFactory.connectUDP(config, targetHost, targetPort) }
            .getOrElse { return "$target ${size}B: connect failed: $it" }
        val random = SecureRandom()
        val sentAt = ConcurrentHashMap<String, Long>()
        val rtts = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val total = 300
        val reader = kotlinx.coroutines.CoroutineScope(Dispatchers.IO).launch {
            while (true) {
                val data = runCatching { connection.receive() }.getOrNull() ?: break
                if (data.size < 20) continue
                val id = data.copyOfRange(8, 20).joinToString("") { "%02x".format(it) }
                sentAt.remove(id)?.let { rtts += (System.nanoTime() - it) / 1_000_000 }
            }
        }
        for (i in 0 until total) {
            val tid = ByteArray(12).also(random::nextBytes)
            val attrLen = if (size > 24) ((size - 24) / 4) * 4 else 0
            val body = ByteArray(if (size > 24) 24 + attrLen else 20)
            body[1] = 1
            body[4] = 0x21; body[5] = 0x12; body[6] = 0xa4.toByte(); body[7] = 0x42
            tid.copyInto(body, 8)
            if (size > 24) {
                body[20] = 0x80.toByte(); body[21] = 0x2f
                body[22] = (attrLen shr 8).toByte(); body[23] = attrLen.toByte()
                val msgLen = 4 + attrLen
                body[2] = (msgLen shr 8).toByte(); body[3] = msgLen.toByte()
            }
            sentAt[tid.joinToString("") { "%02x".format(it) }] = System.nanoTime()
            runCatching { connection.send(body) }
            delay(20)
        }
        withTimeoutOrNull(1500) { while (sentAt.isNotEmpty()) delay(50) }
        connection.cancel()
        reader.cancel()
        val sorted = rtts.sorted()
        val median = sorted.getOrNull(sorted.size / 2) ?: -1
        val p95 = sorted.getOrNull(sorted.size * 95 / 100) ?: -1
        return "$target ${size}B: ${sorted.size}/$total replies, rtt median ${median}ms p95 ${p95}ms"
    }
}
