package com.mythaia.desktop.engine

import com.mythaia.data.network.ProtocolProbe
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket

/**
 * Byte-level trace of one relayed connection: listens on 127.0.0.1:21090
 * (`MYTHAIA_TRACE_PORT`) and sends each accepted connection through the server
 * of `MYTHAIA_HOLD_LINK` to `MYTHAIA_TRACE_TARGET` (host:port), printing every
 * chunk in both directions with its size and time. Point a client at it with
 * `curl --resolve host:443:127.0.0.1 https://host:21090/`.
 */
class RelayTraceSmoke {
    @Test
    fun `trace one relayed connection`() = runBlocking {
        val link = System.getenv("MYTHAIA_HOLD_LINK")
        val target = System.getenv("MYTHAIA_TRACE_TARGET")
        assumeTrue("MYTHAIA_HOLD_LINK / MYTHAIA_TRACE_TARGET not set", !link.isNullOrBlank() && !target.isNullOrBlank())
        val input = ProtocolProbe.readInput(link!!.toByteArray())
        val config = ProtocolProbe.configurationsOf("trace", input).first()
        CertificatePolicy.setAllowInsecure(input.insecure)
        val fragment = System.getenv("MYTHAIA_HOLD_FRAGMENT") != "off"
        com.mythaia.vpn.protocol.tls.FragmentPolicy.set(com.mythaia.data.model.FragmentSettings(isEnabled = fragment))
        println("TRACE app-fragment=$fragment early=${System.getenv("MYTHAIA_TRACE_EARLY") == "1"}")
        val host = target!!.substringBeforeLast(':')
        val port = target.substringAfterLast(':').toInt()
        val listenPort = System.getenv("MYTHAIA_TRACE_PORT")?.toInt() ?: 21090
        val connections = System.getenv("MYTHAIA_TRACE_COUNT")?.toInt() ?: 3

        ServerSocket(listenPort, 50, InetAddress.getLoopbackAddress()).use { server ->
            println("TRACE ready on $listenPort -> $host:$port via ${config.name}")
            repeat(connections) { n ->
                val client = withContext(Dispatchers.IO) { server.accept() }
                val start = System.nanoTime()
                fun t() = "%6d ms".format((System.nanoTime() - start) / 1_000_000)
                // MYTHAIA_TRACE_EARLY=1: read the client's first bytes before
                // dialling and send them with the request, as Xray does.
                val early = if (System.getenv("MYTHAIA_TRACE_EARLY") == "1") {
                    val buf = ByteArray(65536)
                    val r = withContext(Dispatchers.IO) { client.getInputStream().read(buf) }
                    println("TRACE #$n ${t()} early -> $r bytes")
                    if (r > 0) buf.copyOf(r) else null
                } else null
                // MYTHAIA_TRACE_EARLY_LIMIT=n: only the first n of those bytes go
                // with the request, the rest right after: a ClientHello split
                // over two TCP segments, as large post-quantum hellos are.
                val limit = System.getenv("MYTHAIA_TRACE_EARLY_LIMIT")?.toInt()
                val withHeader = if (early != null && limit != null && early.size > limit) early.copyOf(limit) else early
                val rest = if (early != null && withHeader != null && early.size > withHeader.size) early.copyOfRange(withHeader.size, early.size) else null
                val upstream = try {
                    ProxyClientFactory.connect(config, host, port, withHeader).also { c ->
                        if (rest != null) { c.send(rest); println("TRACE #$n ${t()} rest -> ${rest.size} bytes") }
                    }
                } catch (e: Exception) {
                    println("TRACE #$n ${t()} dial failed: $e")
                    client.close()
                    return@repeat
                }
                println("TRACE #$n ${t()} dialled")
                val up = CoroutineScope(Dispatchers.IO).launch {
                    val buf = ByteArray(65536)
                    val ins = client.getInputStream()
                    while (true) {
                        val r = try { ins.read(buf) } catch (e: Exception) { println("TRACE #$n ${t()} client read error $e"); -1 }
                        if (r < 0) { println("TRACE #$n ${t()} client EOF"); break }
                        println("TRACE #$n ${t()} -> $r bytes")
                        try { upstream.send(buf.copyOf(r)) } catch (e: Exception) { println("TRACE #$n ${t()} send error $e"); break }
                    }
                }
                var total = 0
                val outs = client.getOutputStream()
                withTimeoutOrNull(60_000) {
                    while (true) {
                        val data = try { upstream.receive() } catch (e: Exception) { println("TRACE #$n ${t()} receive error $e"); null }
                        if (data == null) { println("TRACE #$n ${t()} server EOF after $total bytes"); break }
                        total += data.size
                        if (total - data.size < 20_000) println("TRACE #$n ${t()} <- ${data.size} bytes (total $total)")
                        try { withContext(Dispatchers.IO) { outs.write(data) } } catch (e: Exception) { println("TRACE #$n ${t()} client write error $e"); break }
                    }
                } ?: println("TRACE #$n ${t()} still open after 60 s, $total bytes")
                up.cancel()
                upstream.cancel()
                client.close()
            }
        }
        CertificatePolicy.setAllowInsecure(false)
    }
}
