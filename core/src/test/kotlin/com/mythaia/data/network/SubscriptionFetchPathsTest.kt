package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Base64
import java.util.Collections
import kotlin.concurrent.thread

/** The fetch paths end to end against a local panel: body metadata, the fallback URL, and a fetch through a server. */
class SubscriptionFetchPathsTest {

    private lateinit var panel: HttpServer
    private val base get() = "http://127.0.0.1:${panel.address.port}"

    private val links = listOf(
        "trojan://secret@a.example.com:443?sni=a.example.com#A",
        "trojan://secret@b.example.com:443?sni=b.example.com#B"
    )

    @Before
    fun start() {
        panel = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
        fun route(path: String, headers: Map<String, String> = emptyMap(), body: () -> String) {
            panel.createContext(path) { exchange ->
                val bytes = body().toByteArray()
                headers.forEach { (k, v) -> exchange.responseHeaders.add(k, v) }
                exchange.sendResponseHeaders(200, bytes.size.toLong())
                exchange.responseBody.use { it.write(bytes) }
            }
        }
        val title = Base64.getEncoder().encodeToString("Мой VPN".toByteArray())
        route("/meta") {
            // Metadata above a base64 list, as some panels serve it.
            "#profile-title: base64:$title\n" +
                "#subscription-userinfo: upload=1; download=2; total=30; expire=1700000000\n" +
                "#announce: Hello\n" +
                "#new-url: https://elsewhere.example.com/sub\n" +
                Base64.getEncoder().encodeToString(links.joinToString("\n").toByteArray())
        }
        route("/headers", headers = mapOf("profile-title" to "From header")) {
            "#profile-title: From body\n" + links.joinToString("\n")
        }
        route("/fallback") { links.first() }
        panel.start()
    }

    @After
    fun stop() {
        panel.stop(0)
    }

    /** A port nothing listens on: bound once, then let go. */
    private fun deadPort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

    @Test
    fun `metadata comes from the body, around a base64 list`() = runBlocking {
        val result = SubscriptionFetcher.fetch("$base/meta")
        assertEquals(2, result.configurations.size)
        assertEquals("Мой VPN", result.name)
        assertEquals(1L, result.upload)
        assertEquals(30L, result.total)
        assertEquals(1_700_000_000_000L, result.expire)
        assertEquals("Hello", result.panel.announce)
        // Plain HTTP: anyone on the path could have written this one.
        assertNull(result.panel.newUrl)
    }

    @Test
    fun `a header beats the body`() = runBlocking {
        assertEquals("From header", SubscriptionFetcher.fetch("$base/headers").name)
    }

    @Test
    fun `the fallback URL answers when the main one does not`() = runBlocking {
        val subscription = Subscription(
            name = "P",
            url = "http://127.0.0.1:${deadPort()}/sub",
            fallbackUrl = "$base/fallback"
        )
        assertEquals(1, SubscriptionFetcher.fetch(subscription).configurations.size)

        val bothDead = subscription.copy(fallbackUrl = "http://127.0.0.1:${deadPort()}/sub")
        try {
            SubscriptionFetcher.fetch(bothDead)
            fail("expected a NetworkError")
        } catch (e: SubscriptionFetcher.FetchError.NetworkError) {
            assertTrue(e.detail, e.detail.contains("fallback URL"))
        }
    }

    @Test
    fun `a fetch through a server reaches the panel through it`() = runBlocking {
        val socks = Socks5Relay()
        try {
            val server = ProxyConfiguration.fromUrl("socks5://127.0.0.1:${socks.port}#relay")
            val subscription = Subscription(name = "P", url = "$base/headers")
            val result = SubscriptionFetcher.fetch(subscription, via = server)
            assertEquals(2, result.configurations.size)
            assertEquals("From header", result.name)
            assertEquals(listOf("127.0.0.1:${panel.address.port}"), socks.targets)
        } finally {
            socks.close()
        }
    }

    /** The smallest SOCKS5 server that relays one CONNECT per client, recording where to. */
    private class Socks5Relay : AutoCloseable {
        private val listener = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val port: Int get() = listener.localPort
        val targets: MutableList<String> = Collections.synchronizedList(ArrayList())

        init {
            thread(isDaemon = true) {
                while (!listener.isClosed) {
                    val client = runCatching { listener.accept() }.getOrNull() ?: break
                    thread(isDaemon = true) { runCatching { relay(client) }; runCatching { client.close() } }
                }
            }
        }

        private fun relay(client: Socket) {
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            check(input.readUnsignedByte() == 5)
            input.skipBytes(input.readUnsignedByte())
            output.write(byteArrayOf(5, 0))
            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 1)
            input.readUnsignedByte()
            val host = when (input.readUnsignedByte()) {
                1 -> ByteArray(4).also { input.readFully(it) }.joinToString(".") { (it.toInt() and 0xFF).toString() }
                3 -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                else -> error("address type")
            }
            val port = input.readUnsignedShort()
            targets += "$host:$port"
            Socket(host, port).use { upstream ->
                output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                val back = thread(isDaemon = true) { runCatching { upstream.getInputStream().copyTo(output) }; runCatching { client.shutdownOutput() } }
                runCatching { input.copyTo(upstream.getOutputStream()) }
                back.join(5_000)
            }
        }

        override fun close() = listener.close()
    }
}
