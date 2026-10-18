package com.mythaia.data.update

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.nio.file.Files
import java.security.MessageDigest

class UpdateClientTest {

    private lateinit var server: HttpServer
    private lateinit var dir: File
    private val payload = ByteArray(300_000) { (it * 31 % 251).toByte() }
    private val payloadSha = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
    private var hits = 0

    @Before
    fun setUp() {
        UpdateClient.allowPlainHttp = true
        dir = Files.createTempDirectory("update-test").toFile()
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/file.apk") { exchange ->
            hits++
            exchange.sendResponseHeaders(200, payload.size.toLong())
            exchange.responseBody.use { it.write(payload) }
        }
        server.createContext("/moved.apk") { exchange ->
            exchange.responseHeaders.add("Location", "/file.apk")
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        server.createContext("/missing.apk") { exchange ->
            exchange.sendResponseHeaders(404, -1)
            exchange.close()
        }
        server.start()
    }

    @After
    fun tearDown() {
        server.stop(0)
        dir.deleteRecursively()
        UpdateClient.allowPlainHttp = false
    }

    private fun asset(path: String, size: Long = payload.size.toLong()) =
        ReleaseAsset(path.trimStart('/'), "http://127.0.0.1:${server.address.port}$path", size, null)

    @Test
    fun `a file with the listed checksum is saved, with progress along the way`() = runBlocking {
        val dest = File(dir, "update.apk")
        var last = 0L
        val route = UpdateClient.download(asset("/moved.apk"), payloadSha, dest, listOf(UpdateRoute.Direct), 1 shl 20) { done, total ->
            assertTrue(done >= last)
            last = done
            assertEquals(payload.size.toLong(), total)
        }
        assertEquals(UpdateRoute.Direct, route)
        assertArrayEquals(payload, dest.readBytes())
        assertEquals(payload.size.toLong(), last)
        assertFalse(File(dir, "update.apk.part").exists())
    }

    @Test
    fun `a file with any other checksum is thrown away and not fetched twice`() = runBlocking {
        val dest = File(dir, "update.apk")
        try {
            UpdateClient.download(asset("/file.apk"), "00".repeat(32), dest, listOf(UpdateRoute.Direct, UpdateRoute.Direct), 1 shl 20)
            fail("accepted a wrong checksum")
        } catch (_: ChecksumMismatch) {
        }
        assertFalse(dest.exists())
        assertEquals(emptyList<String>(), dir.list()!!.toList())
        assertEquals(1, hits)
    }

    @Test
    fun `a route that fails hands over to the next`() = runBlocking {
        // A port nothing listens on, standing in for a proxy that is down.
        val closed = ServerSocket(0).use { it.localPort }
        val dead = UpdateRoute.LocalProxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", closed)))
        val dest = File(dir, "update.apk")
        val route = UpdateClient.download(asset("/file.apk"), payloadSha, dest, listOf(dead, UpdateRoute.Direct), 1 shl 20)
        assertEquals(UpdateRoute.Direct, route)
        assertArrayEquals(payload, dest.readBytes())
    }

    @Test
    fun `too large or missing files are refused`() = runBlocking {
        val dest = File(dir, "update.apk")
        for ((a, limit) in listOf(asset("/file.apk") to 1000L, asset("/file.apk", size = 0) to 1000L, asset("/missing.apk") to (1L shl 20))) {
            try {
                UpdateClient.download(a, payloadSha, dest, listOf(UpdateRoute.Direct), limit)
                fail("accepted ${a.name} under $limit")
            } catch (e: UpdateException) {
                assertTrue(e.message!!, e.message!!.contains("large") || e.message!!.contains("404"))
            }
            assertFalse(dest.exists())
        }
    }
}
