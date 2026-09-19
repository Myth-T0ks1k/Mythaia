package com.mythaia.desktop.engine

import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/** The selector-driven socket against a loopback echo: send, receive, close. */
class NioSocketLoopbackTest {
    @Test
    fun `echo through NioSocket`() = runBlocking {
        val server = ServerSocket()
        server.bind(InetSocketAddress("127.0.0.1", 0))
        thread(isDaemon = true) {
            server.accept().use { c ->
                val buf = ByteArray(1024)
                val n = c.getInputStream().read(buf)
                c.getOutputStream().write(buf, 0, n)
                c.getOutputStream().flush()
            }
        }
        val socket = NioSocket()
        try {
            withTimeout(5_000) { socket.connect("127.0.0.1", server.localPort) }
            withTimeout(5_000) { socket.send("hello".toByteArray()) }
            val answer = withTimeout(5_000) { socket.receive() }
            assertEquals("hello", String(answer!!))
        } finally {
            socket.forceCancel()
            server.close()
        }
    }
}
