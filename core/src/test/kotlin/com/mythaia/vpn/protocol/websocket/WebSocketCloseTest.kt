package com.mythaia.vpn.protocol.websocket

import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * A server ends a proxied stream with a close frame. A normal one is the end
 * of the data, not a failure: reported as one, the stack reset the app's
 * connection and dropped what it had not yet read (a user's log on
 * 2026-10-14 was full of "WebSocket closed (1005)" from a CDN-fronted server).
 */
class WebSocketCloseTest {

    private class ScriptedTransport(reads: List<ByteArray>) : Transport {
        private val queue = ArrayDeque(reads)
        val sent = mutableListOf<ByteArray>()
        override suspend fun send(data: ByteArray) { sent += data }
        override fun sendAsync(data: ByteArray) { sent += data }
        override suspend fun receive(): ByteArray? = queue.removeFirstOrNull()
        override fun forceCancel() {}
    }

    private val upgrade = "HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray()

    private fun binary(payload: ByteArray) = byteArrayOf(0x82.toByte(), payload.size.toByte()) + payload

    private fun close(code: Int?): ByteArray =
        if (code == null) byteArrayOf(0x88.toByte(), 0)
        else byteArrayOf(0x88.toByte(), 2, (code shr 8).toByte(), code.toByte())

    private fun connection(vararg frames: ByteArray): Pair<WebSocketConnection, ScriptedTransport> {
        // The last data frame and the close arrive in one read, as they do off a CDN.
        val transport = ScriptedTransport(listOf(upgrade, frames.reduce { a, b -> a + b }))
        return WebSocketConnection(transport, WebSocketConfiguration(host = "example.com")) to transport
    }

    @Test
    fun `an empty close after the last data is the end of the stream`() = runBlocking {
        val (ws, transport) = connection(binary("tail".toByteArray()), close(null))
        ws.performUpgrade()
        assertArrayEquals("tail".toByteArray(), ws.receive())
        assertNull(ws.receive())
        // The close is answered with an empty close: 1005 is never sent.
        val reply = transport.sent.last()
        assertEquals(0x88, reply[0].toInt() and 0xFF)
        assertEquals(0, reply[1].toInt() and 0x7F)
    }

    @Test
    fun `normal closure and going away end the stream too`() = runBlocking {
        for (code in listOf(1000, 1001)) {
            val (ws, _) = connection(binary(byteArrayOf(1, 2, 3)), close(code))
            ws.performUpgrade()
            assertArrayEquals(byteArrayOf(1, 2, 3), ws.receive())
            assertNull("code $code", ws.receive())
        }
    }

    @Test
    fun `a close reporting a fault still fails`() = runBlocking {
        val (ws, _) = connection(close(1011))
        ws.performUpgrade()
        val error = assertThrows(WebSocketError.ConnectionClosed::class.java) { runBlocking { ws.receive() } }
        assertEquals(1011, error.code)
    }
}
