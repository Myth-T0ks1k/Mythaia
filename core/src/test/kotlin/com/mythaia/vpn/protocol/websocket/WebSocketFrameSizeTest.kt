package com.mythaia.vpn.protocol.websocket

import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class WebSocketFrameSizeTest {

    /** Hands out the given reads in order; swallows writes. */
    private class ScriptedTransport(reads: List<ByteArray>) : Transport {
        private val queue = ArrayDeque(reads)
        override suspend fun send(data: ByteArray) {}
        override fun sendAsync(data: ByteArray) {}
        override suspend fun receive(): ByteArray? = queue.removeFirstOrNull()
        override fun forceCancel() {}
    }

    private val upgrade = "HTTP/1.1 101 Switching Protocols\r\n\r\n".toByteArray()

    /** An unmasked binary frame header with the 64-bit length form. */
    private fun frameHeader(length: Long): ByteArray {
        val header = ByteArray(10)
        header[0] = 0x82.toByte()
        header[1] = 127
        for (i in 0 until 8) header[2 + i] = (length shr (56 - 8 * i)).toByte()
        return header
    }

    private fun pieces(bytes: ByteArray, size: Int): List<ByteArray> =
        (bytes.indices step size).map { bytes.copyOfRange(it, minOf(it + size, bytes.size)) }

    @Test
    fun `a frame larger than a megabyte is received whole`() = runBlocking {
        val payload = ByteArray(2 * 1024 * 1024) { it.toByte() }
        val reads = listOf(upgrade) + pieces(frameHeader(payload.size.toLong()) + payload, 65_536)
        val ws = WebSocketConnection(ScriptedTransport(reads), WebSocketConfiguration(host = "example.com"))
        ws.performUpgrade()
        assertArrayEquals(payload, ws.receive())
    }

    @Test
    fun `a frame declaring more than the maximum is refused at once`() = runBlocking {
        val reads = listOf(upgrade, frameHeader(17L * 1024 * 1024))
        val ws = WebSocketConnection(ScriptedTransport(reads), WebSocketConfiguration(host = "example.com"))
        ws.performUpgrade()
        assertThrows(WebSocketError.InvalidFrame::class.java) { runBlocking { ws.receive() } }
        Unit
    }
}
