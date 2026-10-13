package com.mythaia.vpn.protocol.xhttp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ChunkedTransferDecoderTest {

    @Test
    fun `chunks come out as they complete`() {
        val decoder = ChunkedTransferDecoder()
        decoder.feed("5\r\nhel".toByteArray())
        assertNull(decoder.nextChunk())
        decoder.feed("lo\r\n3;ext=1\r\nabc\r\n0\r\n\r\n".toByteArray())
        assertEquals("hello", String(decoder.nextChunk()!!))
        assertEquals("abc", String(decoder.nextChunk()!!))
        assertNull(decoder.nextChunk())
        assertTrue(decoder.isFinished)
    }

    @Test
    fun `a body that is not chunked is an error, not an endless wait`() {
        val decoder = ChunkedTransferDecoder()
        decoder.feed("<html>not what was asked for</html>\r\n".toByteArray())
        assertThrows(XHttpError.HttpError::class.java) { decoder.nextChunk() }
    }

    @Test
    fun `a size line that never ends is an error too`() {
        val decoder = ChunkedTransferDecoder()
        decoder.feed(ByteArray(2048) { 'a'.code.toByte() })
        assertThrows(XHttpError.HttpError::class.java) { decoder.nextChunk() }
    }

    @Test
    fun `a chunk larger than what is buffered is refused up front`() {
        val decoder = ChunkedTransferDecoder()
        decoder.feed("ffffffff\r\n".toByteArray())
        assertThrows(XHttpError.HttpError::class.java) { decoder.nextChunk() }
    }

    @Test
    fun `pending bytes are capped`() {
        val decoder = ChunkedTransferDecoder()
        decoder.feed("3fffff\r\n".toByteArray())
        assertThrows(XHttpError.HttpError::class.java) {
            decoder.feed(ByteArray(ChunkedTransferDecoder.MAX_PENDING_BYTES))
        }
    }
}
