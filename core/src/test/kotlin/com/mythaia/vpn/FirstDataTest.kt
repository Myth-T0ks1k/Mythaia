package com.mythaia.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FirstDataTest {

    private fun record(bodyLength: Int) = ByteArray(5 + bodyLength).also {
        it[0] = 0x16; it[1] = 0x03; it[2] = 0x01
        it[3] = (bodyLength shr 8).toByte(); it[4] = bodyLength.toByte()
    }

    @Test
    fun `a whole ClientHello record is complete`() {
        assertTrue(FirstData.isComplete(record(1800)))
    }

    @Test
    fun `a ClientHello cut at a segment boundary is not`() {
        val hello = record(1800)
        assertFalse(FirstData.isComplete(hello, 1360))
        assertFalse(FirstData.isComplete(hello, 3))
        assertTrue(FirstData.isComplete(hello + byteArrayOf(0x17, 0x03), hello.size + 2))
    }

    @Test
    fun `anything that is not TLS is complete at once, nothing is not`() {
        assertTrue(FirstData.isComplete("GET / HTTP/1.1\r\n".toByteArray()))
        assertTrue(FirstData.isComplete(byteArrayOf(0x05)))
        assertFalse(FirstData.isComplete(ByteArray(0)))
    }
}
