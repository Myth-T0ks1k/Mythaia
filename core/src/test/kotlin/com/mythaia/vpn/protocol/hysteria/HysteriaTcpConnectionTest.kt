package com.mythaia.vpn.protocol.hysteria

import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The wrapper that hands back the bytes which arrived in the same stream chunk
 * as the Hysteria TCPResponse.
 *
 * A server-first protocol (SSH, SMTP, IMAP, MySQL) sends its banner the moment
 * the stream opens, and it reaches the client glued to the response. Dropping
 * it — which is what discarding the parse buffer did — hangs those protocols,
 * so the invariant tested here is that the leftover is delivered first, before
 * the inner stream is read at all.
 */
class HysteriaTcpConnectionTest {

    /** Scripted inner stream: hands back queued reads in order, counts its reads. */
    private class FakeStream(private val reads: MutableList<ByteArray>) : ProxyConnection() {
        var receiveCalls = 0
            private set
        var cancelled = 0
            private set
        private var connected = true

        override val isConnected: Boolean get() = connected
        override suspend fun sendRaw(data: ByteArray) = Unit
        override fun sendRawAsync(data: ByteArray) = Unit
        override suspend fun receiveRaw(): ByteArray? {
            receiveCalls++
            return if (reads.isEmpty()) null else reads.removeAt(0)
        }

        override fun cancel() {
            cancelled++
            connected = false
        }
    }

    private fun ascii(text: String) = text.toByteArray(Charsets.US_ASCII)

    @Test
    fun `the banner behind the response is delivered before the stream is read`() = runBlocking {
        val inner = FakeStream(mutableListOf(ascii("more")))
        val banner = ascii("SSH-2.0-OpenSSH_9.6")
        val connection = HysteriaTcpConnection(inner, banner)

        // The banner comes out first, and the inner stream is not touched to
        // produce it.
        assertArrayEquals(banner, connection.receiveRaw())
        assertEquals(0, inner.receiveCalls)

        // Only then does the stream get read.
        assertArrayEquals(ascii("more"), connection.receiveRaw())
        assertEquals(1, inner.receiveCalls)
        assertNull(connection.receiveRaw())
    }

    @Test
    fun `an empty leftover reads straight through`() = runBlocking {
        val inner = FakeStream(mutableListOf(ascii("hello")))
        val connection = HysteriaTcpConnection(inner, ByteArray(0))

        assertArrayEquals(ascii("hello"), connection.receiveRaw())
        assertEquals(1, inner.receiveCalls)
    }
}
