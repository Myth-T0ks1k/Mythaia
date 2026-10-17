package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.ProxyError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wait a pooled QUIC client keeps after a failed session attempt, on a
 * clock the test moves by hand so every boundary is exact.
 */
class QuicRedialBackoffTest {

    private val second = 1_000_000_000L
    private var now = 42 * second
    private val backoff = QuicRedialBackoff { now }

    private fun handshakeFailed() = ProxyError.ProtocolError("Hysteria: QUIC handshake failed")

    @Test
    fun `nothing on record lets a dial through`() {
        assertEquals(0L, backoff.remainingNanos())
        backoff.check("Hysteria")
    }

    @Test
    fun `a failure refuses dials until its wait runs out, and says why`() {
        backoff.failed(handshakeFailed())
        assertEquals(3 * second, backoff.remainingNanos())

        val refusal = assertThrows(ProxyError.ConnectionFailed::class.java) { backoff.check("Hysteria") }
        assertTrue(refusal.message, refusal.message!!.contains("QUIC handshake failed"))
        assertTrue(refusal.message, refusal.message!!.contains("next in 3 s"))

        // A nanosecond short of the wait is still inside it, rounded up.
        now += 3 * second - 1
        val late = assertThrows(ProxyError.ConnectionFailed::class.java) { backoff.check("Hysteria") }
        assertTrue(late.message, late.message!!.contains("next in 1 s"))

        now += 1
        assertEquals(0L, backoff.remainingNanos())
        backoff.check("Hysteria")
    }

    @Test
    fun `the wait doubles with each failure in a row, up to fifteen seconds`() {
        val waits = (1..5).map {
            backoff.failed(handshakeFailed())
            backoff.remainingNanos().also { now += it }
        }
        assertEquals(listOf(3, 6, 12, 15, 15).map { it * second }, waits)
    }

    @Test
    fun `a session that comes up starts the next wait from the beginning`() {
        repeat(3) {
            backoff.failed(handshakeFailed())
            now += backoff.remainingNanos()
        }
        backoff.succeeded()
        assertEquals(0L, backoff.remainingNanos())
        backoff.check("TUIC")

        backoff.failed(handshakeFailed())
        assertEquals(QuicRedialBackoff.FIRST_WAIT_NANOS, backoff.remainingNanos())
    }

    @Test
    fun `a failure without a message is still named`() {
        backoff.failed(UnsatisfiedLinkError())
        val refusal = assertThrows(ProxyError.ConnectionFailed::class.java) { backoff.check("TUIC") }
        assertTrue(refusal.message, refusal.message!!.contains("UnsatisfiedLinkError"))
    }

    @Test
    fun `the wait survives System nanoTime wrapping around`() {
        // nanoTime has an arbitrary origin and may sit anywhere in Long's
        // range; only differences between readings mean anything.
        now = Long.MAX_VALUE - second
        backoff.failed(handshakeFailed())
        assertEquals(3 * second, backoff.remainingNanos())
        now += 2 * second
        assertEquals(second, backoff.remainingNanos())
        now += second
        assertEquals(0L, backoff.remainingNanos())
    }
}
