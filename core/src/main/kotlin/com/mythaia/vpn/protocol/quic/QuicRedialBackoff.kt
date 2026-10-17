package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.ProxyError

/**
 * How long a pooled QUIC client (Hysteria2, TUIC) waits after a failed session
 * attempt before it dials the server again.
 *
 * Both clients bring their one session up under a lock. When a server went
 * dark, every dial queued on that lock took it in turn and ran a handshake of
 * its own to the 10 s timeout, so the n-th waiter waited n × 10 s, and the local
 * proxy filled its connection cap in the meantime and refused everything. Now a
 * dial that finds a recent failure on record fails at once with that failure's
 * reason instead of dialling again.
 *
 * The wait starts at three seconds and doubles with each failure in a row, up
 * to fifteen: short enough that a server back from a blip is used again almost
 * at once, long enough that a dead one costs one handshake per wait rather than
 * one per dial. A session that comes up clears the record.
 *
 * Failures are recorded under the client's lock, but [remainingNanos] is also
 * read without it by the UDP path, which is why the state is one immutable
 * snapshot behind a volatile field rather than several fields that could be
 * seen half-updated.
 */
internal class QuicRedialBackoff(private val nanoTime: () -> Long = System::nanoTime) {

    private class Failure(val retryAt: Long, val waitNanos: Long, val reason: String)

    @Volatile
    private var last: Failure? = null

    /** How long until another attempt may dial, in nanoseconds; zero when one may go now. */
    fun remainingNanos(): Long {
        val failure = last ?: return 0L
        return (failure.retryAt - nanoTime()).coerceAtLeast(0L)
    }

    /**
     * Throws when the last attempt failed too recently to dial again, naming
     * why it failed: the caller sees the server's real problem rather than an
     * unexplained refusal.
     */
    fun check(protocol: String) {
        val failure = last ?: return
        val left = failure.retryAt - nanoTime()
        if (left <= 0) return
        val seconds = (left + SECOND_NANOS - 1) / SECOND_NANOS
        throw ProxyError.ConnectionFailed(
            "$protocol: the last session attempt failed, next in $seconds s (${failure.reason})"
        )
    }

    /** Puts [cause] on record and lengthens the wait if the previous attempt failed too. */
    fun failed(cause: Throwable) {
        val previous = last
        val wait = if (previous == null) FIRST_WAIT_NANOS
        else minOf(previous.waitNanos * 2, MAX_WAIT_NANOS)
        last = Failure(nanoTime() + wait, wait, cause.message ?: cause.javaClass.simpleName)
    }

    /** A session came up: the next failure starts the wait from the beginning. */
    fun succeeded() {
        last = null
    }

    internal companion object {
        private const val SECOND_NANOS = 1_000_000_000L
        const val FIRST_WAIT_NANOS = 3 * SECOND_NANOS
        const val MAX_WAIT_NANOS = 15 * SECOND_NANOS
    }
}
