package com.mythaia.vpn.protocol

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList

/**
 * A read that fails must end the one receive loop, through its error
 * handler, and nothing else. On 2026-10-14 a pooled HTTP/2 stream answered
 * 421; the failed read escaped `startReceiving` past its own catch, out of
 * the UDP flow's coroutine, and Android killed the whole VPN process.
 */
class ReceiveFailureTest {

    /** Delivers [chunks] in order, then fails with [failure] (or ends cleanly if null). */
    private class ScriptedConnection(
        chunks: List<ByteArray>,
        private val failure: Exception?
    ) : ProxyConnection() {
        private val queue = ArrayDeque(chunks)
        override val isConnected: Boolean get() = true
        override suspend fun sendRaw(data: ByteArray) {}
        override fun sendRawAsync(data: ByteArray) {}
        override suspend fun receiveRaw(): ByteArray? {
            queue.removeFirstOrNull()?.let { return it }
            failure?.let { throw it }
            return null
        }
        override fun cancel() {}
    }

    @Test
    fun `a failed read reaches the error handler and does not escape`() = runBlocking {
        val received = CopyOnWriteArrayList<String>()
        var reported: Exception? = null
        val failure = IOException("HTTP/2 CONNECT tunnel failed with status 421")
        val connection = ScriptedConnection(listOf("a".toByteArray(), "b".toByteArray()), failure)

        withTimeout(5_000) {
            connection.startReceiving(
                handler = { received += String(it) },
                errorHandler = { reported = it }
            )
        }

        assertEquals(listOf("a", "b"), received)
        assertEquals(failure.message, reported?.message)
    }

    @Test
    fun `a failed read leaves the scope that launched the loop alive`() = runBlocking {
        val uncaught = CopyOnWriteArrayList<Throwable>()
        val guard = kotlinx.coroutines.CoroutineExceptionHandler { _, e -> uncaught += e }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + guard)
        val connection = ScriptedConnection(emptyList(), IOException("stream 247 reset"))

        val job = scope.launch {
            connection.startReceiving(handler = {}, errorHandler = {})
        }
        withTimeout(5_000) { job.join() }

        assertTrue("an exception escaped the loop: $uncaught", uncaught.isEmpty())
        assertTrue(scope.coroutineContext[kotlinx.coroutines.Job]!!.isActive)
    }

    @Test
    fun `a clean end is reported as no error`() = runBlocking {
        var reported: Exception? = IOException("not called")
        ScriptedConnection(listOf("x".toByteArray()), null)
            .startReceiving(handler = {}, errorHandler = { reported = it })
        assertNull(reported)
    }
}
