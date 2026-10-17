package com.mythaia.desktop.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * The client side of the service pipe gives up by its deadline: a service
 * that accepts and then hangs must not freeze the window that asked.
 */
class NamedPipeTest {

    @Before
    fun windowsOnly() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows"))
    }

    private fun pipeName() = "\\\\.\\pipe\\MythaiaTest-${UUID.randomUUID()}"

    /** Waits until the server thread has created its pipe instance. */
    private fun awaitListening(name: String) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!NamedPipe.exists(name)) {
            if (System.nanoTime() > deadline) fail("pipe server did not come up")
            Thread.sleep(10)
        }
    }

    @Test
    fun `no server means null, and quickly`() {
        val started = System.nanoTime()
        assertNull(NamedPipe.exchange(pipeName(), "ping", 5_000))
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertTrue("took $elapsedMs ms", elapsedMs < 2_000)
    }

    @Test
    fun `a server that never answers times out`() {
        val name = pipeName()
        val release = CountDownLatch(1)
        val server = thread(isDaemon = true) {
            NamedPipe.accept(name).use { connection ->
                connection.readLine()
                release.await(10, TimeUnit.SECONDS)
            }
        }
        try {
            awaitListening(name)
            val started = System.nanoTime()
            try {
                NamedPipe.exchange(name, "ping", 700)
                fail("expected a timeout")
            } catch (e: IOException) {
                // The reply never came.
            }
            val elapsedMs = (System.nanoTime() - started) / 1_000_000
            assertTrue("took $elapsedMs ms", elapsedMs in 600..3_000)
        } finally {
            release.countDown()
            server.join(3_000)
        }
    }

    @Test
    fun `a reply is read up to its newline`() {
        val name = pipeName()
        val server = thread(isDaemon = true) {
            NamedPipe.accept(name).use { connection ->
                val request = connection.readLine()
                connection.writeLine("echo $request")
            }
        }
        try {
            awaitListening(name)
            assertEquals("echo привет", NamedPipe.exchange(name, "привет", 2_000))
        } finally {
            server.join(3_000)
        }
    }
}
