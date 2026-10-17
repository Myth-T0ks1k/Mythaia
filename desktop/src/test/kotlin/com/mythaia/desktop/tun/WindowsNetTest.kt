package com.mythaia.desktop.tun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/**
 * [WindowsNet.run] must come back by its deadline whatever the tool does:
 * TUN start calls it while holding the engine's lock, and a hung `netsh`
 * used to block it for good because the output was read before the timeout
 * was ever checked.
 */
class WindowsNetTest {

    @Before
    fun windowsOnly() {
        assumeTrue(WindowsNet.isWindows)
    }

    @Test
    fun `a command that exits gives its exit code and output`() {
        val result = WindowsNet.run(listOf("cmd", "/c", "echo mythaia"))
        assertTrue(result.ok)
        assertEquals("mythaia", result.output)
        assertFalse(WindowsNet.run(listOf("cmd", "/c", "exit 3")).ok)
    }

    @Test
    fun `a command that never exits is killed at the timeout`() {
        val started = System.nanoTime()
        // Prints a line a second for half a minute and keeps its output open.
        val result = WindowsNet.run(listOf("ping", "-n", "30", "127.0.0.1"), timeoutSec = 1)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertFalse(result.ok)
        assertTrue(result.output, result.output.startsWith("timed out"))
        assertTrue("took $elapsedMs ms", elapsedMs < 6_000)
    }

    @Test
    fun `a child left holding the output does not hold up the result`() {
        val started = System.nanoTime()
        // cmd exits at once; the ping it starts in the background inherits the output pipe.
        val result = WindowsNet.run(listOf("cmd", "/c", "start /b ping -n 8 127.0.0.1 >nul"), timeoutSec = 10)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertTrue(result.output, result.ok)
        assertTrue("took $elapsedMs ms", elapsedMs < 5_000)
    }
}
