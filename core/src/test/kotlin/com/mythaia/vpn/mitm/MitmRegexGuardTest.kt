package com.mythaia.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ReDoS deadline guard. A hostile `.amrs` subscription can ship a pattern
 * that makes `java.util.regex` run effectively forever on a crafted input; the
 * guard's contract is that a match either answers or is aborted within its
 * deadline.
 *
 * These tests drive the two guard mechanisms *deterministically*, without
 * relying on catastrophic backtracking actually occurring on the test JVM — on
 * a modern desktop JDK the classic amplifiers like `(a+)+$` are optimised away,
 * so a test that depended on them would prove nothing here even though the guard
 * still matters on the device's regex engine. Instead:
 *
 *  - the leak-free guard is shown aborting a long *linear* scan, which makes the
 *    same per-character [CharSequence.get] calls a catastrophic backtrack makes,
 *    just fewer of them — so the abort path is exercised identically;
 *  - the whole-call wrapper is shown freeing the caller from a block that simply
 *    overruns the wall-clock deadline.
 *
 * Every expectation comes from the guard's contract, never from its own output.
 */
class MitmRegexGuardTest {

    private val deadlineMs = 500L

    /** The guard must abort comfortably under this; a true hang would blow past it. */
    private val hardCeilingMs = 2_000L

    @Test
    fun `the leak-free guard aborts a match that runs past its deadline`() {
        // A five-million-character scan for a needle that is not there far
        // outlasts a 1 ms deadline (it is tens of milliseconds of charAt calls);
        // the guarded input throws mid-scan instead of running to the end. A
        // catastrophic backtrack is just a far longer such run, aborted the same
        // way — this exercises the abort without depending on the JVM backtracking.
        val haystack = "a".repeat(5_000_000)
        val start = System.nanoTime()
        assertThrows(RegexDeadlineExceededException::class.java) {
            MitmRegexGuard.guardedContainsMatch(Regex("zzz"), haystack, 1L)
        }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(
            "the guarded match should abort near its 1ms deadline, not scan to the end (took ${elapsedMs}ms)",
            elapsedMs < hardCeilingMs
        )
    }

    @Test
    fun `the whole-call wrapper frees the caller when the block overruns the deadline`() {
        // The wrapper is the bridge's real case: MitmRewriter runs its regex on a
        // String the bridge never holds, so the only lever is the wall clock. A
        // block that overruns must free the caller near the deadline, not hang.
        val start = System.nanoTime()
        assertThrows(RegexDeadlineExceededException::class.java) {
            MitmRegexGuard.runWithRegexDeadline(deadlineMs) {
                Thread.sleep(deadlineMs * 8) // far past the deadline
            }
        }
        val elapsedMs = (System.nanoTime() - start) / 1_000_000
        assertTrue(
            "the wrapper should free the caller near the ${deadlineMs}ms deadline (took ${elapsedMs}ms)",
            elapsedMs < hardCeilingMs
        )
    }

    @Test
    fun `a legitimate match still succeeds under the guard`() {
        // A normal URL gate against a normal URL: answers true, well within budget.
        val gate = Regex("https://[^/]*\\bexample\\.com/")
        assertTrue(MitmRegexGuard.guardedContainsMatch(gate, "https://www.example.com/path", deadlineMs))

        // A non-match is a clean false, not a throw.
        assertFalse(MitmRegexGuard.guardedContainsMatch(Regex("zzz"), "foo bar baz", deadlineMs))

        // find returns the matched span for a legitimate capture.
        val captured = MitmRegexGuard.guardedFind(Regex("id=(\\d+)"), "q=1&id=42&x=9", deadlineMs)
        assertEquals("42", captured?.groupValues?.get(1))
    }

    @Test
    fun `a burst of concurrent rewrites beyond the worker count waits its turn instead of failing closed`() {
        // 96 blocks each holding a worker briefly, through a pool of 32 workers.
        // With no queue the 33rd and beyond were rejected outright — a burst of
        // ordinary traffic dropped streams. Queued, every one completes well
        // inside its deadline.
        val burst = 96
        val results = java.util.concurrent.ConcurrentLinkedQueue<Any>()
        val threads = (0 until burst).map { i ->
            Thread {
                results.add(
                    runCatching {
                        MitmRegexGuard.runWithRegexDeadline(deadlineMs * 4) {
                            Thread.sleep(20)
                            i
                        }
                    }.getOrElse { it }
                )
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        val failures = results.filterIsInstance<Throwable>()
        assertTrue("every rewrite in the burst should complete, got $failures", failures.isEmpty())
        assertEquals(burst, results.size)
    }

    @Test
    fun `the wrapper returns a normal block result and propagates a matching verdict`() {
        assertEquals(42, MitmRegexGuard.runWithRegexDeadline(deadlineMs) { 40 + 2 })
        assertTrue(
            MitmRegexGuard.runWithRegexDeadline(deadlineMs) {
                Regex("foo").containsMatchIn("a foo b")
            }
        )
    }
}
