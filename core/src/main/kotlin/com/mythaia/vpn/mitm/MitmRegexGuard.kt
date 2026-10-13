package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

/**
 * Raised when a guarded regex match, or a whole guarded rewrite, runs past its
 * deadline. The bridge treats it as "do not rewrite / drop this connection"
 * rather than letting a connection thread hang on catastrophic backtracking.
 */
class RegexDeadlineExceededException(message: String) : RuntimeException(message)

/**
 * A deadline guard for attacker-influenced `java.util.regex` matching.
 *
 * [MitmRewriter] runs two families of regex against bytes an attacker can shape:
 * the `url-pattern` gate (against the request URL) and `body-replace` search
 * patterns (against the response body). The patterns themselves come from
 * `.amrs` rule sets delivered by untrusted subscriptions, so a single
 * catastrophic-backtracking pattern (`(a+)+$` and friends) fed an adversarial
 * input can pin a CPU core for effectively forever. `java.util.regex` has no
 * built-in match timeout, and — crucially — it does **not** honour
 * [Thread.interrupt]: a watchdog that interrupts the matching thread is ignored,
 * the backtracking just keeps going.
 *
 * There are two mechanisms here, because the JVM gives two very different levels
 * of control depending on whether the caller owns the [CharSequence] the regex
 * runs against:
 *
 *  1. **[guardedContainsMatch] / [guardedFind] — the reliable, leak-free abort.**
 *     The one thing `java.util.regex` *does* do during backtracking is call
 *     [CharSequence.charAt] on its input, constantly. So we wrap the input in a
 *     [DeadlineCharSequence] whose [CharSequence.charAt]/[CharSequence.length]
 *     sample [System.nanoTime] and throw [RegexDeadlineExceededException] once
 *     the deadline passes. The throw unwinds the matcher's native-ish loop
 *     cleanly on the *same* thread — no thread is left pinned. This is the guard
 *     the task asks for, and it only works when the caller controls the
 *     CharSequence handed to the regex.
 *
 *  2. **[runWithRegexDeadline] — the whole-call wrapper the bridge uses.**
 *     [MitmRewriter.rewrite] compiles and runs its regexes internally, against
 *     `String`s it builds itself (the normalized URL, the decoded body text) —
 *     the bridge never sees, and so cannot wrap, those CharSequences, and
 *     [MitmRewriter] is off-limits to edit. So the guard can only bound the whole
 *     `rewrite()` call: it runs the block on a daemon worker and waits at most
 *     `deadlineMs`. On timeout it throws [RegexDeadlineExceededException] and the
 *     caller drops the connection. Because interrupt is ignored, the worker may
 *     keep running the pathological match until it finishes or the process exits
 *     (the worker pool is bounded and its threads are daemons, so the leak is
 *     capped and never blocks shutdown); but the per-message deadline frees the
 *     connection thread, which bounds the damage. A future refactor that let
 *     [MitmRewriter] take a guarded [CharSequence] (mechanism 1) would remove the
 *     residual pinned-worker risk entirely — see the risks in the port notes.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
object MitmRegexGuard {

    private val logger = MythaiaLogger("MitmRegexGuard")

    /**
     * A read-only view of [delegate] that throws [RegexDeadlineExceededException]
     * once [System.nanoTime] reaches [deadlineNanos].
     *
     * The deadline is sampled rather than checked on every single access: a
     * catastrophic backtrack makes [charAt] calls in the millions-to-billions, so
     * checking one in every [SAMPLE_MASK]+1 calls still trips within microseconds
     * of the deadline while keeping the per-character overhead off a legitimate
     * linear scan negligible. [length] — called by the matcher up front and
     * periodically — always checks, so even a pattern that somehow reads few
     * characters cannot outlast the deadline unbounded.
     *
     * The comparison is written as a subtraction (`now - deadline >= 0`) so it
     * stays correct across [System.nanoTime]'s arbitrary (and possibly negative)
     * origin and its eventual wraparound.
     *
     * A matcher touches its input from a single thread, so the sampling counter
     * needs no synchronization.
     */
    private class DeadlineCharSequence(
        private val delegate: CharSequence,
        private val deadlineNanos: Long
    ) : CharSequence {

        private var sampleCounter = 0

        override val length: Int
            get() {
                checkDeadline()
                return delegate.length
            }

        override fun get(index: Int): Char {
            if ((sampleCounter++ and SAMPLE_MASK) == 0) checkDeadline()
            return delegate[index]
        }

        override fun subSequence(startIndex: Int, endIndex: Int): CharSequence {
            checkDeadline()
            // Keep the same deadline on the slice: the matcher can re-scan a
            // captured region, and that re-scan must stay bounded too.
            return DeadlineCharSequence(delegate.subSequence(startIndex, endIndex), deadlineNanos)
        }

        override fun toString(): String = delegate.toString()

        private fun checkDeadline() {
            if (System.nanoTime() - deadlineNanos >= 0) {
                throw RegexDeadlineExceededException(
                    "regex match exceeded its deadline (catastrophic backtracking suspected)"
                )
            }
        }
    }

    /**
     * Wraps [input] so any `java.util.regex` match run against the returned
     * sequence aborts with [RegexDeadlineExceededException] once [deadlineMs]
     * elapses. This is the leak-free primitive; a caller that controls the
     * CharSequence a regex sees should prefer it over [runWithRegexDeadline].
     */
    fun guardedInput(input: CharSequence, deadlineMs: Long): CharSequence =
        DeadlineCharSequence(input, System.nanoTime() + deadlineMs.coerceAtLeast(0L) * 1_000_000L)

    /**
     * [Regex.containsMatchIn] with a deadline: fully evaluated on the calling
     * thread, and guaranteed to either answer or throw
     * [RegexDeadlineExceededException] within roughly [deadlineMs]. Leak-free.
     */
    fun guardedContainsMatch(regex: Regex, input: CharSequence, deadlineMs: Long): Boolean =
        regex.containsMatchIn(guardedInput(input, deadlineMs))

    /**
     * [Regex.find] with a deadline. The returned [MatchResult] is backed by the
     * guarded input, so its groups must be read promptly — reading a group after
     * the deadline can itself throw [RegexDeadlineExceededException]. Leak-free
     * while the match itself runs.
     */
    fun guardedFind(regex: Regex, input: CharSequence, deadlineMs: Long): MatchResult? =
        regex.find(guardedInput(input, deadlineMs))

    /**
     * Runs [block] (typically `rewriter.rewrite(msg)`) under a per-message
     * wall-clock deadline on a daemon worker, returning its result if it finishes
     * in time.
     *
     * The deadline is measured from submission, so a block that waits its whole
     * deadline out in the queue behind busy workers times out like one that ran
     * too long — a saturated pool degrades to dropped rewrites, never to a hang.
     *
     * @throws RegexDeadlineExceededException if [block] does not finish within
     *   [deadlineMs], or if the bounded worker pool *and* its queue are full
     *   (every worker pinned by an earlier pathological match and more waiting
     *   than the queue holds) — both are "drop the connection" signals for the
     *   caller. A pinned worker keeps running until its match returns; see the
     *   class note for why that residual leak is bounded rather than eliminated.
     */
    fun <T> runWithRegexDeadline(deadlineMs: Long, block: () -> T): T {
        val future: Future<T> = try {
            executor.submit(Callable<T> { block() })
        } catch (_: RejectedExecutionException) {
            logger.warning(
                "regex worker pool and queue saturated (workers pinned by catastrophic patterns); failing rewrite closed"
            )
            throw RegexDeadlineExceededException("regex worker pool saturated")
        }
        try {
            return future.get(deadlineMs.coerceAtLeast(0L), TimeUnit.MILLISECONDS)
        } catch (_: TimeoutException) {
            // Best-effort interrupt: it unwinds any non-regex blocking in the
            // block, but java.util.regex ignores it and keeps backtracking on the
            // abandoned worker. The deadline has still freed this (connection)
            // thread, which is the point.
            future.cancel(true)
            logger.warning("rewrite exceeded its ${deadlineMs}ms regex deadline; dropping the connection")
            throw RegexDeadlineExceededException("rewrite exceeded ${deadlineMs}ms regex deadline")
        } catch (e: ExecutionException) {
            // The block itself threw. Surface the original cause so a real bug
            // (or a guardedInput deadline inside the block) is not masked as a
            // generic failure.
            throw e.cause ?: e
        } catch (e: InterruptedException) {
            // The caller's coroutine/thread was cancelled: propagate cancellation.
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw e
        }
    }

    /** `true` for the bit-mask sampling (check the deadline every 2048th `charAt`). */
    private const val SAMPLE_MASK = 0x7FF

    /**
     * Upper bound on concurrently-running regex workers — the thread army a
     * burst of pinned matches can grow to, and so part of the DoS defence.
     */
    private const val MAX_REGEX_WORKERS = 32

    /**
     * How many rewrites may wait for a worker before a new one is refused. A
     * busy tunnel legitimately has far more than [MAX_REGEX_WORKERS] rewrites in
     * flight at once (every stream of every intercepted connection), and with no
     * queue each one past the 32nd was rejected outright — a burst of ordinary
     * traffic dropped streams. Queued rewrites still carry their own deadline
     * from submission, so the queue bounds latency as well as memory: a rewrite
     * that waits out its deadline is dropped, not run late.
     */
    private const val MAX_QUEUED_REWRITES = 256

    private val workerCount = AtomicLong(0)

    /**
     * [MAX_REGEX_WORKERS] core threads (allowed to time out, so a quiet tunnel
     * holds none) over a bounded [LinkedBlockingQueue], with
     * [ThreadPoolExecutor.AbortPolicy] only once the queue too is full. The core
     * size is the maximum on purpose: a [ThreadPoolExecutor] queues ahead of
     * growing past its core size, so a small core with a queue would serialise a
     * burst on one or two threads and time the rest out; with core == max every
     * submission up to the cap gets a thread at once and only the overflow waits.
     */
    private val executor = ThreadPoolExecutor(
        MAX_REGEX_WORKERS,
        MAX_REGEX_WORKERS,
        30L,
        TimeUnit.SECONDS,
        LinkedBlockingQueue(MAX_QUEUED_REWRITES),
        { runnable ->
            Thread(runnable, "mitm-regex-guard-${workerCount.incrementAndGet()}").apply {
                isDaemon = true
            }
        },
        ThreadPoolExecutor.AbortPolicy()
    ).apply { allowCoreThreadTimeOut(true) }
}
