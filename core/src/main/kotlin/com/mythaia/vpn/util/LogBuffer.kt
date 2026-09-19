package com.mythaia.vpn.util

import com.mythaia.vpn.TunnelConstants
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Thread-safe ring buffer for user-facing logs forwarded from [MythaiaLogger.logSink].
 *
 * Entries older than [TunnelConstants.logRetentionIntervalSec] are evicted on
 * every write, and the buffer is capped at [TunnelConstants.logMaxEntries].
 */
object LogBuffer {

    private val RETENTION_SECONDS = TunnelConstants.logRetentionIntervalSec
    private val MAX_ENTRIES = TunnelConstants.logMaxEntries

    data class Entry(
        /** Monotonic sequence number — a stable identity for UI list keys. */
        val seq: Long,
        val timestamp: Long,
        val level: MythaiaLogger.Level,
        val message: String
    )

    private val lock = ReentrantLock()
    private val entries = ArrayDeque<Entry>(MAX_ENTRIES + 1)
    private var nextSeq = 0L

    private val _state = MutableStateFlow<List<Entry>>(emptyList())
    val state: StateFlow<List<Entry>> = _state

    fun append(message: String, level: MythaiaLogger.Level) {
        val now = System.currentTimeMillis()
        val snapshot = lock.withLock {
            entries.addLast(Entry(nextSeq++, now, level, message))
            compact(now)
            entries.toList()
        }
        _state.value = snapshot
    }

    fun fetchLogs(): List<Entry> = lock.withLock {
        compact(System.currentTimeMillis())
        entries.toList()
    }

    fun clear() {
        lock.withLock { entries.clear() }
        _state.value = emptyList()
    }

    /** Caller must hold [lock]. */
    private fun compact(now: Long) {
        val cutoff = now - RETENTION_SECONDS * 1000L
        while (entries.isNotEmpty() && entries.first().timestamp < cutoff) {
            entries.removeFirst()
        }
        while (entries.size > MAX_ENTRIES) {
            entries.removeFirst()
        }
    }
}
