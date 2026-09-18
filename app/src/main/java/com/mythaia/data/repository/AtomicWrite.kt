package com.mythaia.data.repository

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Writes [text] to [this] atomically: writes to a sibling `.tmp` file then
 * renames it into place via `ATOMIC_MOVE`, so a crash or kill mid-write
 * leaves either the previous file or the new one — never a half-written
 * file that the next launch can't decode.
 *
 * Falls back to `REPLACE_EXISTING` only on filesystems that don't support
 * atomic move (rare, but documented for FUSE-backed paths).
 */
internal fun File.writeTextAtomic(text: String) {
    // A name no concurrent writer can share. writeTextAsync serialises its
    // callers, but syncRoutingFile writes straight through from whatever
    // coroutine asked for it, and two of those sharing one temp file would
    // interleave their contents and rename the mixture into place.
    val tmp = File(parentFile, "$name.${java.util.UUID.randomUUID()}.tmp")
    // The rename is only atomic against a crash if the bytes are on disk
    // first; without the sync a power loss can commit the name and leave a
    // zero-length file behind it.
    java.io.FileOutputStream(tmp).use { out ->
        out.write(text.toByteArray(Charsets.UTF_8))
        out.flush()
        try { out.fd.sync() } catch (_: java.io.SyncFailedException) {}
    }
    try {
        Files.move(
            tmp.toPath(),
            toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING
        )
    } catch (_: AtomicMoveNotSupportedException) {
        Files.move(tmp.toPath(), toPath(), StandardCopyOption.REPLACE_EXISTING)
    } finally {
        // A failed move leaves the temp behind; with a unique name it would
        // otherwise accumulate one file per failure.
        if (tmp.exists()) tmp.delete()
    }
}

/**
 * Shared single-supervised IO scope for repository disk writes. Mirrors iOS
 * `Task.detached` — the caller publishes its in-memory state immediately and
 * the disk fsync happens asynchronously off the calling thread.
 *
 * Parallelism is limited to 1 so writes are executed in submission order:
 * unordered execution could let an older snapshot win the rename race and
 * persist stale data. (Each write now uses its own temp file, so the contents
 * can no longer interleave — but the ordering still matters.)
 */
internal val repositoryWriterScope: CoroutineScope =
    CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

/** Schedules an async write. Errors are swallowed and printed; the in-memory state is the source of truth. */
internal fun File.writeTextAsync(text: String, onError: ((Throwable) -> Unit)? = null) {
    repositoryWriterScope.launch {
        try {
            writeTextAtomic(text)
        } catch (e: Throwable) {
            onError?.invoke(e)
                ?: com.mythaia.vpn.util.MythaiaLogger("Store")
                    .error("Atomic write failed for ${this@writeTextAsync.name}: $e")
        }
    }
}

/**
 * Sets [this] aside as `name.corrupt-<time>` so a store that failed to decode
 * is not overwritten by the next save. Returns false if nothing was moved.
 */
internal fun File.quarantineCorrupt(): Boolean {
    if (!exists()) return false
    val target = File(parentFile, "$name.corrupt-${System.currentTimeMillis()}")
    return runCatching { renameTo(target) }.getOrDefault(false)
}
