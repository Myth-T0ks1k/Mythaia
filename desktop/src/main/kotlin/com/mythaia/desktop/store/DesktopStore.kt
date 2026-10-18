package com.mythaia.desktop.store

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * JSON files under `%APPDATA%\Mythaia`, written whole and atomically: the
 * new text goes to a sibling file first and is moved into place, so a crash
 * mid-write leaves the previous version, never a truncated one.
 *
 * Saves return at once. The value is handed to one background writer,
 * which encodes and writes it; a save of a file whose last save is still
 * waiting replaces that one, so a burst of changes to a 10,000-server list
 * costs one encode and one write, and the caller — the UI thread, often,
 * under AppState's lock — never waits for the disk. [flush] waits for what
 * is queued, on the way out.
 */
class DesktopStore {
    private val logger = MythaiaLogger("Store")

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = true
        isLenient = true
    }

    /**
     * The server list without indentation or default values: a fraction of
     * the pretty form for a big list. Every version reads it, since a
     * missing key is its default to them too: ProxyConfiguration has changed
     * no key or default since 1.0.0, and Android has always stored it this way.
     */
    private val compactJson = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    fun loadSettings(): DesktopSettings =
        read(AppPaths.settings, DesktopSettings.serializer()) ?: DesktopSettings()

    fun saveSettings(settings: DesktopSettings) =
        save(AppPaths.settings) { json.encodeToString(DesktopSettings.serializer(), settings) }

    fun loadConfigurations(): List<ProxyConfiguration> =
        read(AppPaths.configs, ListSerializer(ProxyConfiguration.serializer())) ?: emptyList()

    fun saveConfigurations(configurations: List<ProxyConfiguration>) =
        save(AppPaths.configs) { encodeConfigurations(configurations) }

    internal fun encodeConfigurations(configurations: List<ProxyConfiguration>): String =
        compactJson.encodeToString(ListSerializer(ProxyConfiguration.serializer()), configurations)

    internal fun decodeConfigurations(text: String): List<ProxyConfiguration> =
        json.decodeFromString(ListSerializer(ProxyConfiguration.serializer()), text)

    fun loadSubscriptions(): List<Subscription> =
        read(AppPaths.subscriptions, ListSerializer(Subscription.serializer())) ?: emptyList()

    fun saveSubscriptions(subscriptions: List<Subscription>) =
        save(AppPaths.subscriptions) { json.encodeToString(ListSerializer(Subscription.serializer()), subscriptions) }

    fun loadChains(): List<com.mythaia.data.model.ProxyChain> =
        read(AppPaths.chains, ListSerializer(com.mythaia.data.model.ProxyChain.serializer())) ?: emptyList()

    fun saveChains(chains: List<com.mythaia.data.model.ProxyChain>) =
        save(AppPaths.chains) { json.encodeToString(ListSerializer(com.mythaia.data.model.ProxyChain.serializer()), chains) }

    fun loadRules(): List<RouteRule> =
        read(AppPaths.rules, ListSerializer(RouteRule.serializer())) ?: emptyList()

    fun saveRules(rules: List<RouteRule>) =
        save(AppPaths.rules) { json.encodeToString(ListSerializer(RouteRule.serializer()), rules) }

    // ------------------------------------------------------------ writer

    /** Saves not yet started, newest per file; guarded by [queueLock]. */
    private val pending = LinkedHashMap<File, () -> String>()
    private val queueLock = Object()

    /** True from the first queued save until the writer finds the queue empty; guarded by [queueLock]. */
    private var writerActive = false

    private val writer = java.util.concurrent.Executors.newSingleThreadExecutor { task ->
        Thread(task, "store-writer").apply { isDaemon = true }
    }

    /**
     * Queues [encode]'s text for [file]. It runs later on the writer thread,
     * so it must read only what it captured: an immutable snapshot.
     */
    internal fun save(file: File, encode: () -> String) {
        synchronized(queueLock) {
            pending[file] = encode
            if (!writerActive) {
                writerActive = true
                writer.execute(::drain)
            }
        }
    }

    private fun drain() {
        while (true) {
            val (file, encode) = synchronized(queueLock) {
                val next = pending.entries.firstOrNull()
                if (next == null) {
                    writerActive = false
                    queueLock.notifyAll()
                    return
                }
                pending.remove(next.key)
                next.key to next.value
            }
            try {
                write(file, encode())
            } catch (e: Throwable) {
                // An encode that throws loses this one save, not the writer.
                logger.error("${file.name} could not be saved: ${e.message ?: e}")
            }
        }
    }

    /**
     * Waits until every save queued so far is on disk, or [timeoutMs] runs
     * out. Returns whether the queue emptied.
     */
    fun flush(timeoutMs: Long = FLUSH_TIMEOUT_MS): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        synchronized(queueLock) {
            while (writerActive) {
                val left = (deadline - System.nanoTime()) / 1_000_000
                if (left <= 0) {
                    logger.warning("Saves still pending after $timeoutMs ms: ${pending.keys.joinToString { it.name }}")
                    return false
                }
                queueLock.wait(left)
            }
        }
        return true
    }

    /**
     * Files that exist but could not be read this session. Writing one would
     * replace the user's servers or settings with the empty defaults the app
     * started from, so their saves go to a side file instead; see [write].
     */
    private val unreadable: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()

    private fun <T> read(file: File, serializer: kotlinx.serialization.KSerializer<T>): T? {
        if (!file.isFile) return null
        // Something else may have the file open for a moment — an antivirus
        // scan, a backup or sync client — so a read that fails gets retried
        // before anything is concluded from it.
        var text: String? = null
        var lastError: Exception? = null
        for (attempt in 0 until READ_ATTEMPTS) {
            try {
                text = file.readText(Charsets.UTF_8)
                break
            } catch (e: Exception) {
                lastError = e
                if (attempt < READ_ATTEMPTS - 1) Thread.sleep(READ_RETRY_MS)
            }
        }
        if (text == null) {
            logger.error("${file.name} could not be opened: ${lastError?.message}. It is left as it is, and changes are saved beside it")
            unreadable += file.absolutePath
            return null
        }
        return try {
            json.decodeFromString(serializer, text)
        } catch (e: Exception) {
            logger.error("${file.name} could not be read: ${e.message}")
            // The text itself is broken: keep it for the user and start from defaults.
            runCatching { file.renameTo(File(file.parentFile, "${file.name}.corrupt-${System.currentTimeMillis()}")) }
            null
        }
    }

    @Synchronized
    internal fun write(file: File, text: String) {
        if (file.absolutePath in unreadable) {
            runCatching { File(file.parentFile, "${file.name}.unsaved").writeText(text, Charsets.UTF_8) }
            return
        }
        val temp = File(file.parentFile, "${file.name}.tmp")
        try {
            temp.writeText(text, Charsets.UTF_8)
        } catch (e: Exception) {
            logger.error("${file.name} could not be written: ${e.message}")
            runCatching { temp.delete() }
            return
        }
        // Windows refuses to replace a file something else has open for the
        // moment — an antivirus, a backup agent, a sync client — so the move
        // gets a few tries, then a plain replace; and if that fails too the
        // new text stays in the temp file rather than being thrown away.
        var lastError: Exception? = null
        repeat(MOVE_ATTEMPTS) { attempt ->
            try {
                Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                return
            } catch (e: Exception) {
                lastError = e
                if (attempt < MOVE_ATTEMPTS - 1) Thread.sleep(MOVE_RETRY_MS)
            }
        }
        try {
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
            logger.warning("${file.name}: atomic replace kept failing (${lastError?.message}); replaced it the plain way")
        } catch (e: Exception) {
            logger.error("${file.name} could not be replaced: ${e.message}. The unsaved version is in ${temp.absolutePath}")
        }
    }

    companion object {
        /** What the way out waits for the last saves: a 30 MB list on a slow disk takes a few seconds. */
        private const val FLUSH_TIMEOUT_MS = 15_000L
        private const val MOVE_ATTEMPTS = 5
        private const val MOVE_RETRY_MS = 50L
        private const val READ_ATTEMPTS = 10
        private const val READ_RETRY_MS = 200L
    }
}
