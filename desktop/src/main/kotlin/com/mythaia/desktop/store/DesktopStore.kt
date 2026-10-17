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
 */
class DesktopStore {
    private val logger = MythaiaLogger("Store")

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = true
        isLenient = true
    }

    fun loadSettings(): DesktopSettings =
        read(AppPaths.settings, DesktopSettings.serializer()) ?: DesktopSettings()

    fun saveSettings(settings: DesktopSettings) =
        write(AppPaths.settings, json.encodeToString(DesktopSettings.serializer(), settings))

    fun loadConfigurations(): List<ProxyConfiguration> =
        read(AppPaths.configs, ListSerializer(ProxyConfiguration.serializer())) ?: emptyList()

    fun saveConfigurations(configurations: List<ProxyConfiguration>) =
        write(AppPaths.configs, json.encodeToString(ListSerializer(ProxyConfiguration.serializer()), configurations))

    fun loadSubscriptions(): List<Subscription> =
        read(AppPaths.subscriptions, ListSerializer(Subscription.serializer())) ?: emptyList()

    fun saveSubscriptions(subscriptions: List<Subscription>) =
        write(AppPaths.subscriptions, json.encodeToString(ListSerializer(Subscription.serializer()), subscriptions))

    fun loadChains(): List<com.mythaia.data.model.ProxyChain> =
        read(AppPaths.chains, ListSerializer(com.mythaia.data.model.ProxyChain.serializer())) ?: emptyList()

    fun saveChains(chains: List<com.mythaia.data.model.ProxyChain>) =
        write(AppPaths.chains, json.encodeToString(ListSerializer(com.mythaia.data.model.ProxyChain.serializer()), chains))

    fun loadRules(): List<RouteRule> =
        read(AppPaths.rules, ListSerializer(RouteRule.serializer())) ?: emptyList()

    fun saveRules(rules: List<RouteRule>) =
        write(AppPaths.rules, json.encodeToString(ListSerializer(RouteRule.serializer()), rules))

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
        private const val MOVE_ATTEMPTS = 5
        private const val MOVE_RETRY_MS = 50L
        private const val READ_ATTEMPTS = 10
        private const val READ_RETRY_MS = 200L
    }
}
