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

    private fun <T> read(file: File, serializer: kotlinx.serialization.KSerializer<T>): T? {
        if (!file.isFile) return null
        return try {
            json.decodeFromString(serializer, file.readText(Charsets.UTF_8))
        } catch (e: Exception) {
            logger.error("${file.name} could not be read: ${e.message}")
            // Keep the broken file for the user; start from defaults.
            runCatching { file.renameTo(File(file.parentFile, "${file.name}.corrupt-${System.currentTimeMillis()}")) }
            null
        }
    }

    @Synchronized
    private fun write(file: File, text: String) {
        val temp = File(file.parentFile, "${file.name}.tmp")
        try {
            temp.writeText(text, Charsets.UTF_8)
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: Exception) {
            logger.error("${file.name} could not be written: ${e.message}")
            runCatching { temp.delete() }
        }
    }
}
