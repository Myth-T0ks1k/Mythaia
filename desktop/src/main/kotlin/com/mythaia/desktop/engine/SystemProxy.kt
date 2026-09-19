package com.mythaia.desktop.engine

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The Windows per-user proxy (what Edge, Chrome, WinHTTP-using apps and the
 * system itself read). Set through the registry and announced with
 * WinINet's settings-changed notification so browsers pick it up at once.
 *
 * What was there before is snapshotted to disk the first time it is
 * replaced and restored on disconnect, so a crash cannot leave the user with
 * a dead proxy after a reboot: the next start restores it too.
 */
object SystemProxy {
    private val logger = MythaiaLogger("SystemProxy")
    private const val KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private const val INTERNET_OPTION_REFRESH = 37
    private const val INTERNET_OPTION_SETTINGS_CHANGED = 39

    @Serializable
    data class Snapshot(val enable: Int, val server: String?, val override: String?)

    @Suppress("FunctionName")
    private interface WinInet : Library {
        fun InternetSetOptionW(hInternet: Pointer?, option: Int, buffer: Pointer?, length: Int): Boolean
    }

    private val winInet: WinInet? by lazy {
        runCatching { Native.load("wininet", WinInet::class.java) }
            .onFailure { logger.warning("wininet unavailable: ${it.message}") }
            .getOrNull()
    }

    private val json = Json { ignoreUnknownKeys = true }

    val isWindows: Boolean = System.getProperty("os.name").orEmpty().startsWith("Windows")

    /** Whether the registry currently points at our local proxy. */
    fun isOurs(server: String): Boolean {
        val current = current() ?: return false
        return current.enable == 1 && current.server == server
    }

    fun current(): Snapshot? = runCatching {
        Snapshot(
            enable = intValue("ProxyEnable") ?: 0,
            server = stringValue("ProxyServer"),
            override = stringValue("ProxyOverride")
        )
    }.getOrNull()

    /** Points the system at `server` (host:port), keeping [bypass] as the exception list. */
    fun enable(server: String, bypass: String) {
        if (!isWindows) return
        try {
            if (!AppPaths.proxySnapshot.exists()) {
                current()?.let { AppPaths.proxySnapshot.writeText(json.encodeToString(Snapshot.serializer(), it)) }
            }
            Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 1)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", server)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", bypass)
            announceChange()
            logger.info("System proxy set to $server")
        } catch (e: Exception) {
            logger.error("Could not set the system proxy: ${e.message}")
        }
    }

    /** Puts back what was there before [enable], or simply turns the proxy off. */
    fun restore() {
        if (!isWindows) return
        try {
            val snapshot = AppPaths.proxySnapshot.takeIf { it.isFile }
                ?.let { runCatching { json.decodeFromString(Snapshot.serializer(), it.readText()) }.getOrNull() }
            if (snapshot != null && snapshot.enable == 1 && !snapshot.server.isNullOrBlank()) {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 1)
                Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", snapshot.server)
                if (snapshot.override != null) {
                    Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", snapshot.override)
                }
            } else {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 0)
            }
            announceChange()
            AppPaths.proxySnapshot.delete()
            logger.info("System proxy restored")
        } catch (e: Exception) {
            logger.error("Could not restore the system proxy: ${e.message}")
        }
    }

    /** On start: a snapshot left behind means the last run did not get to restore. */
    fun restoreIfLeftOver() {
        if (AppPaths.proxySnapshot.isFile) restore()
    }

    private fun announceChange() {
        val lib = winInet ?: return
        lib.InternetSetOptionW(null, INTERNET_OPTION_SETTINGS_CHANGED, null, 0)
        lib.InternetSetOptionW(null, INTERNET_OPTION_REFRESH, null, 0)
    }

    private fun intValue(name: String): Int? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, KEY, name))
            Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, KEY, name) else null

    private fun stringValue(name: String): String? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, KEY, name))
            Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, KEY, name) else null
}

/** The `Run` key entry that starts the app with the user's session. */
object LaunchAtLogin {
    private const val RUN_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    private const val VALUE = "Mythaia Pro"
    private val logger = MythaiaLogger("LaunchAtLogin")

    fun isEnabled(): Boolean = runCatching {
        Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE)
    }.getOrDefault(false)

    /** Returns false when there is no installed launcher to point the entry at. */
    fun set(enabled: Boolean): Boolean {
        if (!SystemProxy.isWindows) return false
        return try {
            if (enabled) {
                val exe = AppPaths.launcherExe() ?: return false
                Advapi32Util.registrySetStringValue(
                    WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE, "\"${exe.absolutePath}\" --minimized"
                )
            } else if (isEnabled()) {
                Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE)
            }
            true
        } catch (e: Exception) {
            logger.error("Run key: ${e.message}")
            false
        }
    }
}
