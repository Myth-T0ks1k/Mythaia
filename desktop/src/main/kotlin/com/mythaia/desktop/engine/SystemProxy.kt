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
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock

/**
 * The Windows per-user proxy (what Edge, Chrome, WinHTTP-using apps and the
 * system itself read). The LAN settings are set through the registry, the
 * dial-up, PPPoE and VPN connections' own through [PerConnectionProxy], and
 * the change is announced with WinINet's settings-changed notification so
 * browsers pick it up at once.
 *
 * What was there before is snapshotted to disk the first time it is
 * replaced and restored on disconnect, so a crash cannot leave the user with
 * a dead proxy after a reboot: the next start restores it too, and so do
 * the guard process and the sign-in entry of [ProxyGuard] when the app is
 * not started again.
 */
object SystemProxy {
    private val logger = MythaiaLogger("SystemProxy")

    /**
     * Tests only: a key under HKCU (`Software\MythaiaTest`) that stands in
     * for the real one, so the user's own proxy is never touched. The
     * dial-up connections and the change notification are left alone then.
     */
    private val testRoot: String? = System.getProperty("mythaia.test.registryRoot")?.takeIf { it.isNotBlank() }
    private val KEY = testRoot?.let { "$it\\Internet Settings" } ?: "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private val RUN_ONCE_KEY = testRoot?.let { "$it\\RunOnce" } ?: "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    private const val RUN_ONCE_VALUE = "Mythaia Pro proxy restore"
    private const val INTERNET_OPTION_REFRESH = 37
    private const val INTERNET_OPTION_SETTINGS_CHANGED = 39

    /** The LAN values, and each phonebook connection's options by name (absent from older snapshots). */
    @Serializable
    data class Snapshot(
        val enable: Int,
        val server: String?,
        val override: String?,
        val connections: Map<String, PerConnectionProxy.Options> = emptyMap()
    )

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
        acrossProcesses { enableLocked(server, bypass) }
    }

    private fun enableLocked(server: String, bypass: String) {
        try {
            if (testRoot != null) Advapi32Util.registryCreateKey(WinReg.HKEY_CURRENT_USER, KEY)
            val connections = if (testRoot != null) emptyList() else PerConnectionProxy.connectionNames().orEmpty()
            val saved = readSnapshot()
            val snapshot = withConnections(saved ?: current(), connections, server)
            if (snapshot != null && snapshot != saved) {
                AppPaths.proxySnapshot.writeText(json.encodeToString(Snapshot.serializer(), snapshot))
            }
            Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 1)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", server)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", bypass)
            // A PC online through one of these reads its options, not the LAN's.
            val proxied = PerConnectionProxy.proxied(server, bypass)
            val set = connections.count { PerConnectionProxy.set(it, proxied) }
            announceChange()
            armRestoreAtSignIn()
            logger.info("System proxy set to $server" + if (connections.isEmpty()) "" else " (and on $set of ${connections.size} dial-up/VPN connections)")
        } catch (e: Exception) {
            logger.error("Could not set the system proxy: ${e.message}")
        } catch (e: LinkageError) {
            // JNA extracts jnidispatch.dll to %TEMP% on first use; where
            // antivirus or AppLocker blocks it, every registry call throws an
            // Error, which would otherwise reach the UI thread and close the window.
            logger.error("Could not set the system proxy (JNA unavailable): ${e.message ?: e}")
        }
    }

    /** Puts back what was there before [enable], or simply turns the proxy off. */
    fun restore() {
        if (!isWindows) return
        acrossProcesses { restoreLocked() }
    }

    private fun restoreLocked() {
        try {
            val snapshot = readSnapshot()
            // The user's own server and exception strings go back whether or
            // not their proxy was switched on: a disabled corporate proxy is
            // still theirs to keep.
            if (snapshot != null) {
                snapshot.server?.let { Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", it) }
                snapshot.override?.let { Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", it) }
                val enable = if (snapshot.enable == 1 && !snapshot.server.isNullOrBlank()) 1 else 0
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", enable)
                // A connection deleted since is simply refused.
                if (testRoot == null) snapshot.connections.forEach { (name, options) -> PerConnectionProxy.set(name, options) }
            } else {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 0)
            }
            announceChange()
            AppPaths.proxySnapshot.delete()
            disarmRestoreAtSignIn()
            logger.info("System proxy restored")
        } catch (e: Exception) {
            logger.error("Could not restore the system proxy: ${e.message}")
        } catch (e: LinkageError) {
            logger.error("Could not restore the system proxy (JNA unavailable): ${e.message ?: e}")
        }
    }

    /** On start: a snapshot left behind means the last run did not get to restore. */
    fun restoreIfLeftOver(onlyWhen: () -> Boolean = { true }) {
        if (!isWindows || !AppPaths.proxySnapshot.isFile) return
        acrossProcesses {
            if (AppPaths.proxySnapshot.isFile && onlyWhen()) restoreLocked()
        }
    }

    /**
     * The installed app's restore, run once at the next sign-in, for when
     * the PC goes down with the proxy still set (power cut, blue screen) and
     * the app is not set to start with Windows. Without an installed
     * launcher (a run from Gradle) there is nothing to point it at.
     */
    private fun armRestoreAtSignIn() {
        val exe = AppPaths.launcherExe() ?: return
        runCatching {
            Advapi32Util.registryCreateKey(WinReg.HKEY_CURRENT_USER, RUN_ONCE_KEY)
            Advapi32Util.registrySetStringValue(
                WinReg.HKEY_CURRENT_USER, RUN_ONCE_KEY, RUN_ONCE_VALUE, "\"${exe.absolutePath}\" ${ProxyGuard.RESTORE_ARG}"
            )
        }.onFailure { logger.warning("Could not arm the restore at sign-in: ${it.message}") }
    }

    /** Removes [armRestoreAtSignIn]'s entry once there is nothing left to restore. */
    fun disarmRestoreAtSignIn() {
        if (!isWindows) return
        runCatching {
            if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_ONCE_KEY, RUN_ONCE_VALUE)) {
                Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, RUN_ONCE_KEY, RUN_ONCE_VALUE)
            }
        }
    }

    private val processLock = Any()

    /**
     * Runs [block] holding `system-proxy.lock` in the data folder, so the
     * crash restore ([ProxyGuard]) and a new instance's own start can never
     * interleave their reads and writes of the snapshot and the registry.
     * A lock that cannot be had within ten seconds is gone without: a stuck
     * peer must not stop the proxy being set or put back.
     */
    private fun acrossProcesses(block: () -> Unit) = synchronized(processLock) {
        val channel = runCatching { RandomAccessFile(File(AppPaths.dataDir, "system-proxy.lock"), "rw").channel }.getOrNull()
        var lock: FileLock? = null
        try {
            val deadline = System.currentTimeMillis() + 10_000
            while (channel != null && lock == null) {
                lock = runCatching { channel.tryLock() }.getOrNull()
                if (lock != null || System.currentTimeMillis() > deadline) break
                Thread.sleep(100)
            }
            if (channel != null && lock == null) logger.warning("system-proxy.lock is held elsewhere; going ahead without it")
            block()
        } finally {
            runCatching { lock?.release() }
            runCatching { channel?.close() }
        }
    }

    private fun readSnapshot(): Snapshot? = AppPaths.proxySnapshot.takeIf { it.isFile }
        ?.let { runCatching { json.decodeFromString(Snapshot.serializer(), it.readText()) }.getOrNull() }

    /**
     * [base] with the options of each of [connections] it does not hold yet,
     * read now, before they are changed: one added since the first snapshot
     * gets its own. Options that already point at [proxy] are not the user's,
     * so going back from them means no proxy.
     */
    internal fun withConnections(
        base: Snapshot?,
        connections: List<String>,
        proxy: String,
        query: (String) -> PerConnectionProxy.Options? = PerConnectionProxy::query
    ): Snapshot? {
        val known = base?.connections.orEmpty()
        val added = connections.filter { it !in known }
            .mapNotNull { name -> query(name)?.let { name to PerConnectionProxy.before(it, proxy) } }
        if (added.isEmpty()) return base
        return (base ?: Snapshot(enable = 0, server = null, override = null)).copy(connections = known + added)
    }

    private fun announceChange() {
        if (testRoot != null) return
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
        } catch (e: LinkageError) {
            // JNA could not load its native part; see SystemProxy.enable.
            logger.error("Run key (JNA unavailable): ${e.message ?: e}")
            false
        }
    }
}
