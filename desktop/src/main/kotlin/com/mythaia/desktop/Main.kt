package com.mythaia.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.mythaia.desktop.engine.SystemProxy
import com.mythaia.desktop.store.DesktopStore
import com.mythaia.desktop.ui.App
import com.mythaia.desktop.ui.MythaiaTheme
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.util.LogBackend
import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.io.PrintWriter
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.system.exitProcess

const val APP_VERSION = "1.0.1"

/** Held for the life of the process; a local would be collected and the lock released. */
private object InstanceLock {
    var lock: FileLock? = null
}

fun main(args: Array<String>) {
    ensureAsciiSocketTempDir()
    // The service process: no window, no user data, just the tunnel behind a pipe.
    if (args.contains("--service")) com.mythaia.desktop.service.MythaiaService.runUnderScm()
    if (args.contains("--service-console")) com.mythaia.desktop.service.MythaiaService.runInConsole()
    val logger = installLogging()
    InstanceLock.lock = acquireInstanceLock()
    if (InstanceLock.lock == null) {
        // Ask the running instance to show itself (and import a link we were given), then leave.
        args.firstOrNull { DeepLinks.isLink(it) }?.let { runCatching { AppPaths.importRequest.writeText(DeepLinks.extract(it)) } }
        runCatching { AppPaths.showRequest.writeText(System.currentTimeMillis().toString()) }
        logger.info("Another instance is running; asked it to show its window")
        exitProcess(0)
    }

    val nativeAvailable = loadNativeLibrary(logger)
    SystemProxy.restoreIfLeftOver()
    runCatching { com.mythaia.desktop.tun.TunEngine.cleanupLeftovers() }
    runCatching { com.mythaia.desktop.tun.Elevation.cleanupArgFile() }

    val state = AppState(DesktopStore(), nativeAvailable)
    // An elevated relaunch for TUN mode: switch to it and connect at once.
    if (args.contains("--tun")) {
        state.updateSettings { it.copy(tunnelMode = "tun") }
        state.connect()
    }
    Runtime.getRuntime().addShutdownHook(Thread { runCatching { state.shutdown() } })
    watchShowRequests(state)
    val startHidden = args.contains("--minimized") || state.settings.value.startMinimized
    state.windowVisible.value = !startHidden
    if (state.settings.value.autoConnect) state.connect()
    DeepLinks.register()
    // A link from outside — a browser, usually — is shown and confirmed before anything is stored.
    args.firstOrNull { DeepLinks.isLink(it) }?.let { state.requestImport(DeepLinks.extract(it)) }

    application {
        val settings by state.settings.collectAsState()
        val visible by state.windowVisible.collectAsState()
        val connection by state.connection.collectAsState()
        val dark = when (settings.theme) {
            "dark" -> true
            "light" -> false
            else -> isSystemInDarkTheme()
        }
        S.lang
        val windowState = rememberWindowState(size = DpSize(settings.windowWidth.dp, settings.windowHeight.dp))
        val appIcon = painterResource("icon/mythaia_256.png")
        val trayOn = painterResource("icon/mythaia_tray.png")
        val trayOff = painterResource("icon/mythaia_tray_off.png")
        val trayIcon = if (connection is ConnectionState.Connected) trayOn else trayOff
        val front by state.bringToFront.collectAsState()

        val exit = {
            state.shutdown()
            exitApplication()
        }

        Tray(
            icon = trayIcon,
            tooltip = tr("app_name"),
            onAction = { state.windowVisible.value = true },
            menu = {
                Item(tr("tray_show"), onClick = { state.windowVisible.value = true })
                Item(
                    if (connection is ConnectionState.Connected || connection is ConnectionState.Connecting) tr("disconnect") else tr("connect"),
                    onClick = { state.toggle() }
                )
                Separator()
                Item(tr("tray_exit"), onClick = exit)
            }
        )

        Window(
            onCloseRequest = {
                state.rememberWindowSize(windowState.size.width.value.toInt(), windowState.size.height.value.toInt())
                if (settings.closeToTray) state.windowVisible.value = false else exit()
            },
            visible = visible,
            title = tr("app_name"),
            icon = appIcon,
            state = windowState,
            onKeyEvent = { event ->
                if (event.type != androidx.compose.ui.input.key.KeyEventType.KeyDown) return@Window false
                when {
                    event.isCtrlPressed && event.key == androidx.compose.ui.input.key.Key.V && !com.mythaia.desktop.ui.UiFocus.textField.value -> { state.importFromClipboard(); true }
                    event.key == androidx.compose.ui.input.key.Key.F5 -> { state.pingGroup(state.activeGroupId, com.mythaia.data.network.LatencyKind.HTTP); true }
                    else -> false
                }
            }
        ) {
            androidx.compose.runtime.LaunchedEffect(front, visible) {
                if (visible && front != 0L) {
                    window.toFront()
                    window.requestFocus()
                }
            }
            MythaiaTheme(dark = dark) {
                App(state)
            }
        }
    }
}

/**
 * JDK 21 on Windows builds every NIO selector's wake-up pipe from an AF_UNIX
 * socket whose path lives under the temp directory, and that fails when the
 * path has non-ASCII characters (a Cyrillic user name, say). The socket
 * layer opens a selector, so the path is pointed at an ASCII directory
 * before anything touches NIO.
 */
private fun ensureAsciiSocketTempDir() {
    if (System.getProperty("jdk.net.unixdomain.tmpdir") != null) return
    val temp = System.getProperty("java.io.tmpdir").orEmpty()
    if (temp.all { it.code < 128 }) return
    val candidates = listOf(
        File(System.getenv("ProgramData") ?: "C:/ProgramData", "Mythaia/tmp"),
        File(System.getenv("SystemRoot") ?: "C:/Windows", "Temp"),
        File("C:/gtmp")
    )
    val dir = candidates.firstOrNull { d ->
        d.absolutePath.all { it.code < 128 } && (d.isDirectory || d.mkdirs()) && d.canWrite()
    } ?: return
    System.setProperty("jdk.net.unixdomain.tmpdir", dir.absolutePath)
}

/** Logs to `%APPDATA%\Mythaia\logs\mythaia.log`, rotating at two megabytes. */
private fun installLogging(): MythaiaLogger {
    MythaiaLogger.backend = FileLogBackend(File(AppPaths.logDir, "mythaia.log"))
    MythaiaLogger.debugEnabled = System.getProperty("mythaia.debug") == "true"
    return MythaiaLogger("Main").also { it.info("Mythaia Pro $APP_VERSION starting") }
}

private class FileLogBackend(private val file: File) : LogBackend {
    private var writer: PrintWriter? = null
    private val stamp = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")

    @Synchronized
    private fun write(tag: String, category: String, message: String) {
        try {
            if (file.length() > 2L * 1024 * 1024) {
                writer?.close(); writer = null
                val old = File(file.parentFile, "mythaia.1.log")
                old.delete()
                file.renameTo(old)
            }
            val w = writer ?: PrintWriter(java.io.BufferedWriter(java.io.FileWriter(file, Charsets.UTF_8, true)), true).also { writer = it }
            w.println("${LocalDateTime.now().format(stamp)} $tag [$category] $message")
        } catch (_: Exception) {
        }
    }

    override fun log(level: MythaiaLogger.Level, category: String, message: String) =
        write(level.name.uppercase().padEnd(7), category, message)

    override fun debug(category: String, message: String) = write("DEBUG  ", category, message)
}

private fun loadNativeLibrary(logger: MythaiaLogger): Boolean {
    val file = AppPaths.nativeLibrary()
    if (file == null) {
        logger.warning("mythaia_native.dll not found; QUIC protocols and Clash parsing are off")
        return false
    }
    System.setProperty("mythaia.native.library", file.absolutePath)
    return try {
        val version = NativeBridge.nativeQuicVersion()
        logger.info("Native library loaded from ${file.absolutePath} (ngtcp2 $version)")
        true
    } catch (e: Throwable) {
        logger.error("Native library failed to load: ${e.message}")
        false
    }
}

/** A second instance writes a file; the running one shows its window. */
private fun watchShowRequests(state: AppState) {
    val thread = Thread({
        var last = AppPaths.showRequest.takeIf { it.isFile }?.lastModified() ?: 0L
        while (true) {
            try {
                Thread.sleep(1000)
                val file = AppPaths.showRequest
                if (file.isFile && file.lastModified() > last) {
                    last = file.lastModified()
                    state.windowVisible.value = true
                    state.bringToFront.value = System.currentTimeMillis()
                    // Written by a second instance started with a link: the same confirmation as a direct start.
                    val request = AppPaths.importRequest
                    if (request.isFile) {
                        val text = runCatching { request.readText() }.getOrNull()
                        request.delete()
                        if (!text.isNullOrBlank()) state.requestImport(text)
                    }
                }
            } catch (_: InterruptedException) {
                return@Thread
            } catch (_: Exception) {
            }
        }
    }, "show-request-watch")
    thread.isDaemon = true
    thread.start()
}

/**
 * `mythaia://add-proxy?link=…` and bare proxy schemes (`vless://` …), as the
 * Android app and iOS handle them. Registered per user, pointing at the
 * installed launcher; a running instance receives the link through the
 * import request file.
 */
private object DeepLinks {
    private val schemes = listOf("mythaia", "vless", "vmess", "trojan", "ss", "socks5", "hysteria2", "hy2", "anytls", "tuic")

    fun isLink(arg: String): Boolean = schemes.any { arg.startsWith("$it://", ignoreCase = true) }

    /** The proxy link inside a `mythaia://add-proxy?link=` URL, or the argument itself. */
    fun extract(arg: String): String {
        if (!arg.startsWith("mythaia://", ignoreCase = true)) return arg
        val query = arg.substringAfter('?', "")
        val link = query.split('&').map { it.substringBefore('=') to it.substringAfter('=', "") }
            .firstOrNull { it.first == "link" || it.first == "url" }?.second
        return link?.let { runCatching { java.net.URLDecoder.decode(it, "UTF-8") }.getOrDefault(it) } ?: arg
    }

    fun register() {
        if (!com.mythaia.desktop.engine.SystemProxy.isWindows) return
        val exe = AppPaths.launcherExe() ?: return
        runCatching {
            val key = "Software\\Classes\\mythaia"
            com.sun.jna.platform.win32.Advapi32Util.registryCreateKey(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER, key)
            com.sun.jna.platform.win32.Advapi32Util.registrySetStringValue(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER, key, "", "URL:Mythaia")
            com.sun.jna.platform.win32.Advapi32Util.registrySetStringValue(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER, key, "URL Protocol", "")
            com.sun.jna.platform.win32.Advapi32Util.registryCreateKey(com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER, "$key\\shell\\open\\command")
            com.sun.jna.platform.win32.Advapi32Util.registrySetStringValue(
                com.sun.jna.platform.win32.WinReg.HKEY_CURRENT_USER, "$key\\shell\\open\\command", "", "\"${exe.absolutePath}\" \"%1\""
            )
        }
    }
}

private fun acquireInstanceLock(): FileLock? = try {
    val channel = RandomAccessFile(AppPaths.instanceLock, "rw").channel
    channel.tryLock()
} catch (_: Exception) {
    null
}
