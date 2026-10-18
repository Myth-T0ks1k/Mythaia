package com.mythaia.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DefaultWindowExceptionHandlerFactory
import androidx.compose.ui.window.LocalWindowExceptionHandlerFactory
import androidx.compose.ui.window.Tray
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowExceptionHandler
import androidx.compose.ui.window.WindowExceptionHandlerFactory
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

const val APP_VERSION = "1.3.1"

/** Held for the life of the process; a local would be collected and the lock released. */
private object InstanceLock {
    var lock: FileLock? = null
}

@OptIn(ExperimentalComposeUiApi::class)
fun main(args: Array<String>) {
    keepNioOffAfUnix()
    // Before anything touches JNA or Skia: their DLLs from the app folder, never %TEMP%.
    val jnaDir = NativeLoading.configureJna()
    NativeLoading.fixSkikoPath()
    // The service process: no window, no user data, just the tunnel behind a pipe.
    if (args.contains("--service")) com.mythaia.desktop.service.MythaiaService.runUnderScm()
    if (args.contains("--service-console")) com.mythaia.desktop.service.MythaiaService.runInConsole()
    val logger = installLogging()
    // Started by the proxy guard after a crash, or at sign-in: put the proxy back and leave.
    if (args.contains(com.mythaia.desktop.engine.ProxyGuard.RESTORE_ARG)) {
        exitProcess(com.mythaia.desktop.engine.ProxyGuard.restoreAfterCrash())
    }
    logJna(logger, jnaDir)
    val graphicsCrashed = CrashReporting.install()
    chooseRenderer(logger, graphicsCrashed)
    // The elevated helper the running app starts to register or remove the service: no window, no lock.
    if (args.contains(com.mythaia.desktop.service.ServiceInstaller.INSTALL_ARG)) {
        exitProcess(com.mythaia.desktop.service.ServiceInstaller.installHere())
    }
    if (args.contains(com.mythaia.desktop.service.ServiceInstaller.UNINSTALL_ARG)) {
        exitProcess(com.mythaia.desktop.service.ServiceInstaller.uninstallHere())
    }
    // The elevated copy started for TUN mode replaces a window that is still
    // shutting down and holds the lock for a few seconds more; giving up at
    // once left neither of them running. Otherwise half a second: the crash
    // restore (ProxyGuard) takes the lock for an instant to see whether an
    // instance runs, and must not turn this one away.
    if (!acquireInstanceLock(logger, waitMillis = if (args.contains("--tun")) 15_000 else 500)) {
        // Ask the running instance to show itself (and import a link we were given), then leave.
        args.firstOrNull { DeepLinks.isLink(it) }?.let { runCatching { AppPaths.importRequest.writeText(DeepLinks.extract(it)) } }
        runCatching { AppPaths.showRequest.writeText(System.currentTimeMillis().toString()) }
        logger.info("Another instance is running; asked it to show its window")
        exitProcess(0)
    }

    val nativeAvailable = loadNativeLibrary(logger)
    SystemProxy.restoreIfLeftOver()
    // Before anything can set the proxy: if this process is killed, the guard puts it back.
    com.mythaia.desktop.engine.ProxyGuard.start()
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
        // Bumped to build the window afresh after an exception in it.
        var windowGeneration by remember { mutableStateOf(0) }
        val windowErrors = remember { WindowErrors() }

        // Disconnecting can wait on a TUN or service connect for seconds; on
        // the UI thread that froze the window into "Not responding", which
        // people end from Task Manager — and that leaves the system proxy set.
        val exit = {
            if (Exiting.started.compareAndSet(false, true)) {
                state.windowVisible.value = false
                Thread({
                    runCatching { state.shutdown() }
                    javax.swing.SwingUtilities.invokeLater { exitApplication() }
                }, "exit").start()
            }
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

        // An exception in the window — composing, drawing, a click — used to
        // close it with Compose's default handler, which to the user is the app
        // vanishing. It is logged and the window built again instead; only an
        // error that keeps coming back gets the default treatment.
        val exceptionHandlerFactory = remember {
            WindowExceptionHandlerFactory { window ->
                WindowExceptionHandler { error ->
                    CrashReporting.logUncaught("the window", error)
                    if (windowErrors.tooMany()) {
                        DefaultWindowExceptionHandlerFactory.exceptionHandler(window).onException(error)
                    } else {
                        javax.swing.SwingUtilities.invokeLater { windowGeneration++ }
                    }
                }
            }
        }

        CompositionLocalProvider(LocalWindowExceptionHandlerFactory provides exceptionHandlerFactory) {
            key(windowGeneration) {
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
    }
}

/** Set once Exit has begun, so a second click does not start a second shutdown. */
private object Exiting {
    val started = java.util.concurrent.atomic.AtomicBoolean(false)
}

/** Window exceptions in the last minute; past three the window is not rebuilt again. */
private class WindowErrors {
    private val times = ArrayDeque<Long>()

    @Synchronized
    fun tooMany(): Boolean {
        val now = System.currentTimeMillis()
        times.addLast(now)
        while (times.isNotEmpty() && now - times.first() > 60_000) times.removeFirst()
        return times.size > 3
    }
}

/**
 * Keeps every NIO selector on a TCP loopback wake-up pipe.
 *
 * JDK 21 on Windows builds each selector's wake-up pipe from an AF_UNIX
 * socket in %TEMP% (`sun.nio.ch.PipeImpl`). If binding it fails, the JDK
 * falls back to TCP loopback; if binding works and connecting does not, the
 * selector cannot open at all — and that happens on real machines: a
 * Cyrillic user name in the path, Windows builds without a working AF_UNIX,
 * security software that filters it. The socket layer then fails for the
 * rest of the session. Pointing the AF_UNIX directory at one that does not
 * exist makes every bind fail, so the fallback the JDK used until 16 is
 * taken everywhere, the same way on every machine.
 */
private fun keepNioOffAfUnix() {
    if (System.getProperty("jdk.net.unixdomain.tmpdir") != null) return
    val drive = System.getenv("SystemDrive")?.takeIf { it.isNotBlank() } ?: "C:"
    System.setProperty("jdk.net.unixdomain.tmpdir", "$drive\\mythaia-no-af-unix-${java.util.UUID.randomUUID()}")
}

/**
 * Draws with the CPU when the GPU path killed a previous run.
 *
 * Skia draws through Direct3D, and a faulty graphics driver (old Intel
 * ones, some hybrid laptops, remote desktops and virtual machines) crashes
 * inside it, which takes the whole app with it. Once a crash report names
 * the graphics stack, `render-api` in the data folder records SOFTWARE and
 * every later start uses it; deleting the file goes back to the GPU. Skia
 * also honours SKIKO_RENDER_API from the environment, which wins over this.
 */
private fun chooseRenderer(logger: MythaiaLogger, graphicsCrashed: Boolean) {
    val marker = File(AppPaths.dataDir, "render-api")
    if (graphicsCrashed) runCatching { marker.writeText("SOFTWARE") }
    val api = runCatching { marker.takeIf { it.isFile }?.readText()?.trim() }.getOrNull()
    if (!api.isNullOrEmpty() && System.getProperty("skiko.renderApi") == null) {
        System.setProperty("skiko.renderApi", api)
        logger.info("Rendering with $api (${marker.name} in the data folder)")
    }
}

/** Logs to `%APPDATA%\Mythaia\logs\mythaia.log`, rotating at two megabytes. */
private fun installLogging(): MythaiaLogger {
    MythaiaLogger.backend = FileLogBackend(File(AppPaths.logDir, "mythaia.log"))
    MythaiaLogger.debugEnabled = System.getProperty("mythaia.debug") == "true"
    return MythaiaLogger("Main").also {
        // What a crash report from someone else's machine needs first.
        val runtime = Runtime.getRuntime()
        it.info(
            "Mythaia Pro $APP_VERSION starting on ${System.getProperty("os.name")} ${System.getProperty("os.version")}" +
                " (${System.getProperty("os.arch")}, ${runtime.availableProcessors()} CPUs)," +
                " Java ${System.getProperty("java.runtime.version")}, heap up to ${runtime.maxMemory() / (1024 * 1024)} MB"
        )
    }
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
    val path = NativeLoading.loadablePath(file)
    System.setProperty("mythaia.native.library", path)
    return try {
        val version = NativeBridge.nativeQuicVersion()
        logger.info("Native library loaded from $path (ngtcp2 $version)")
        true
    } catch (e: Throwable) {
        logger.error("Native library failed to load: ${e.message}")
        false
    }
}

/**
 * Loads JNA's native part now, so the log says where it came from and a
 * failure is reported once, here, rather than by the first registry call.
 */
private fun logJna(logger: MythaiaLogger, shippedDir: File?) {
    if (shippedDir == null) logger.info("jnidispatch.dll is not in the app folder; JNA unpacks its own copy")
    try {
        // Reading it initialises Native, which is what loads jnidispatch.dll.
        val bits = com.sun.jna.Native.POINTER_SIZE * 8
        logger.info("JNA native part ($bits-bit) from ${System.getProperty("jnidispatch.path") ?: "?"}")
    } catch (e: LinkageError) {
        logger.error("JNA's native part did not load: ${e.message ?: e}; system proxy, TUN and the service are unavailable")
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

/**
 * Takes the lock that makes this the one running instance, waiting up to
 * [waitMillis] for another instance to let go; false when one holds it.
 *
 * A lock file that cannot be opened or locked at all (a redirected data
 * folder that is offline, a read-only file) is not another instance: that
 * case used to exit quietly on every start. It is logged, and this instance
 * runs without the lock.
 */
private fun acquireInstanceLock(logger: MythaiaLogger, waitMillis: Long): Boolean {
    val channel = try {
        RandomAccessFile(AppPaths.instanceLock, "rw").channel
    } catch (e: Exception) {
        logger.warning("Cannot open ${AppPaths.instanceLock}: ${e.message}; running without the single-instance lock")
        return true
    }
    val deadline = System.currentTimeMillis() + waitMillis
    while (true) {
        val lock = try {
            channel.tryLock()
        } catch (e: java.nio.channels.OverlappingFileLockException) {
            null
        } catch (e: Exception) {
            logger.warning("Cannot lock ${AppPaths.instanceLock}: ${e.message}; running without the single-instance lock")
            return true
        }
        if (lock != null) {
            InstanceLock.lock = lock
            return true
        }
        if (System.currentTimeMillis() >= deadline) {
            runCatching { channel.close() }
            return false
        }
        Thread.sleep(250)
    }
}
