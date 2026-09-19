package com.mythaia.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
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

const val APP_VERSION = "1.9.0"

fun main(args: Array<String>) {
    val logger = installLogging()
    val lock = acquireInstanceLock()
    if (lock == null) {
        logger.info("Another instance is running; exiting")
        exitProcess(0)
    }

    val nativeAvailable = loadNativeLibrary(logger)
    SystemProxy.restoreIfLeftOver()

    val state = AppState(DesktopStore(), nativeAvailable)
    Runtime.getRuntime().addShutdownHook(Thread { runCatching { state.shutdown() } })
    val startHidden = args.contains("--minimized") || state.settings.value.startMinimized
    state.windowVisible.value = !startHidden
    if (state.settings.value.autoConnect) state.connect()

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
        val trayIcon = painterResource("icon/mythaia_tray.png")

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
            onCloseRequest = { if (settings.closeToTray) state.windowVisible.value = false else exit() },
            visible = visible,
            title = tr("app_name"),
            icon = appIcon,
            state = windowState
        ) {
            MythaiaTheme(dark = dark) {
                App(state)
            }
        }
    }
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

private fun acquireInstanceLock(): FileLock? = try {
    val channel = RandomAccessFile(AppPaths.instanceLock, "rw").channel
    channel.tryLock()
} catch (_: Exception) {
    null
}
