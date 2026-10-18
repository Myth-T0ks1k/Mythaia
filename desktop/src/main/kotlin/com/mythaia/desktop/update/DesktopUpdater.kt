package com.mythaia.desktop.update

import com.mythaia.data.update.AppVersion
import com.mythaia.data.update.Release
import com.mythaia.data.update.ReleaseAsset
import com.mythaia.data.update.Releases
import com.mythaia.data.update.UpdateClient
import com.mythaia.data.update.UpdateRoute
import com.mythaia.desktop.APP_VERSION
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.AppState
import com.mythaia.desktop.ConnectionState
import com.mythaia.desktop.tr
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.awt.Desktop
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URI

private val logger = MythaiaLogger("Update")

sealed interface DesktopUpdateState {
    data object Idle : DesktopUpdateState
    data object Checking : DesktopUpdateState
    data class UpToDate(val latest: AppVersion) : DesktopUpdateState
    data class Available(val release: Release) : DesktopUpdateState
    data class Downloading(val release: Release, val done: Long, val total: Long) : DesktopUpdateState
    data class Ready(val release: Release, val file: File, val sha256: String) : DesktopUpdateState
    data class Failed(val message: String, val release: Release?) : DesktopUpdateState
}

/**
 * The Windows app's updater: the same GitHub release, checksum-checked.
 *
 * An installed copy downloads the setup program and, when told to, runs it
 * and quits (the installer replaces the files; the service keeps its own
 * copy in Program Files and is updated from Settings as before). A portable
 * copy downloads the new zip and shows it, since only the user knows where
 * they unpacked the old one. Nothing is fetched unless the user asks or has
 * turned on the daily check.
 */
class DesktopUpdater(private val app: AppState) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var job: Job? = null

    private val _state = MutableStateFlow<DesktopUpdateState>(DesktopUpdateState.Idle)
    val state: StateFlow<DesktopUpdateState> = _state.asStateFlow()

    /** Running from Gradle rather than a packaged build: there is nothing to replace. */
    val canInstall: Boolean = AppPaths.launcherExe() != null

    /** Unpacked from the portable zip rather than installed: it gets the zip, not the installer. */
    val portable: Boolean = AppPaths.launcherExe()?.let { !isInstalledLocation(it) } ?: false

    fun checkIfDue() {
        val settings = app.settings.value
        if (!settings.updateAutoCheck) return
        val now = System.currentTimeMillis()
        if (now - settings.updateLastCheck in 0 until CHECK_INTERVAL_MS) return
        check(automatic = true)
    }

    fun check(automatic: Boolean = false) {
        if (job?.isActive == true) return
        job = scope.launch {
            if (!automatic) _state.value = DesktopUpdateState.Checking
            app.rememberUpdaterState { it.copy(updateLastCheck = System.currentTimeMillis()) }
            try {
                val release = UpdateClient.latest(routes())
                val installed = AppVersion.parse(APP_VERSION)
                if (installed != null && release.version <= installed) {
                    _state.value = DesktopUpdateState.UpToDate(release.version)
                    return@launch
                }
                logger.info("[Update] ${release.version} is out")
                _state.value = DesktopUpdateState.Available(release)
                if (automatic && app.settings.value.updateDismissedTag != release.tag) {
                    app.rememberUpdaterState { it.copy(updateDismissedTag = release.tag) }
                    app.notify(tr("update_notice", release.version.toString()), tr("update_download"), long = true) {
                        if (canInstall) download() else openReleasePage()
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.warning("[Update] Check failed: ${e.message ?: e}")
                _state.value = if (automatic) DesktopUpdateState.Idle
                else DesktopUpdateState.Failed(tr("update_check_failed", e.message ?: e.toString()), null)
            }
        }
    }

    fun download() {
        val release = when (val s = _state.value) {
            is DesktopUpdateState.Available -> s.release
            is DesktopUpdateState.Failed -> s.release
            else -> null
        } ?: return
        if (!canInstall || job?.isActive == true) return
        val asset: ReleaseAsset = Releases.windowsAsset(release, portable) ?: run {
            _state.value = DesktopUpdateState.Failed(tr("update_no_file"), release)
            return
        }
        job = scope.launch {
            _state.value = DesktopUpdateState.Downloading(release, 0, asset.size)
            try {
                val routes = routes()
                val expected = UpdateClient.expectedSha256(asset, UpdateClient.checksums(release, routes))
                val dir = File(AppPaths.dataDir, "updates").apply {
                    listFiles()?.forEach { it.delete() }
                    mkdirs()
                }
                val file = File(dir, asset.name)
                var shown = 0L
                val route = UpdateClient.download(asset, expected, file, routes, UpdateClient.MAX_WINDOWS_BYTES) { done, total ->
                    if (done - shown >= PROGRESS_STEP || done == total) {
                        shown = done
                        _state.value = DesktopUpdateState.Downloading(release, done, if (total > 0) total else asset.size)
                    }
                }
                logger.info("[Update] ${asset.name} downloaded $route, checksum matches")
                _state.value = DesktopUpdateState.Ready(release, file, expected)
                app.notify(
                    tr("update_ready", release.version.toString()),
                    tr(if (portable) "update_show_file" else "update_install"),
                    long = true
                ) { install() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.warning("[Update] Download failed: ${e.message ?: e}")
                _state.value = DesktopUpdateState.Failed(tr("update_download_failed", e.message ?: e.toString()), release)
            }
        }
    }

    /**
     * Runs the installer and quits so it can replace the files — the exit
     * hook disconnects and puts the system proxy back first. A portable copy
     * gets its zip shown in Explorer instead.
     */
    fun install() {
        val ready = _state.value as? DesktopUpdateState.Ready ?: return
        val file = ready.file
        // Checked again: the file sat in the user's profile since the download.
        if (!file.isFile || UpdateClient.sha256Hex(file) != ready.sha256) {
            _state.value = DesktopUpdateState.Available(ready.release)
            return
        }
        if (portable) {
            runCatching { ProcessBuilder("explorer.exe", "/select,", file.absolutePath).start() }
                .onFailure { runCatching { Desktop.getDesktop().open(file.parentFile) } }
            return
        }
        try {
            ProcessBuilder(file.absolutePath).directory(file.parentFile).start()
        } catch (e: Exception) {
            _state.value = DesktopUpdateState.Failed(tr("update_download_failed", e.message ?: e.toString()), ready.release)
            return
        }
        logger.info("[Update] Installer started; exiting so it can replace the files")
        kotlin.system.exitProcess(0)
    }

    fun cancel() {
        job?.cancel()
        job = null
        _state.value = DesktopUpdateState.Idle
    }

    fun openReleasePage() {
        val page = when (val s = _state.value) {
            is DesktopUpdateState.Available -> s.release.pageUrl
            is DesktopUpdateState.Failed -> s.release?.pageUrl
            else -> null
        } ?: Releases.LATEST_PAGE_URL
        runCatching { Desktop.getDesktop().browse(URI(page)) }
    }

    /**
     * Direct first. With the tunnel up in proxy mode the app's own HTTP port
     * reaches GitHub through the server too; in TUN mode the direct request
     * already goes through the tunnel.
     */
    private fun routes(): List<UpdateRoute> {
        val settings = app.settings.value
        val viaProxy = app.connection.value is ConnectionState.Connected && settings.tunnelMode == "proxy"
        return listOfNotNull(
            UpdateRoute.Direct,
            if (viaProxy) UpdateRoute.LocalProxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", settings.httpPort))) else null
        )
    }

    private fun isInstalledLocation(exe: File): Boolean {
        val path = exe.absolutePath.lowercase()
        val roots = listOfNotNull(
            System.getenv("ProgramFiles"),
            System.getenv("ProgramFiles(x86)"),
            System.getenv("ProgramW6432"),
            System.getenv("LOCALAPPDATA")?.let { "$it\\Programs" }
        ).map { it.lowercase().trimEnd('\\') + "\\" }
        return roots.any { path.startsWith(it) }
    }

    private companion object {
        const val CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
        const val PROGRESS_STEP = 512 * 1024L
    }
}
