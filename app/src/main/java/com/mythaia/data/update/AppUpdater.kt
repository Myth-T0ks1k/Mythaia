package com.mythaia.data.update

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import androidx.core.content.edit
import androidx.core.net.toUri
import com.mythaia.BuildConfig
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.vpn.MythaiaVpnService
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
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.UUID

private val logger = MythaiaLogger("AppUpdater")

/** Where the self-updater is: one state for the whole app, shown in Settings and the prompt. */
sealed interface UpdateState {
    data object Idle : UpdateState
    data object Checking : UpdateState
    data class UpToDate(val latest: AppVersion) : UpdateState
    data class Available(val release: Release, val asset: ReleaseAsset?) : UpdateState
    data class Downloading(val release: Release, val asset: ReleaseAsset, val done: Long, val total: Long) : UpdateState
    data class Ready(val release: Release, val file: File) : UpdateState
    data class Failed(val message: String, val release: Release?) : UpdateState
}

/** What this copy of the app may do about a new release. */
enum class UpdateMode {
    /** Signed with the release key: it downloads, checks and installs the update itself. */
    SELF,
    /** The free (F-Droid) build: its store signs and ships its updates, so it only points there. */
    STORE,
    /** Signed with another key (a debug or a rebuilt copy): Android would refuse our APK over it. */
    MANUAL
}

/**
 * Updates the app from the project's GitHub releases.
 *
 * Nothing here talks to the network on its own: the check runs when the user
 * asks for it in Settings, or once a day on opening the app when they have
 * turned that on (it is off until they do). The APK is downloaded straight
 * from GitHub and, where GitHub is blocked, through the server the tunnel is
 * on; it is installed only once its SHA-256 matches the release's
 * SHA256SUMS.txt and it is signed with the release certificate — and Android
 * itself refuses an update signed with any other key than the installed app.
 */
class AppUpdater private constructor(private val context: Context) {

    private val prefs = context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var job: Job? = null

    private val _state = MutableStateFlow<UpdateState>(UpdateState.Idle)
    val state: StateFlow<UpdateState> = _state.asStateFlow()

    /** A release the automatic check found, to offer once; null when there is none to show. */
    private val _prompt = MutableStateFlow<Release?>(null)
    val prompt: StateFlow<Release?> = _prompt.asStateFlow()

    private val _autoCheck = MutableStateFlow(prefs.getBoolean(KEY_AUTO_CHECK, false))
    val autoCheck: StateFlow<Boolean> = _autoCheck.asStateFlow()

    val currentVersion: String get() = BuildConfig.VERSION_NAME

    val mode: UpdateMode by lazy {
        when {
            BuildConfig.FOSS -> UpdateMode.STORE
            installedCertSha256() == Releases.ANDROID_RELEASE_CERT_SHA256 -> UpdateMode.SELF
            else -> UpdateMode.MANUAL
        }
    }

    fun setAutoCheck(enabled: Boolean) {
        prefs.edit { putBoolean(KEY_AUTO_CHECK, enabled) }
        _autoCheck.value = enabled
    }

    /** The app came to the front: checks if the user asked for daily checks and a day has passed. */
    fun checkIfDue() {
        if (mode == UpdateMode.STORE || !_autoCheck.value) return
        val now = System.currentTimeMillis()
        val last = prefs.getLong(KEY_LAST_CHECK, 0L)
        if (now - last in 0 until CHECK_INTERVAL_MS) return
        if (job?.isActive == true) return
        check(automatic = true)
    }

    /** Asks GitHub for the latest release. */
    fun check(automatic: Boolean = false) {
        if (mode == UpdateMode.STORE) return
        if (job?.isActive == true) return
        cleanUp()
        job = scope.launch {
            if (!automatic) _state.value = UpdateState.Checking
            prefs.edit { putLong(KEY_LAST_CHECK, System.currentTimeMillis()) }
            try {
                val release = UpdateClient.latest(routes())
                val installed = AppVersion.parse(BuildConfig.VERSION_NAME)
                if (installed != null && release.version <= installed) {
                    logger.info("[Update] ${release.version} is the latest; this is ${BuildConfig.VERSION_NAME}")
                    _state.value = UpdateState.UpToDate(release.version)
                    return@launch
                }
                val asset = Releases.androidAsset(release, Build.SUPPORTED_ABIS.toList())
                logger.info("[Update] ${release.version} is out; asset ${asset?.name}")
                _state.value = UpdateState.Available(release, asset)
                if (automatic && prefs.getString(KEY_DISMISSED, null) != release.tag) _prompt.value = release
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.warning("[Update] Check failed: ${e.message ?: e}")
                // A failed background check is not worth an interruption.
                _state.value = if (automatic) UpdateState.Idle
                else UpdateState.Failed(context.getString(com.mythaia.R.string.update_check_failed, message(e)), null)
            }
        }
    }

    /** The prompt was closed without updating: it does not come back for this release. */
    fun dismissPrompt() {
        _prompt.value?.let { prefs.edit { putString(KEY_DISMISSED, it.tag) } }
        _prompt.value = null
    }

    /** Downloads and verifies the update [check] found. */
    fun download() {
        val release = when (val s = _state.value) {
            is UpdateState.Available -> s.release
            is UpdateState.Failed -> s.release
            else -> null
        } ?: return
        if (mode != UpdateMode.SELF || job?.isActive == true) return
        val asset = Releases.androidAsset(release, Build.SUPPORTED_ABIS.toList())
        if (asset == null) {
            _state.value = UpdateState.Failed(context.getString(com.mythaia.R.string.update_no_apk), release)
            return
        }
        job = scope.launch {
            _state.value = UpdateState.Downloading(release, asset, 0, asset.size)
            try {
                val routes = routes()
                val checksums = UpdateClient.checksums(release, routes)
                val expected = UpdateClient.expectedSha256(asset, checksums)
                val file = File(updatesDir(), asset.name)
                var lastShown = 0L
                val route = UpdateClient.download(asset, expected, file, routes, UpdateClient.MAX_APK_BYTES) { done, total ->
                    // A few hundred updates, not one per 64 KiB.
                    if (done - lastShown >= PROGRESS_STEP || done == total) {
                        lastShown = done
                        _state.value = UpdateState.Downloading(release, asset, done, if (total > 0) total else asset.size)
                    }
                }
                logger.info("[Update] ${asset.name} downloaded $route, checksum matches")
                withContext(Dispatchers.IO) { verifyApk(file) }
                _state.value = UpdateState.Ready(release, file)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.warning("[Update] Download failed: ${e.message ?: e}")
                _state.value = UpdateState.Failed(context.getString(com.mythaia.R.string.update_download_failed, message(e)), release)
            }
        }
    }

    /**
     * Hands the verified APK to the system installer. Android asks the user
     * once to let this app install apps; until then the settings screen for
     * that opens instead, and the update waits, still verified, for the next tap.
     */
    fun install(activityContext: Context) {
        val ready = _state.value as? UpdateState.Ready ?: return
        if (!ready.file.exists()) {
            _state.value = UpdateState.Available(ready.release, Releases.androidAsset(ready.release, Build.SUPPORTED_ABIS.toList()))
            return
        }
        if (!context.packageManager.canRequestPackageInstalls()) {
            val settings = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, "package:${context.packageName}".toUri())
            if (startSafely(activityContext, settings)) return
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.exports", ready.file)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, APK_MIME)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        if (!startSafely(activityContext, intent)) {
            _state.value = UpdateState.Failed(context.getString(com.mythaia.R.string.update_no_installer), ready.release)
        }
    }

    /** Leaves a finished or failed attempt; a download in flight is stopped. */
    fun reset() {
        job?.cancel()
        job = null
        _state.value = UpdateState.Idle
    }

    /** Opens the release on GitHub, for the copies that cannot update themselves. */
    fun openReleasePage(activityContext: Context, release: Release?) {
        startSafely(activityContext, Intent(Intent.ACTION_VIEW, (release?.pageUrl ?: Releases.LATEST_PAGE_URL).toUri()))
    }

    /** The free build's store: whatever handles market links (F-Droid's client does), else its web page. */
    fun openStore(activityContext: Context) {
        val market = Intent(Intent.ACTION_VIEW, "market://details?id=${context.packageName}".toUri())
        if (startSafely(activityContext, market)) return
        startSafely(activityContext, Intent(Intent.ACTION_VIEW, "https://f-droid.org/packages/${context.packageName}/".toUri()))
    }

    private fun startSafely(activityContext: Context, intent: Intent): Boolean {
        if (activityContext === context) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            activityContext.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    /**
     * Direct first. When that fails, through the server the tunnel is on —
     * or, with the tunnel down, the one it would connect to — since GitHub
     * is exactly the kind of site some networks block.
     */
    private fun routes(): List<UpdateRoute> {
        val repository = ConfigRepository.get(context)
        val server: ProxyConfiguration? = MythaiaVpnService.activeConfigId?.let { repository.get(it) }
            ?: prefs.getString("selectedConfigurationId", null)
                ?.let { runCatching { UUID.fromString(it) }.getOrNull() }
                ?.let { repository.get(it) }
        val usable = server?.takeIf { it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3 }
        return listOfNotNull(UpdateRoute.Direct, usable?.let { UpdateRoute.Through(it) })
    }

    /**
     * Refuses an APK that is not the next version of this very app signed
     * with the release key. The checksum says the file is the one the
     * release lists; this says the release is ours.
     */
    private fun verifyApk(file: File) {
        val info = archiveInfo(file) ?: throw UpdateException(context.getString(com.mythaia.R.string.update_bad_apk))
        if (info.packageName != context.packageName) {
            throw UpdateException(context.getString(com.mythaia.R.string.update_bad_apk))
        }
        @Suppress("DEPRECATION")
        val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else info.versionCode.toLong()
        if (code <= BuildConfig.VERSION_CODE) {
            throw UpdateException(context.getString(com.mythaia.R.string.update_not_newer))
        }
        val signers = signers(info)
        if (signers.size != 1 || sha256(signers[0]) != Releases.ANDROID_RELEASE_CERT_SHA256) {
            file.delete()
            throw UpdateException(context.getString(com.mythaia.R.string.update_wrong_signature))
        }
    }

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    private fun archiveInfo(file: File): PackageInfo? {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
        else PackageManager.GET_SIGNATURES
        return pm.getPackageArchiveInfo(file.absolutePath, flags)
    }

    @SuppressLint("PackageManagerGetSignatures")
    @Suppress("DEPRECATION")
    private fun installedCertSha256(): String? = runCatching {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
        }
        signers(info).singleOrNull()?.let { sha256(it) }
    }.getOrNull()

    /** The certificates the APK's contents are signed with now (not ones it rotated away from). */
    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo): List<Signature> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signing = info.signingInfo
            if (signing != null) return signing.apkContentsSigners?.toList().orEmpty()
        }
        return info.signatures?.toList().orEmpty()
    }

    private fun sha256(signature: Signature): String =
        MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }

    private fun updatesDir(): File = File(context.cacheDir, UPDATES_DIR).apply { mkdirs() }

    /** Old downloads go: an installed update leaves its APK behind otherwise. */
    private fun cleanUp() {
        if (_state.value is UpdateState.Ready) return
        File(context.cacheDir, UPDATES_DIR).listFiles()?.forEach { it.delete() }
    }

    private fun message(e: Exception): String = e.message ?: context.getString(com.mythaia.R.string.unknown_error)

    companion object {
        private const val KEY_AUTO_CHECK = "updateAutoCheck"
        private const val KEY_LAST_CHECK = "updateLastCheck"
        private const val KEY_DISMISSED = "updateDismissedTag"
        private const val UPDATES_DIR = "updates"
        private const val APK_MIME = "application/vnd.android.package-archive"
        private const val CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000L
        private const val PROGRESS_STEP = 128 * 1024L

        // Holds the application context only, which lives as long as the process.
        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: AppUpdater? = null

        fun get(context: Context): AppUpdater =
            instance ?: synchronized(this) {
                instance ?: AppUpdater(context.applicationContext).also { instance = it }
            }
    }
}
