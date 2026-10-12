package com.mythaia.ui.settings

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import com.mythaia.BuildConfig
import com.mythaia.vpn.util.LogBuffer
import com.mythaia.vpn.MythaiaVpnService

/**
 * The system screens a VPN app cannot replace, and the facts about the
 * system it cannot change: the kill switch lives in Android's own VPN
 * settings, Private DNS can only be turned off by the user.
 */
object SystemShortcuts {

    /**
     * Android's VPN settings: "Always-on VPN" and "Block connections without
     * VPN" — the real kill switch, enforced by the OS even while the app is
     * dead. Some OEM builds lack the exact screen, hence the fallback.
     */
    fun openVpnSettings(context: Context) {
        start(context, Intent(Settings.ACTION_VPN_SETTINGS)) || start(context, Intent(Settings.ACTION_WIRELESS_SETTINGS))
    }

    /** Per-app language (Android 13+), fed by res/xml/locales_config.xml. */
    fun openAppLanguage(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        return start(context, Intent(Settings.ACTION_APP_LOCALE_SETTINGS, Uri.fromParts("package", context.packageName, null)))
    }

    val supportsAppLanguage: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    fun openNotificationSettings(context: Context) {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        start(context, intent) || start(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)))
    }

    /** "Network & internet", where Private DNS lives; there is no intent for its own dialog. */
    fun openNetworkSettings(context: Context) {
        start(context, Intent(Settings.ACTION_WIRELESS_SETTINGS))
    }

    /**
     * The Private DNS host when Android is in strict ("hostname") mode, else
     * null. Strict mode sends DNS over TLS to that host through the tunnel,
     * past the tunnel's own DNS — so domain rules, ad blocking and fake-IP
     * routing never see the names. Automatic mode falls back to plain DNS
     * against the tunnel and is harmless, so it is not reported.
     */
    fun strictPrivateDns(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val mode = runCatching { Settings.Global.getString(context.contentResolver, "private_dns_mode") }.getOrNull()
        val specifier = runCatching { Settings.Global.getString(context.contentResolver, "private_dns_specifier") }.getOrNull()
        if (mode == "hostname" && !specifier.isNullOrBlank()) return specifier
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        return cm.allNetworks.asSequence()
            .mapNotNull { runCatching { cm.getLinkProperties(it) }.getOrNull() }
            .mapNotNull { it.privateDnsServerName }
            .firstOrNull()
    }

    /** What support needs to see, as text for the clipboard. No keys, passwords or addresses. */
    fun diagnosticsReport(context: Context, serverProtocol: String?): String = buildString {
        appendLine("Mythaia Pro ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), ${Build.MANUFACTURER} ${Build.MODEL}, ${Build.SUPPORTED_ABIS.firstOrNull()}")
        appendLine("Tunnel: ${if (MythaiaVpnService.isActive) "up" else "down"}${serverProtocol?.let { ", $it" } ?: ""}")
        appendLine("Private DNS strict: ${strictPrivateDns(context) != null}")
        appendLine()
        appendLine("Recent log:")
        val stamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
        LogBuffer.fetchLogs().takeLast(80).forEach { entry ->
            appendLine("${stamp.format(java.util.Date(entry.timestamp))} ${entry.level.name.first().uppercaseChar()} ${entry.message}")
        }
    }

    fun copyToClipboard(context: Context, label: String, text: String) {
        context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText(label, text))
    }

    private fun start(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: ActivityNotFoundException) {
        false
    } catch (_: SecurityException) {
        false
    }
}
