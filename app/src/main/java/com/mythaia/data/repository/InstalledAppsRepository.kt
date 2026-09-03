package com.mythaia.data.repository

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("SplitTunnel")

/** One installed app the user can put on either side of the tunnel. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val icon: Drawable?
)

/**
 * Lists the apps offered on the split-tunnel screen.
 *
 * Only apps holding `android.permission.INTERNET` are listed: an app that
 * cannot open a socket has nothing to route either way, and leaving them out
 * keeps the list to a length someone can actually scan.
 */
class InstalledAppsRepository(private val context: Context) {

    fun load(): List<InstalledApp> {
        val pm = context.packageManager
        val self = context.packageName

        val packages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        } catch (e: Exception) {
            // A very large package list can blow the Binder transaction limit.
            logger.error("Failed to list installed packages: ${e.message ?: e}")
            return emptyList()
        }

        return packages.asSequence()
            .filter { it.packageName != self }
            .filter { it.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true }
            .mapNotNull { pkg ->
                val info = pkg.applicationInfo ?: return@mapNotNull null
                InstalledApp(
                    packageName = pkg.packageName,
                    label = runCatching { pm.getApplicationLabel(info).toString() }
                        .getOrDefault(pkg.packageName),
                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                    icon = runCatching { pm.getApplicationIcon(info) }.getOrNull()
                )
            }
            // Case-insensitive by label so the list reads the same in every
            // locale, with the package name breaking ties between apps that
            // share a display name.
            .sortedWith(compareBy({ it.label.lowercase() }, { it.packageName }))
            .toList()
    }
}
