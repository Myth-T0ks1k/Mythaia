package com.mythaia.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.mythaia.MainActivity
import com.mythaia.R
import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("Tile")

/**
 * The Quick Settings tile: the tunnel on and off from the notification shade.
 *
 * Stopping is done here; starting is handed to the app. A connect needs the VPN
 * consent dialog, a routing sync and a DNS resolve, and a tile can present none
 * of those — duplicating that path here would mean a second, quietly divergent
 * copy of it.
 */
class MythaiaTileService : TileService() {

    private val onVpnStateChanged: () -> Unit = { refresh() }

    override fun onStartListening() {
        super.onStartListening()
        MythaiaVpnService.addStateListener(onVpnStateChanged)
        refresh()
    }

    override fun onStopListening() {
        MythaiaVpnService.removeStateListener(onVpnStateChanged)
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()

        if (MythaiaVpnService.isActive) {
            startService(
                Intent(this, MythaiaVpnService::class.java)
                    .apply { action = MythaiaVpnService.ACTION_STOP }
            )
            // Show the change at once rather than waiting for the service to
            // wind down; the listener corrects it either way.
            updateTile(active = false)
            return
        }

        openAppToConnect()
    }

    /**
     * Opens the app with a request to connect.
     *
     * From Android 14 the shade will only collapse for a PendingIntent handed
     * to startActivityAndCollapse; the older overload throws there.
     */
    private fun openAppToConnect() {
        val intent = Intent(this, MainActivity::class.java).apply {
            action = MainActivity.ACTION_CONNECT
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pending = PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (e: Exception) {
            logger.warning("[Tile] Could not open the app: ${e.message ?: e}")
        }
    }

    private fun refresh() {
        // A tunnel the tile did not start still counts as on, and consent that
        // was revoked leaves the tile unavailable rather than lying about it.
        val ready = VpnService.prepare(this) == null || MythaiaVpnService.isActive
        updateTile(active = MythaiaVpnService.isActive, available = ready)
    }

    private fun updateTile(active: Boolean, available: Boolean = true) {
        val tile = qsTile ?: return
        tile.state = when {
            !available -> Tile.STATE_UNAVAILABLE
            active -> Tile.STATE_ACTIVE
            else -> Tile.STATE_INACTIVE
        }
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                if (active) R.string.connected else R.string.disconnected
            )
        }
        tile.updateTile()
    }
}
