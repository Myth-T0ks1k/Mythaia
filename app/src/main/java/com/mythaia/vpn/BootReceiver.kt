package com.mythaia.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.mythaia.data.network.ProviderKeys
import com.mythaia.vpn.util.MythaiaLogger

/**
 * "Connect when the phone starts": brings the tunnel up on the selected
 * server after a reboot. Off unless the user — or a provider's
 * `app-auto-start` — turned it on, and only once the user has granted the
 * VPN permission: a boot is no moment to ask for it.
 *
 * Android's own always-on VPN does the same more thoroughly; this is for
 * those who never found that setting.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean(ProviderKeys.AppSettings.KEY_START_ON_BOOT, false)) return
        if (MythaiaVpnService.isActive) return
        if (VpnService.prepare(context) != null) {
            logger.warning("[Boot] Not connecting: the VPN permission is not granted")
            return
        }
        val pending = goAsync()
        // start() resolves the server's name, which must not run on the main thread.
        Thread {
            try {
                TunnelLauncher.startSelected(context.applicationContext)?.let { refusal ->
                    logger.warning("[Boot] Not connecting: $refusal")
                }
            } catch (e: Exception) {
                logger.warning("[Boot] Start failed: ${e.message ?: e}")
            } finally {
                pending.finish()
            }
        }.start()
    }

    private companion object {
        val logger = MythaiaLogger("Boot")
    }
}
