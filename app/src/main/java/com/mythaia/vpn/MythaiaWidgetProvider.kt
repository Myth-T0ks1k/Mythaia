package com.mythaia.vpn

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import com.mythaia.MainActivity
import com.mythaia.R

/**
 * The home-screen widget: connection state, the server in use, and one tap to
 * toggle.
 *
 * Like the Quick Settings tile it stops the tunnel itself and hands a connect
 * to the app, which is the only place the consent dialog and the routing sync
 * can happen.
 */
class MythaiaWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        for (id in appWidgetIds) {
            appWidgetManager.updateAppWidget(id, buildViews(context))
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)

        if (intent.action == ACTION_TOGGLE) {
            if (MythaiaVpnService.isActive) {
                context.startService(
                    Intent(context, MythaiaVpnService::class.java)
                        .apply { action = MythaiaVpnService.ACTION_STOP }
                )
            } else {
                context.startActivity(
                    Intent(context, MainActivity::class.java).apply {
                        action = MainActivity.ACTION_CONNECT
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    }
                )
            }
            // The service publishes its own change too, but a stop takes a
            // moment to land; redraw now so the tap is acknowledged.
            refresh(context)
        }
    }

    private fun buildViews(context: Context): RemoteViews {
        val active = MythaiaVpnService.isActive
        val views = RemoteViews(context.packageName, R.layout.widget_mythaia)

        views.setTextViewText(
            R.id.widget_status,
            context.getString(if (active) R.string.connected else R.string.disconnected)
        )
        // The server, not the traffic: a widget cannot hold a binding to read
        // live counters, and a frozen number is worse than none.
        views.setTextViewText(
            R.id.widget_traffic,
            if (active) {
                MythaiaVpnService.activeServerName ?: context.getString(R.string.connected)
            } else {
                context.getString(R.string.tap_to_connect)
            }
        )
        views.setInt(
            R.id.widget_indicator,
            "setColorFilter",
            context.getColor(if (active) R.color.widget_on else R.color.widget_off)
        )

        val toggle = Intent(context, MythaiaWidgetProvider::class.java).apply {
            action = ACTION_TOGGLE
        }
        views.setOnClickPendingIntent(
            R.id.widget_root,
            PendingIntent.getBroadcast(
                context,
                0,
                toggle,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
        )
        return views
    }

    companion object {
        const val ACTION_TOGGLE = "com.mythaia.WIDGET_TOGGLE"

        /** Redraws every placed instance. Safe to call when none exist. */
        fun refresh(context: Context) {
            val manager = AppWidgetManager.getInstance(context) ?: return
            val ids = manager.getAppWidgetIds(
                ComponentName(context, MythaiaWidgetProvider::class.java)
            )
            if (ids.isEmpty()) return
            manager.updateAppWidget(ids, MythaiaWidgetProvider().buildViews(context))
        }
    }
}
