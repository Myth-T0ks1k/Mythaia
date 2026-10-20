package com.mythaia.data.network

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.edit
import com.mythaia.MainActivity
import com.mythaia.R
import com.mythaia.data.model.SplitTunnelMode
import com.mythaia.data.model.SplitTunnelSettings
import com.mythaia.data.model.Subscription
import com.mythaia.data.repository.InstalledAppsRepository
import com.mythaia.data.repository.RoutingProfileRepository
import com.mythaia.data.routing.HappRouting
import com.mythaia.data.routing.RoutingProfiles
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.protocol.tls.read
import com.mythaia.vpn.protocol.tls.write
import com.mythaia.vpn.util.MythaiaLogger
import org.json.JSONObject

private val logger = MythaiaLogger("Subscriptions")

/**
 * What a subscription refresh brings besides servers and metadata: the
 * provider's app settings, its routing profile, and its messages, which go
 * up as notifications. Run by the background refresh and the in-app one
 * alike, after [SubscriptionMetadata.applyTo].
 */
object ProviderKeys {

    /** The user's "let subscriptions change app settings", on unless turned off. */
    const val KEY_ALLOWED = "subscriptionSettingsAllowed"

    fun allowed(context: Context): Boolean = prefs(context).getBoolean(KEY_ALLOWED, true)

    /**
     * After a refresh turned [before] into [after] with [panel]: acts on the
     * app keys and the routing link that changed, raises the messages not
     * yet raised, and returns the subscription to store.
     */
    fun afterRefresh(context: Context, before: Subscription, after: Subscription, panel: SubscriptionFetcher.PanelInfo): Subscription {
        val applied = actOnSettings(context, before, panel)
        val (messages, marked) = ProviderMessages.due(after.copy(appliedSettings = after.appliedSettings + applied))
        if (messages.isNotEmpty()) runCatching { ProviderNotifications.post(context, marked, messages) }
            .onFailure { logger.warning("[Sub] Notification failed: ${it.message ?: it}") }
        return marked
    }

    /**
     * For a subscription just imported: the same settings, but its messages
     * only marked as seen — the user is looking at them in the app.
     */
    fun afterImport(context: Context, subscription: Subscription, panel: SubscriptionFetcher.PanelInfo): Subscription {
        val applied = actOnSettings(context, subscription.copy(appliedSettings = emptyMap()), panel)
        return ProviderMessages.markSeen(subscription.copy(appliedSettings = subscription.appliedSettings + applied))
    }

    /**
     * The app keys and the routing link [panel] carries that differ from what
     * [before] last sent, acted on; returns them, to be recorded.
     */
    private fun actOnSettings(context: Context, before: Subscription, panel: SubscriptionFetcher.PanelInfo): Map<String, String> {
        val allowed = allowed(context)
        val recorded = LinkedHashMap<String, String>()
        if (allowed) {
            val changed = RemoteSettings.changedAppKeys(before.appliedSettings, panel.settings)
            if (changed.isNotEmpty()) {
                runCatching { AppSettings.apply(context, changed, panel.settings, before.name) }
                    .onFailure { logger.warning("[Sub] Settings from ${before.name} failed: ${it.message ?: it}") }
                recorded += changed
            }
        }
        actOnRouting(context, before, panel, allowed)?.let { recorded += it }
        return recorded
    }

    private fun actOnRouting(
        context: Context,
        before: Subscription,
        panel: SubscriptionFetcher.PanelInfo,
        allowed: Boolean
    ): Map<String, String>? {
        val out = LinkedHashMap<String, String>()
        val repository = RoutingProfileRepository.get(context)
        val source = RoutingProfiles.Source(before.id.toString(), before.name)
        panel.routing?.let { value ->
            // Acted on when it changes, so a profile the user turned off is
            // not turned back on by the next hourly refresh.
            val key = value.hashCode().toString(16) + ":" + value.length
            if (before.appliedSettings[KEY_ROUTING] != key) {
                when (val command = HappRouting.parseSubscriptionValue(value, before.name)) {
                    null -> logger.warning("[Sub] ${before.name}: routing value not understood")
                    is HappRouting.Command.Add ->
                        // Without the user's leave the profile is kept, not turned on.
                        repository.handle(if (allowed) command else command.copy(activate = false), source)
                    HappRouting.Command.Off -> if (allowed) repository.handle(command, source)
                }
                out[KEY_ROUTING] = key
            }
        }
        panel.routingEnable?.let { enabled ->
            val value = enabled.toString()
            if (before.appliedSettings[KEY_ROUTING_ENABLE] != value) {
                if (!enabled && allowed) repository.off()
                out[KEY_ROUTING_ENABLE] = value
            }
        }
        return out.takeIf { it.isNotEmpty() }
    }

    private const val KEY_ROUTING = "routing"
    private const val KEY_ROUTING_ENABLE = "routing-enable"

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)

    /** The app-wide settings a provider can set, and which provider set each. */
    object AppSettings {
        const val KEY_PING_KIND = "pingKind"
        const val KEY_CHECK_URL = "latencyCheckUrl"
        const val KEY_EXCLUDED_ROUTES = "excludedRoutes"
        const val KEY_START_ON_BOOT = "startOnBoot"
        private const val KEY_MANAGED = "managedSettings"

        const val GROUP_PING = "ping"
        const val GROUP_FRAGMENT = "fragment"
        const val GROUP_ROUTES = "routes"
        const val GROUP_PER_APP = "perApp"
        const val GROUP_AUTO_START = "autoStart"

        /** Group to the name of the subscription that last set it. */
        fun managed(context: Context): Map<String, String> {
            val text = prefs(context).getString(KEY_MANAGED, null) ?: return emptyMap()
            return runCatching {
                val obj = JSONObject(text)
                obj.keys().asSequence().associateWith { obj.getString(it) }
            }.getOrDefault(emptyMap())
        }

        /** The user changed [group] by hand: it is theirs again. */
        fun release(context: Context, group: String) {
            val current = managed(context)
            if (group !in current) return
            write(context, current - group)
        }

        private fun mark(context: Context, groups: Collection<String>, source: String) {
            if (groups.isEmpty()) return
            write(context, managed(context) + groups.associateWith { source })
        }

        private fun write(context: Context, map: Map<String, String>) {
            prefs(context).edit { putString(KEY_MANAGED, JSONObject(map).toString()) }
        }

        fun excludedRoutes(context: Context): List<String> =
            prefs(context).getString(KEY_EXCLUDED_ROUTES, null)?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()

        fun setExcludedRoutes(context: Context, routes: List<String>) {
            prefs(context).edit { putString(KEY_EXCLUDED_ROUTES, routes.joinToString(",")) }
        }

        fun latencyKind(context: Context): LatencyKind? =
            prefs(context).getString(KEY_PING_KIND, null)?.let { name -> LatencyKind.entries.firstOrNull { it.name == name } }

        fun checkUrl(context: Context): String? = prefs(context).getString(KEY_CHECK_URL, null)

        /** Publishes the stored check URL to the latency tester; for every process start. */
        fun load(context: Context) {
            LatencyTester.checkUrl = checkUrl(context)
        }

        /**
         * Acts on [changed], keys from [RemoteSettings.APP_KEYS]; [all] is
         * every key the response carried, for groups such as fragmentation
         * whose keys only make sense together.
         */
        fun apply(context: Context, changed: Map<String, String>, all: Map<String, String>, source: String) {
            val prefs = prefs(context)
            val groups = LinkedHashSet<String>()

            changed["ping-type"]?.let { RemoteSettings.latencyKind(it) }?.let { kind ->
                prefs.edit { putString(KEY_PING_KIND, kind.name) }
                groups += GROUP_PING
            }
            if ("check-url-via-proxy" in changed) {
                RemoteSettings.checkUrl(changed["check-url-via-proxy"])?.let { url ->
                    prefs.edit { putString(KEY_CHECK_URL, url) }
                    LatencyTester.checkUrl = url
                    groups += GROUP_PING
                }
            }
            if (changed.keys.any { it.startsWith("fragmentation-") }) {
                RemoteSettings.fragment(FragmentPolicy.read(prefs), all)?.let { settings ->
                    FragmentPolicy.write(prefs, settings)
                    groups += GROUP_FRAGMENT
                }
            }
            RemoteSettings.excludeRoutes(excludedRoutes(context), changed)?.let { routes ->
                setExcludedRoutes(context, routes)
                groups += GROUP_ROUTES
            }
            if (changed.keys.any { it.startsWith("per-app-proxy-") }) {
                applyPerApp(context, prefs, changed)
                groups += GROUP_PER_APP
            }
            RemoteSettings.flag(changed["app-auto-start"])?.let { on ->
                prefs.edit { putBoolean(KEY_START_ON_BOOT, on) }
                groups += GROUP_AUTO_START
            }
            mark(context, groups, source)
            logger.info("[Sub] Settings from $source: ${changed.keys.joinToString()}")
        }

        private fun applyPerApp(context: Context, prefs: SharedPreferences, changed: Map<String, String>) {
            val current = SplitTunnelSettings.read(prefs)
            var mode = current.mode
            var packages = current.packages
            when (RemoteSettings.perAppMode(changed["per-app-proxy-mode"])) {
                "on" -> mode = SplitTunnelMode.ALLOW
                "bypass" -> mode = SplitTunnelMode.DISALLOW
                "off" -> mode = SplitTunnelMode.OFF
            }
            changed["per-app-proxy-list-set"]?.let { packages = RemoteSettings.packages(it).toSet() }
            changed["per-app-proxy-list-invert"]?.let { value ->
                val except = RemoteSettings.packages(value).toSet()
                packages = InstalledAppsRepository(context).load().map { it.packageName }.filterNot { it in except }.toSet()
            }
            changed["per-app-proxy-list"]?.let { packages = packages + RemoteSettings.packages(it) }
            SplitTunnelSettings.write(prefs, SplitTunnelSettings(mode, packages - context.packageName))
        }
    }
}

/** Provider messages as system notifications, on a channel of their own. */
object ProviderNotifications {

    private const val CHANNEL_ID = "provider_messages"

    fun post(context: Context, subscription: Subscription, messages: List<ProviderMessages.Message>) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, context.getString(R.string.provider_messages_channel), NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = context.getString(R.string.provider_messages_channel_description)
            }
        )
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        for (message in messages) {
            val text = when (message.kind) {
                ProviderMessages.Kind.EXPIRY -> when (val warning = message.expiry) {
                    is Subscription.ExpiryWarning.Soon ->
                        context.resources.getQuantityString(R.plurals.subscription_expires_in_days, warning.days, warning.days)
                    else -> context.getString(R.string.subscription_expired_notice)
                }
                else -> message.text ?: continue
            }
            val id = (subscription.id.hashCode() * 31 + message.kind.ordinal) and 0x7FFFFFFF
            val builder = Notification.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_stat_wing)
                .setContentTitle(subscription.name)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
            message.link?.let { link ->
                val label = message.linkLabel ?: if (message.kind == ProviderMessages.Kind.EXPIRY) {
                    context.getString(R.string.subscription_renew)
                } else context.getString(R.string.open_link)
                val view = PendingIntent.getActivity(
                    context, id, Intent(Intent.ACTION_VIEW, Uri.parse(link)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                builder.addAction(Notification.Action.Builder(null, label, view).build())
            }
            manager.notify(id, builder.build())
        }
    }
}
