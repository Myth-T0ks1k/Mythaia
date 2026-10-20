package com.mythaia.data.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class Subscription(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    val name: String,
    val url: String,
    val lastUpdate: Long? = null,
    val upload: Long? = null,
    val download: Long? = null,
    val total: Long? = null,
    val expire: Long? = null,
    val collapsed: Boolean = false,
    /** Whether the user manually renamed this subscription — prevents auto-overwrite on update. */
    val isNameCustomized: Boolean = false,
    /**
     * Domain fronting for the fetch itself.
     *
     * When [frontTargets] is not empty the subscription is downloaded by
     * connecting to each target in turn (a host or IP, optionally `:port`),
     * presenting [frontSni] in the TLS handshake (the URL's own host when
     * null) and the URL's host in the HTTP `Host` header. This gets a panel
     * through a filter that blocks its domain but not the CDN in front of it.
     */
    val frontSni: String? = null,
    val frontTargets: List<String> = emptyList(),
    /** The panel's `announce` header: a message from the provider, shown with the group. */
    val announce: String? = null,
    /** `support-url`: where the provider takes questions. */
    val supportUrl: String? = null,
    /** `profile-web-page-url`: the provider's page for this account. */
    val webPageUrl: String? = null,
    /** `profile-update-interval`, in hours: how often the provider asks to be refreshed. */
    val updateIntervalHours: Int? = null,
    /** `fallback-url`: where the subscription is fetched from when [url] does not answer. */
    val fallbackUrl: String? = null,
    /** `sub-info-*`: a coloured block from the provider, with an optional button. */
    val subInfo: SubInfo? = null,
    /** `sub-expire`: warn when [expire] is three days away or past. */
    val expireNotice: Boolean = false,
    /** `sub-expire-button-link`: where the expiry warning's Renew button leads. */
    val expireButtonLink: String? = null,
    /** `subscription-auto-update-open-enable`: refresh each time the app opens. */
    val updateOnOpen: Boolean = false,
    /** `subscription-auto-update-enable: 0` keeps the background refresh away from this subscription. */
    val autoUpdate: Boolean = true,
    /** `subscription-request-timeout`, in seconds. */
    val requestTimeoutSeconds: Int? = null,
    /** When the last refresh failed, and why; cleared by the next one that works. */
    val lastFailure: Long? = null,
    val lastFailureMessage: String? = null,
    /** `change-user-agent`: the User-Agent this subscription is fetched with; null for Mythaia's own. */
    val userAgent: String? = null,
    /** `subscription-pin`: the group goes first in the list. */
    val pinned: Boolean = false,
    /** `subscriptions-collapse: 0`: the group may not be folded. */
    val collapsible: Boolean = true,
    /** `subscriptions-sort-type`: `ping`, `alphabet`, or null for the panel's order. */
    val serverSort: String? = null,
    /** `hide-settings`: no editor and no share links for this subscription's servers. */
    val hideSettings: Boolean = false,
    /** `subscription-ping-onopen-enabled`: measure the servers when the app opens. */
    val pingOnOpen: Boolean = false,
    /** `subscription-autoconnect` with its type (`lastused`, `lowestdelay`, `random`); null when off. */
    val autoConnect: String? = null,
    /**
     * The app-wide keys ([com.mythaia.data.network.RemoteSettings.APP_KEYS])
     * this subscription last sent and the app acted on, so the same value is
     * not applied over the user's own choice on every refresh.
     */
    val appliedSettings: Map<String, String> = emptyMap(),
    /** Hashes of the `announce` and `sub-info-text` last raised as a notification. */
    val announceShown: String? = null,
    val infoShown: String? = null,
    /** The expiry warning last raised, as `<expire>:soon` or `<expire>:expired`. */
    val expiryShown: String? = null
) {
    /** Whether the fetch goes through a front rather than straight to the URL. */
    val isFronted: Boolean get() = frontTargets.isNotEmpty()

    @Serializable
    data class SubInfo(
        val text: String,
        /** `red`, `blue` or `green`. */
        val color: String = "blue",
        val buttonText: String? = null,
        val buttonLink: String? = null
    )

    /** Which provider-set restrictions or choices are in force, for the "managed by" note. */
    val managedSettings: Boolean
        get() = userAgent != null || pinned || !collapsible || serverSort != null || hideSettings || pingOnOpen || autoConnect != null

    /** Whether the last refresh failed, with no success since. */

    val isFailing: Boolean get() = lastFailure != null && lastFailure > (lastUpdate ?: 0L)

    /** The `sub-expire` warning due at [now], if any. */
    fun expiryWarning(now: Long = System.currentTimeMillis()): ExpiryWarning? {
        val at = expire?.takeIf { expireNotice && it > 0 } ?: return null
        return when {
            at <= now -> ExpiryWarning.Expired
            // Whole days left, as the usage card counts them: 2 days 5 hours is 2.
            at - now <= EXPIRY_WARNING_MS -> ExpiryWarning.Soon(((at - now) / DAY_MS).toInt().coerceAtLeast(1))
            else -> null
        }
    }

    sealed class ExpiryWarning {
        object Expired : ExpiryWarning()
        /** Expires within [days] days (1 to 3). */
        data class Soon(val days: Int) : ExpiryWarning()
    }

    companion object {
        private const val DAY_MS = 24 * 60 * 60 * 1000L
        private const val EXPIRY_WARNING_MS = 3 * DAY_MS
    }
}
