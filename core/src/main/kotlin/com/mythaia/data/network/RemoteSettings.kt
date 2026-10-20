package com.mythaia.data.network

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.routing.IpRanges

/**
 * The keys a provider uses to set up the app, which Happ sells behind a
 * Provider ID and Mythaia reads for every subscription.
 *
 * They are read like the other metadata (header first, then a `#key: value`
 * body line) but only from a response that came over verified TLS: settings
 * that turn off fragmentation or send apps around the tunnel are not
 * something anyone on the path may decide. The user can refuse them all
 * with one switch.
 *
 * Two kinds:
 *
 *  - [SUBSCRIPTION_KEYS] are about the subscription that sends them (its
 *    User-Agent, how its servers sort, whether their settings are hidden)
 *    and [SubscriptionMetadata.applyTo] reads them on every refresh;
 *  - [APP_KEYS] set the app as a whole, so each is applied only when its
 *    value differs from the one this subscription sent before: a setting the
 *    user changes afterwards stays theirs until the provider sends a new one.
 *
 * | key | effect |
 * |---|---|
 * | `subscription-autoconnect`, `-type` (`lastused`, `lowestdelay`, `random`) | connect to this subscription's servers when the app opens |
 * | `subscription-ping-onopen-enabled` | measure them when the app opens |
 * | `change-user-agent` | the User-Agent this subscription is fetched with |
 * | `subscriptions-sort-type` (`without`, `ping`, `alphabet`) | how its servers are listed |
 * | `subscription-pin` | its group first in the list |
 * | `subscriptions-collapse: 0`, `subscriptions-expand-now` | its group cannot be folded / is unfolded |
 * | `hide-settings` | no editor, no links for its servers |
 * | `ping-type` (`proxy`, `proxy-head`, `tcp`, `icmp`), `check-url-via-proxy` | how servers are measured |
 * | `fragmentation-enable`, `-packets`, `-length`, `-interval` | the TLS hello fragmentation |
 * | `exclude-routes`, `exclude-routes-set` | addresses kept out of the tunnel |
 * | `per-app-proxy-mode`, `-list`, `-list-invert`, `-list-set` | which apps use the tunnel (Android) |
 * | `app-auto-start` | connect when the device starts (Android) |
 */
object RemoteSettings {

    val SUBSCRIPTION_KEYS = listOf(
        "subscription-autoconnect", "subscription-autoconnect-type", "subscription-ping-onopen-enabled",
        "change-user-agent", "subscriptions-sort-type", "subscription-pin",
        "subscriptions-collapse", "subscriptions-expand-now", "hide-settings"
    )

    val APP_KEYS = listOf(
        "ping-type", "check-url-via-proxy",
        "fragmentation-enable", "fragmentation-packets", "fragmentation-length", "fragmentation-interval",
        "exclude-routes", "exclude-routes-set",
        "per-app-proxy-mode", "per-app-proxy-list", "per-app-proxy-list-invert", "per-app-proxy-list-set",
        "app-auto-start"
    )

    private const val MAX_VALUE = 8192

    /**
     * The keys of both kinds present in a response, keys lower-case, values
     * trimmed and `base64:` decoded; empty when the response was not [secure].
     */
    fun read(raw: (String) -> String?, secure: Boolean): Map<String, String> {
        if (!secure) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (key in SUBSCRIPTION_KEYS + APP_KEYS) {
            val value = SubscriptionMetadata.decode(raw(key)?.trim())?.trim() ?: continue
            if (value.length <= MAX_VALUE) out[key] = value
        }
        return out
    }

    /** The app keys in [settings] whose value differs from [applied], the ones last acted on. */
    fun changedAppKeys(applied: Map<String, String>, settings: Map<String, String>): Map<String, String> =
        settings.filter { (key, value) -> key in APP_KEYS && applied[key] != value }

    /** Happ's flags: on for `true` or `1`. */
    fun flag(value: String?): Boolean? = value?.trim()?.lowercase()?.let { it == "true" || it == "1" }

    /** `subscription-autoconnect` with its `-type`, or null when it is off or absent. */
    fun autoConnect(settings: Map<String, String>): String? {
        if (flag(settings["subscription-autoconnect"]) != true) return null
        return when (settings["subscription-autoconnect-type"]?.lowercase()) {
            AUTO_LOWEST_DELAY -> AUTO_LOWEST_DELAY
            AUTO_RANDOM -> AUTO_RANDOM
            else -> AUTO_LAST_USED
        }
    }

    const val AUTO_LAST_USED = "lastused"
    const val AUTO_LOWEST_DELAY = "lowestdelay"
    const val AUTO_RANDOM = "random"

    const val SORT_PING = "ping"
    const val SORT_ALPHABET = "alphabet"

    /** `subscriptions-sort-type`: [SORT_PING], [SORT_ALPHABET], or null for the panel's own order. */
    fun serverSort(settings: Map<String, String>): String? = when (settings["subscriptions-sort-type"]?.lowercase()) {
        SORT_PING -> SORT_PING
        SORT_ALPHABET -> SORT_ALPHABET
        else -> null
    }

    /**
     * `change-user-agent`, when it can go in a header as is: printable ASCII,
     * no line breaks (which would let a panel write headers of its own).
     */
    fun userAgent(settings: Map<String, String>): String? =
        settings["change-user-agent"]?.trim()?.takeIf { ua ->
            ua.isNotEmpty() && ua.length <= 256 && ua.all { it in ' '..'~' }
        }

    /**
     * `ping-type` as the nearest measurement Mythaia has: `proxy` and
     * `proxy-head` are a request through the server, `tcp` and `icmp` the
     * plain reachability ping (Mythaia sends no ICMP).
     */
    fun latencyKind(value: String?): LatencyKind? = when (value?.trim()?.lowercase()) {
        "proxy", "proxy-head" -> LatencyKind.HTTP
        "tcp", "icmp" -> LatencyKind.TCP
        else -> null
    }

    /** `check-url-via-proxy`, when it is an http(s) URL with a host. */
    fun checkUrl(value: String?): String? {
        val url = value?.trim()?.takeIf { it.length <= 2048 } ?: return null
        val parsed = runCatching { java.net.URI(url) }.getOrNull() ?: return null
        val scheme = parsed.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") return null
        if (parsed.host.isNullOrEmpty()) return null
        return url
    }

    /**
     * [current] with the `fragmentation-*` keys of [settings] laid over it,
     * or null when there are none. `-packets` is not read: Mythaia cuts the
     * TLS hello whatever was asked, which is what every value there amounts to
     * against a filter that reads the server name.
     */
    fun fragment(current: FragmentSettings, settings: Map<String, String>): FragmentSettings? {
        val keys = listOf("fragmentation-enable", "fragmentation-packets", "fragmentation-length", "fragmentation-interval")
        if (keys.none { it in settings }) return null
        var next = current
        flag(settings["fragmentation-enable"])?.let { next = next.copy(isEnabled = it) }
        range(settings["fragmentation-length"])?.let { r ->
            if (r.first >= 1) next = next.copy(minLength = r.first, maxLength = r.last, lengthSteps = emptyList())
        }
        range(settings["fragmentation-interval"])?.let { r ->
            next = next.copy(minInterval = r.first, maxInterval = r.last, delaySteps = emptyList())
        }
        return next
    }

    /** `10`, `10-20`; null for anything else. */
    private fun range(value: String?): IntRange? {
        val ends = value?.trim()?.split('-')?.map { it.trim() } ?: return null
        val low = ends.getOrNull(0)?.toIntOrNull() ?: return null
        val high = if (ends.size == 2) ends[1].toIntOrNull() ?: return null else if (ends.size == 1) low else return null
        if (low < 0 || high < low || high > 10_000) return null
        return low..high
    }

    /**
     * The excluded routes after [settings]: `exclude-routes-set` replaces
     * [current], `exclude-routes` adds to it. Null when neither is present.
     * Entries are CIDRs or single addresses, comma or space separated.
     */
    fun excludeRoutes(current: List<String>, settings: Map<String, String>): List<String>? {
        val set = settings["exclude-routes-set"]
        val add = settings["exclude-routes"]
        if (set == null && add == null) return null
        val base = if (set != null) cidrs(set) else current
        return (base + (add?.let { cidrs(it) } ?: emptyList())).distinct().take(MAX_ROUTES)
    }

    private const val MAX_ROUTES = 256

    /** The valid CIDRs in [value], written as `address/prefix`. */
    fun cidrs(value: String): List<String> =
        value.split(',', ' ', '\n', ';').map { it.trim() }.filter { it.isNotEmpty() }
            .mapNotNull { text -> IpRanges.parseCidr(text)?.let { text.substringBefore('/') + "/" + it.second } }
            .distinct()

    /** Android package names in [value], comma or space separated. */
    fun packages(value: String?): List<String> =
        value.orEmpty().split(',', ' ', '\n', ';').map { it.trim() }.filter { PACKAGE.matches(it) }.distinct().take(2000)

    private val PACKAGE = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+")

    /** `per-app-proxy-mode`: `on` (only the listed apps), `bypass` (all but them), `off`. */
    fun perAppMode(value: String?): String? = when (value?.trim()?.lowercase()) {
        "on" -> "on"
        "bypass" -> "bypass"
        "off" -> "off"
        else -> null
    }
}
