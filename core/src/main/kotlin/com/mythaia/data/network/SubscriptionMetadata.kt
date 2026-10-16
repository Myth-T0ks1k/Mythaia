package com.mythaia.data.network

import com.mythaia.data.model.Subscription
import com.mythaia.vpn.util.decodeBase64Lenient

/**
 * What a panel says about a subscription besides its servers.
 *
 * Every key is read from the response headers first and, failing that, from
 * a `#key: value` line in the body — the two places Happ reads them, so a
 * panel set up for Happ (Remnawave, Marzban, 3x-ui) works here unchanged.
 * Text values may be plain or `base64:`-prefixed; a flag is on for `true` or
 * `1` and off for any other value.
 *
 * | key | effect |
 * |---|---|
 * | `profile-title`, `subscription-userinfo` | name; traffic and expiry |
 * | `announce`, `support-url`, `profile-web-page-url` | the provider's message and links |
 * | `sub-info-text`, `-color`, `-button-text`, `-button-link` | a coloured block with a button |
 * | `sub-expire` (or `notification-subs-expire`), `sub-expire-button-link` | warn three days before expiry |
 * | `profile-update-interval` | background refresh, in hours |
 * | `subscription-auto-update-open-enable` | refresh whenever the app opens |
 * | `subscription-auto-update-enable` | `0` keeps the background refresh away |
 * | `subscription-request-timeout` | seconds to wait for the panel |
 * | `new-url` | the subscription moves there for good |
 * | `new-domain` | the same, keeping the path |
 * | `fallback-url` | fetched when the URL does not answer |
 * | `fronting-target` (or `resolve-address`) | hosts to dial instead of the panel; `off` stops fronting |
 * | `fronting-sni` | the name sent in the TLS handshake |
 * | `host` | with a target, Happ's name for the panel's real host |
 *
 * The keys that send the subscription elsewhere — `new-url`, `new-domain`,
 * `fallback-url` and the fronting ones — count only in a response that came
 * over verified TLS. From a plain-HTTP panel anyone on the path could move
 * the subscription for good.
 */
object SubscriptionMetadata {

    /** Lines like `#profile-title: My VPN`. */
    private val BODY_LINE = Regex("""^\s*#\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*?)\s*$""")
    private val HOST_NAME = Regex("""^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$""")
    private val OFF_WORDS = setOf("off", "none", "disable", "disabled", "0", "false")
    private const val MAX_URL = 2048

    /** The `#key: value` lines of [body], keys lower-cased; the first of a repeated key wins. */
    fun bodyFields(body: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in body.lineSequence()) {
            if (!line.trimStart().startsWith('#')) continue
            val m = BODY_LINE.matchEntire(line) ?: continue
            out.putIfAbsent(m.groupValues[1].lowercase(), m.groupValues[2])
        }
        return out
    }

    /** Whether [line] is one of the metadata lines [bodyFields] reads. */
    fun isMetadataLine(line: String): Boolean = BODY_LINE.matches(line)

    /**
     * The panel's metadata, each key read through [header] and then [body].
     * [secure] is whether the response arrived over verified TLS.
     */
    fun read(header: (String) -> String?, body: Map<String, String>, secure: Boolean): SubscriptionFetcher.PanelInfo {
        fun raw(name: String): String? =
            header(name)?.trim()?.takeIf { it.isNotEmpty() } ?: body[name]?.trim()?.takeIf { it.isNotEmpty() }
        fun text(name: String, limit: Int): String? = decode(raw(name))?.trim()?.takeIf { it.isNotEmpty() }?.take(limit)
        fun link(name: String): String? = raw(name)?.takeIf { it.length <= MAX_URL && isLink(it) }
        fun flag(name: String): Boolean? = raw(name)?.lowercase()?.let { it == "true" || it == "1" }
        fun httpsUrl(name: String): String? = if (secure) raw(name)?.takeIf { it.length <= MAX_URL && isHttpsUrl(it) } else null

        val target = if (secure) raw("fronting-target") ?: raw("resolve-address") else null
        val frontingOff = target != null && target.lowercase() in OFF_WORDS
        val targets = if (target == null || frontingOff) null else target.split(',')
            .map { it.trim() }.filter { isHostPort(it) }.distinct().take(16).takeIf { it.isNotEmpty() }

        return SubscriptionFetcher.PanelInfo(
            title = text("profile-title", 100),
            userInfo = raw("subscription-userinfo"),
            announce = text("announce", 1000),
            supportUrl = link("support-url"),
            webPageUrl = link("profile-web-page-url"),
            updateIntervalHours = raw("profile-update-interval")?.toIntOrNull()?.takeIf { it in 1..720 },
            updateOnOpen = flag("subscription-auto-update-open-enable"),
            autoUpdate = flag("subscription-auto-update-enable"),
            requestTimeoutSeconds = raw("subscription-request-timeout")?.toIntOrNull()?.takeIf { it in 3..60 },
            newUrl = httpsUrl("new-url"),
            newDomain = if (secure) raw("new-domain")?.lowercase()?.takeIf { isHostPort(it) } else null,
            fallbackUrl = httpsUrl("fallback-url"),
            frontTargets = targets,
            frontingOff = frontingOff,
            frontSni = if (secure && !frontingOff) raw("fronting-sni")?.lowercase()?.takeIf { HOST_NAME.matches(it) } else null,
            frontHost = if (targets != null) raw("host")?.lowercase()?.takeIf { isHostPort(it) } else null,
            subInfo = text("sub-info-text", 500)?.let { infoText ->
                Subscription.SubInfo(
                    text = infoText,
                    color = raw("sub-info-color")?.lowercase()?.takeIf { it in setOf("red", "blue", "green") } ?: "blue",
                    buttonText = text("sub-info-button-text", 40),
                    buttonLink = link("sub-info-button-link")
                )
            },
            expireNotice = flag("sub-expire") ?: flag("notification-subs-expire"),
            expireButtonLink = link("sub-expire-button-link")
        )
    }

    /**
     * [current] after a successful fetch: the servers' metadata folded in, and
     * the subscription moved where the panel says it now lives. A key the
     * panel leaves out keeps its old value, except the messages, which a panel
     * that stops sending them has withdrawn.
     */
    fun applyTo(current: Subscription, result: SubscriptionFetcher.Result, now: Long = System.currentTimeMillis()): Subscription {
        val panel = result.panel

        // new-url may carry fronting of its own, in either link form.
        val newLink = panel.newUrl?.let { SubscriptionLink.parse(it) }
        var url = newLink?.url
            ?: panel.newDomain?.let { replaceHost(current.url, it) }
            ?: current.url
        var sni = if (newLink?.isFronted == true) newLink.frontSni else current.frontSni
        var targets = if (newLink?.isFronted == true) newLink.frontTargets else current.frontTargets
        when {
            panel.frontingOff -> { sni = null; targets = emptyList() }
            panel.frontTargets != null -> {
                targets = panel.frontTargets
                // Happ's pair: `resolve-address` is dialled and `host` names the
                // panel, so the URL's own host is the front and goes in the SNI.
                val frontHost = panel.frontHost
                val front = hostPort(url)
                if (frontHost != null && front != null && !hostOnly(frontHost).equals(hostOnly(front), ignoreCase = true)) {
                    replaceHost(url, frontHost)?.let { moved ->
                        url = moved
                        sni = hostOnly(front)
                    }
                }
                panel.frontSni?.let { sni = it }
            }
            panel.frontSni != null -> {
                sni = panel.frontSni
                // An SNI on its own fronts the panel's own address, as in a link.
                if (targets.isEmpty()) targets = listOfNotNull(hostPort(url))
            }
        }

        return current.copy(
            lastUpdate = now,
            name = if (current.isNameCustomized) current.name else (result.name ?: newLink?.name ?: current.name),
            upload = result.upload ?: current.upload,
            download = result.download ?: current.download,
            total = result.total ?: current.total,
            expire = result.expire ?: current.expire,
            announce = panel.announce,
            subInfo = panel.subInfo,
            supportUrl = panel.supportUrl ?: current.supportUrl,
            webPageUrl = panel.webPageUrl ?: current.webPageUrl,
            updateIntervalHours = panel.updateIntervalHours ?: current.updateIntervalHours,
            updateOnOpen = panel.updateOnOpen ?: current.updateOnOpen,
            autoUpdate = panel.autoUpdate ?: current.autoUpdate,
            requestTimeoutSeconds = panel.requestTimeoutSeconds ?: current.requestTimeoutSeconds,
            expireNotice = panel.expireNotice ?: current.expireNotice,
            expireButtonLink = panel.expireButtonLink ?: current.expireButtonLink,
            url = url,
            fallbackUrl = panel.fallbackUrl?.takeIf { it != url } ?: current.fallbackUrl?.takeIf { it != url },
            frontSni = sni,
            frontTargets = targets,
            lastFailure = null,
            lastFailureMessage = null
        )
    }

    /**
     * [url] with its host replaced by [host] (`name` or `name:port`). The
     * path, query and user info stay; so does the port, unless [host] names one.
     */
    fun replaceHost(url: String, host: String): String? {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd <= 0 || host.isEmpty()) return null
        val rest = url.substring(schemeEnd + 3)
        val authorityEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }.let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, authorityEnd)
        val userInfo = authority.substringBeforeLast('@', "")
        val oldPort = portOf(authority.substringAfterLast('@'))
        val newAuthority = buildString {
            if (userInfo.isNotEmpty()) append(userInfo).append('@')
            append(host)
            if (portOf(host) == null && oldPort != null) append(':').append(oldPort)
        }
        return url.substring(0, schemeEnd + 3) + newAuthority + rest.substring(authorityEnd)
    }

    /** `host` or `host:port` of [url], without user info. */
    fun hostPort(url: String): String? =
        url.substringAfter("://", "").substringBefore('/').substringBefore('?').substringBefore('#')
            .substringAfterLast('@').takeIf { it.isNotEmpty() }

    /** [hostPort] without its port and IPv6 brackets. */
    private fun hostOnly(hostPort: String): String =
        if (hostPort.startsWith('[')) hostPort.substring(1).substringBefore(']')
        else hostPort.substringBefore(':')

    /** The port of `host:port` or `[v6]:port`; null when there is none. */
    private fun portOf(hostPort: String): String? {
        val afterHost = if (hostPort.startsWith('[')) hostPort.substringAfter(']', "") else hostPort
        if (!afterHost.startsWith(':') && afterHost.count { it == ':' } != 1) return null
        return afterHost.substringAfterLast(':').takeIf { p -> p.isNotEmpty() && p.all { it.isDigit() } }
    }

    private fun isHostPort(value: String): Boolean {
        if (value.isEmpty() || value.length > 255) return false
        if (value.startsWith('[')) {
            val close = value.indexOf(']')
            if (close < 0) return false
            val v6 = value.substring(1, close)
            val rest = value.substring(close + 1)
            return v6.isNotEmpty() && v6.all { it.isLetterOrDigit() || it == ':' || it == '.' } &&
                (rest.isEmpty() || (rest.startsWith(':') && rest.drop(1).toIntOrNull() in 1..65535))
        }
        val host = value.substringBefore(':')
        val port = value.substringAfter(':', "")
        return HOST_NAME.matches(host) && (port.isEmpty() || port.toIntOrNull() in 1..65535)
    }

    /** Plain text, or the UTF-8 behind a `base64:` prefix; null for a blank result. */
    fun decode(value: String?): String? {
        if (value == null) return null
        val decoded = if (value.startsWith("base64:")) {
            runCatching { String(decodeBase64Lenient(value.removePrefix("base64:")), Charsets.UTF_8) }.getOrNull()
        } else value
        return decoded?.takeIf { it.isNotBlank() }
    }

    private fun isLink(value: String): Boolean =
        value.startsWith("https://") || value.startsWith("http://") || value.startsWith("tg://")

    private fun isHttpsUrl(value: String): Boolean =
        value.startsWith("https://", ignoreCase = true) && hostPort(value)?.let { isHostPort(it) } == true
}
