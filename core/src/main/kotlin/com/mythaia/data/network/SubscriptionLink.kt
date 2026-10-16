package com.mythaia.data.network

import com.mythaia.data.model.percentDecode

/**
 * A subscription link that carries its own domain fronting, so a panel whose
 * domain is blocked is added in one step: paste or open the link and the
 * download already goes through the front, with nothing to fill in by hand.
 *
 * Two forms, read wherever a subscription is added:
 *
 * - the panel's URL with the settings in its fragment, which is never sent
 *   to the panel:
 *   `https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org`
 * - a link that opens the app, the panel's URL percent-encoded:
 *   `mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub%2FTOKEN&front=104.16.1.1&sni=www.example.org`
 *
 * `front` lists the hosts actually dialled (a host or IP, optionally `:port`;
 * comma-separated or repeated), `sni` the name sent in the TLS handshake
 * (`front-sni` is read too), `name` an optional name for the group. With
 * `sni` and no `front`, the panel's own host is dialled with that SNI.
 *
 * Happ's form is read too, where the URL names the front rather than the
 * panel: `https://cdn-front.example/sub/TOKEN#Name?resolve-address=104.16.1.1&host=panel.example.com`
 * dials `resolve-address` (the front's own address when absent), sends the
 * URL's host as the SNI and asks for `host`.
 */
data class SubscriptionLink(
    val url: String,
    val frontSni: String? = null,
    val frontTargets: List<String> = emptyList(),
    val name: String? = null
) {
    /** Whether the download goes through a front rather than straight to [url]. */
    val isFronted: Boolean get() = frontTargets.isNotEmpty()

    /** The panel URL with the fronting in its fragment; [url] itself when there is none. */
    fun toFragmentLink(): String {
        val params = settingParams()
        return if (params.isEmpty()) url else url + "#" + params.joinToString("&")
    }

    /** A `mythaia://import` link that adds this subscription, fronting included, when opened. */
    fun toAppLink(): String =
        (listOf("url=" + encode(url, keep = "")) + settingParams()).joinToString("&", prefix = APP_PREFIX)

    private fun settingParams(): List<String> = buildList {
        if (frontTargets.isNotEmpty()) add("front=" + frontTargets.joinToString(",") { encode(it) })
        frontSni?.let { add("sni=" + encode(it)) }
        name?.let { add("name=" + encode(it)) }
    }

    companion object {
        private const val APP_PREFIX = "mythaia://import?"
        private val SNI_KEYS = setOf("sni", "front-sni", "frontsni", "front_sni")
        private val FRONT_KEYS = setOf("front", "resolve-address")
        private val OWN_KEYS = SNI_KEYS + FRONT_KEYS + setOf("name", "host")

        /** Whether [link] is an http(s) URL or app import link that asks for fronting. */
        fun isFrontedLink(link: String): Boolean = parse(link)?.isFronted == true

        /**
         * Reads [link] in either form. Null when it is neither an http(s) URL
         * nor a `mythaia://import` link; an http(s) URL whose fragment holds
         * none of the keys above comes back exactly as given.
         */
        fun parse(link: String): SubscriptionLink? {
            val s = link.trim()
            if (s.startsWith(APP_PREFIX, ignoreCase = true)) return parseAppLink(s.substring(APP_PREFIX.length))
            if (!isHttp(s)) return null
            val hash = s.indexOf('#')
            if (hash < 0) return SubscriptionLink(s)
            val params = fragmentParams(s.substring(hash + 1))
            // A name alone is read too: an import link with a name and no
            // fronting used to leave "#name=…" on the stored URL.
            if (params.none { it.first in OWN_KEYS }) return SubscriptionLink(s)
            return fromParams(s.substring(0, hash), params)
        }

        private fun parseAppLink(rest: String): SubscriptionLink? {
            val query = rest.substringBefore('#')
            val fragment = rest.substringAfter('#', "")
            val parts = query.split('&').filter { it.isNotEmpty() }
            val urlIndex = parts.indexOfFirst { it.startsWith("url=", ignoreCase = true) }
            if (urlIndex < 0) return null
            var url = percentDecode(parts[urlIndex].substring(4)).trim()
            if (!isHttp(url)) return null

            // Our own links encode the URL. One written by hand may not, and the
            // panel's own query (…/sub?token=1&lang=ru) then lands beside ours:
            // whatever after `url=` is not ours goes back onto the URL.
            val own = mutableListOf<Pair<String, String>>()
            parts.forEachIndexed { i, part ->
                if (i == urlIndex) return@forEachIndexed
                val key = percentDecode(part.substringBefore('=')).lowercase()
                if (key in OWN_KEYS) own += key to percentDecode(part.substringAfter('=', ""))
                else if (i > urlIndex) url += (if ('?' in url) "&" else "?") + part
            }
            // `#name` as Hiddify writes it, or settings put in the fragment.
            if (fragment.isNotEmpty()) {
                if ('=' in fragment) own += fragmentParams(fragment)
                else own += "name" to percentDecode(fragment)
            }
            // A hand-written link may also carry the fragment form inside the URL.
            val inner = parse(url) ?: return null
            val outer = fromParams(inner.url, own)
            return SubscriptionLink(
                url = inner.url,
                frontSni = outer.frontSni ?: inner.frontSni,
                frontTargets = outer.frontTargets.ifEmpty { inner.frontTargets },
                name = outer.name ?: inner.name
            )
        }

        private fun fromParams(url: String, params: List<Pair<String, String>>): SubscriptionLink {
            var panelUrl = url
            var sni = params.lastOrNull { it.first in SNI_KEYS && it.second.isNotBlank() }?.second?.trim()
            var targets = params.filter { it.first in FRONT_KEYS }
                .flatMap { it.second.split(',') }
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
            // Happ's `host`: the URL names the front, `host` the panel.
            val host = params.lastOrNull { it.first == "host" && it.second.isNotBlank() }?.second?.trim()
            val front = hostAndPort(url)
            if (host != null && front != null && !sameHost(host, front)) {
                SubscriptionMetadata.replaceHost(url, host)?.let { moved ->
                    panelUrl = moved
                    if (sni == null) sni = hostOnly(front)
                    if (targets.isEmpty()) targets = listOf(front)
                }
            }
            // An SNI on its own fronts the panel's own address: the name in the
            // handshake is what a filter reads, wherever the packets go.
            if (targets.isEmpty() && sni != null) targets = listOfNotNull(hostAndPort(panelUrl))
            return SubscriptionLink(
                url = panelUrl,
                frontSni = sni,
                frontTargets = targets,
                name = params.lastOrNull { it.first == "name" && it.second.isNotBlank() }?.second?.trim()
            )
        }

        /**
         * A fragment's settings: `key=value&…`, or Happ's `Name?key=value&…`,
         * whose part before the `?` names the group.
         */
        private fun fragmentParams(fragment: String): List<Pair<String, String>> {
            val q = fragment.indexOf('?')
            if (q < 0 || '=' in fragment.substring(0, q)) return parseParams(fragment)
            val name = percentDecode(fragment.substring(0, q)).trim()
            val params = parseParams(fragment.substring(q + 1))
            return if (name.isEmpty() || params.any { it.first == "name" }) params else params + ("name" to name)
        }

        private fun hostOnly(hostPort: String): String =
            if (hostPort.startsWith('[')) hostPort.substring(1).substringBefore(']') else hostPort.substringBefore(':')

        private fun sameHost(a: String, b: String): Boolean = hostOnly(a).equals(hostOnly(b), ignoreCase = true)

        private fun parseParams(s: String): List<Pair<String, String>> =
            s.split('&').filter { it.isNotEmpty() }.map { part ->
                percentDecode(part.substringBefore('=')).lowercase() to percentDecode(part.substringAfter('=', ""))
            }

        private fun isHttp(s: String): Boolean =
            s.startsWith("https://", ignoreCase = true) || s.startsWith("http://", ignoreCase = true)

        private fun hostAndPort(url: String): String? =
            url.substringAfter("://").substringBefore('/').substringBefore('?').substringBefore('#')
                .substringAfterLast('@').takeIf { it.isNotEmpty() }

        /** Percent-encodes [s], leaving the unreserved characters and those in [keep] as they are. */
        private fun encode(s: String, keep: String = ":[]"): String {
            val out = StringBuilder()
            for (b in s.toByteArray(Charsets.UTF_8)) {
                val c = (b.toInt() and 0xFF).toChar()
                if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in "-._~" || c in keep) out.append(c)
                else out.append('%').append("%02X".format(b.toInt() and 0xFF))
            }
            return out.toString()
        }
    }
}
