package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration

/**
 * Finds the share links and subscription URLs in whatever was pasted.
 *
 * People paste a whole chat message ("here is your key: vless://… valid till
 * Friday"), a list of links, or another client's import link wrapping the
 * real one (`happ://add/https://…`, `v2rayng://install-config?url=…`). The
 * add screen wanted the link and nothing else; this gets it out.
 */
object LinkExtractor {

    /** Wrapper schemes other clients put around a subscription or a link. */
    private val WRAPPERS = listOf(
        "mythaia://add-proxy?link=", "mythaia://import?url=",
        "happ://add/", "happ://import/",
        "v2rayng://install-config?url=", "v2rayn://install-config?url=",
        "hiddify://import/", "hiddify://install-config?url=",
        "sing-box://import-remote-profile?url=", "sing-box://import-remote-profile/?url=",
        "clash://install-config?url=", "clashmeta://install-config?url=",
        "streisand://import/", "karing://install-config?url=", "nekobox://install-config?url="
    )

    private val SCHEMES: List<String> = (ProxyConfiguration.parsableUrlPrefixes + listOf("http://") +
        WRAPPERS.map { it.substringBefore("://") + "://" }).distinct()

    /** Characters that end a link when it sits in running text. */
    private val TERMINATORS = setOf(' ', '\t', '\n', '\r', '"', '\'', '<', '>', '`', '«', '»', '“', '”', '‘', '’', '|')

    /**
     * Every link in [text], unwrapped and in order, duplicates removed. A link
     * in running text ends at whitespace or a quote; trailing punctuation a
     * sentence would add (`.`, `,`, `)`) is dropped unless the link needs it.
     */
    fun extract(text: String): List<String> {
        val found = LinkedHashSet<String>()
        var i = 0
        while (i < text.length) {
            val start = nextLinkStart(text, i)
            if (start < 0) break
            var end = start
            while (end < text.length && text[end] !in TERMINATORS) end++
            var link = text.substring(start, end)
            link = trimSentencePunctuation(link)
            unwrap(link)?.let { found += it }
            i = maxOf(end, start + 1)
        }
        return found.toList()
    }

    /**
     * Where the first link at or after [from] starts, or -1.
     *
     * Every scheme ends in "://", so only that is searched for, and the
     * schemes are tried against the few characters just before each hit.
     * Searching the text for each scheme in turn rescanned all of the rest
     * of it for every scheme it did not contain, once per link: a paste of
     * a few thousand servers never finished, and the add screen froze.
     */
    private fun nextLinkStart(text: String, from: Int): Int {
        var colon = text.indexOf("://", from)
        while (colon >= 0) {
            // Several schemes can end at the same "://" (`ss://` inside
            // `vmess://`); the earliest start is the one the link has.
            var start = -1
            for (scheme in SCHEMES) {
                val at = colon + 3 - scheme.length
                if (at < from || (start >= 0 && start <= at)) continue
                // Compared case-insensitively in place rather than in a
                // lowercased copy: lowercasing can change the length (Turkish
                // "İ" becomes two chars), and an offset found in the copy
                // would then land mid-link in the original.
                if (scheme.regionMatches(0, text, at, scheme.length, ignoreCase = true)) start = at
            }
            if (start >= 0) return start
            colon = text.indexOf("://", colon + 1)
        }
        return -1
    }

    /** The real link inside another client's import link, or [link] itself. */
    fun unwrap(link: String): String? {
        val lower = link.lowercase()
        // Our own import link may carry fronting beside the URL; it comes out
        // as the URL with the fronting in its fragment, which the add screen reads.
        if (lower.startsWith("mythaia://import?")) {
            SubscriptionLink.parse(link)?.let { return it.toFragmentLink() }
        }
        // A Happ routing profile is a link of its own, not a wrapper around one.
        if (com.mythaia.data.routing.HappRouting.isLink(link)) return link
        for (wrapper in WRAPPERS) {
            if (lower.startsWith(wrapper)) {
                val inner = link.substring(wrapper.length).substringBefore("#name=")
                val decoded = runCatching { java.net.URLDecoder.decode(inner, "UTF-8") }.getOrDefault(inner)
                return decoded.takeIf { it.contains("://") }
            }
        }
        if (WRAPPERS.any { lower.startsWith(it.substringBefore("://") + "://") } &&
            !ProxyConfiguration.parsableUrlPrefixes.any { lower.startsWith(it) }
        ) {
            return null
        }
        return link.takeIf { it.length > link.indexOf("://") + 3 }
    }

    private fun trimSentencePunctuation(link: String): String {
        var s = link
        while (s.isNotEmpty() && s.last() in ".,;:!?)]}") {
            // A closing bracket that the link opened belongs to it.
            val c = s.last()
            if (c == ')' && s.count { it == '(' } >= s.count { it == ')' }) break
            if (c == ']' && s.count { it == '[' } >= s.count { it == ']' }) break
            s = s.dropLast(1)
        }
        return s
    }
}
