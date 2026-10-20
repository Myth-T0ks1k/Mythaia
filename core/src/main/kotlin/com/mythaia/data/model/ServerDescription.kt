package com.mythaia.data.model

import com.mythaia.vpn.util.decodeBase64Lenient

/**
 * Happ's `serverDescription`: `#My server?serverDescription=SGFwcCB0aGUgYmVzdA==`
 * in a share link puts "Happ the best" under the server's name. The value is
 * base64 and at most 30 characters once decoded.
 */
internal object ServerDescription {

    private val MARKERS = listOf("?serverDescription=", "%3FserverDescription%3D")
    const val MAX_LENGTH = 30

    /** [url] without the description in its fragment, and the description. */
    fun split(url: String): Pair<String, String?> {
        val hash = url.lastIndexOf('#')
        if (hash < 0) return url to null
        val fragment = url.substring(hash + 1)
        val (name, description, found) = cut(fragment)
        if (!found) return url to null
        return url.substring(0, hash + 1) + name to description
    }

    /** A name that still carries the marker, as a VMess `ps` can: the name, and the description. */
    fun splitName(name: String): Pair<String, String?> {
        val (rest, description, found) = cut(name)
        return if (found) rest.trim().ifEmpty { name } to description else name to null
    }

    private fun cut(text: String): Triple<String, String?, Boolean> {
        for (marker in MARKERS) {
            val at = text.indexOf(marker, ignoreCase = true)
            if (at < 0) continue
            val value = text.substring(at + marker.length).substringBefore('&')
            return Triple(text.substring(0, at), decode(value), true)
        }
        return Triple(text, null, false)
    }

    private fun decode(value: String): String? {
        val raw = percentDecode(value).trim()
        if (raw.isEmpty()) return null
        for (urlSafe in booleanArrayOf(false, true)) {
            val text = runCatching { String(decodeBase64Lenient(raw, urlSafe), Charsets.UTF_8) }.getOrNull() ?: continue
            if (text.contains('�')) continue
            val clean = text.filterNot { it.isISOControl() }.trim()
            if (clean.isNotEmpty()) return clean.take(MAX_LENGTH)
        }
        return null
    }
}
