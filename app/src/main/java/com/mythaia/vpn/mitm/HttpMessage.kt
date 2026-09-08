package com.mythaia.vpn.mitm

/**
 * Which half of an exchange a message or a rule belongs to.
 *
 * The `.amrs` format writes it as a number, `0` for request and `1` for
 * response, so the numeric code lives here rather than in the parser.
 */
enum class HttpPhase(val code: Int) {
    REQUEST(0),
    RESPONSE(1);

    companion object {
        fun fromCode(code: Int): HttpPhase? = entries.firstOrNull { it.code == code }
    }
}

/**
 * One header field, kept as it was written.
 *
 * HTTP header names compare case-insensitively (RFC 9110 section 5.1) but the
 * spelling still travels on the wire, which is why the name is stored verbatim
 * and compared with [nameEquals] rather than lowercased on entry.
 */
data class HttpHeader(val name: String, val value: String) {

    /** Whether this header is the one called [other], ignoring ASCII case. */
    fun isNamed(other: String): Boolean = nameEquals(name, other)

    companion object {
        /**
         * ASCII case-insensitive equality, which is all a header name needs
         * (names are pure ASCII tokens) and avoids the locale surprises of
         * `String.lowercase()` on a Turkish device, where `I` folds to a
         * dotless i and `Host` would stop matching `host`.
         */
        fun nameEquals(a: String, b: String): Boolean {
            if (a.length != b.length) return false
            for (i in a.indices) {
                if (foldAscii(a[i]) != foldAscii(b[i])) return false
            }
            return true
        }

        private fun foldAscii(c: Char): Char =
            if (c in 'A'..'Z') (c.code or 0x20).toChar() else c

        /**
         * RFC 9110 section 5.6.2: a field name is one or more `tchar`. Also
         * the shape of a method token, which the same section defines.
         */
        fun isValidName(name: String): Boolean {
            if (name.isEmpty()) return false
            for (c in name) {
                val ok = when (c) {
                    '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' -> true
                    in '0'..'9', in 'A'..'Z', in 'a'..'z' -> true
                    else -> false
                }
                if (!ok) return false
            }
            return true
        }

        /**
         * A value must not carry CR, LF or NUL: those are the request- and
         * response-splitting primitive once the value reaches an HTTP/1 wire.
         */
        fun isValidValue(value: String): Boolean =
            value.none { it == '\r' || it == '\n' || it == '\u0000' }
    }
}

/**
 * A transport-independent HTTP message: the head a rule can read and the
 * body a rule can edit, with nothing about how either was framed.
 *
 * The rewriter is a pure function over this type, which is what makes it
 * testable without a socket. Framing is deliberately absent: the body is the
 * already-decompressed bytes, and whoever unframed it (HTTP/1 chunks, HTTP/2
 * DATA frames, a `Content-Encoding`) is responsible for re-framing the edited
 * body with a fresh `Content-Length`, because only that layer knows what the
 * original framing was.
 *
 * For a response, [url] is the *originating request's* URL after any
 * transparent rewrite. Response heads carry no path, and the rule format tests
 * response-phase rules against the request URL, so the caller sets it here.
 */
class HttpMessage(
    val phase: HttpPhase,
    /** Request method; null on a response. */
    val method: String?,
    /** The whole URL, `https://host/path?query`; null when it could not be determined. */
    val url: String?,
    /** `HTTP/1.1`, `HTTP/2`, and so on; kept so a synthesized response can echo it. */
    val version: String,
    /** Response status; null on a request. */
    val status: Int?,
    /** Every header in wire order, duplicates included. */
    val headers: List<HttpHeader>,
    /** The decompressed body, or empty when there is none. */
    val body: ByteArray
) {

    /** The first header named [name], ignoring case, or null. */
    fun header(name: String): String? =
        headers.firstOrNull { it.isNamed(name) }?.value

    /** Every value of the header named [name], ignoring case, in order. */
    fun headerValues(name: String): List<String> =
        headers.filter { it.isNamed(name) }.map { it.value }

    fun copy(
        phase: HttpPhase = this.phase,
        method: String? = this.method,
        url: String? = this.url,
        version: String = this.version,
        status: Int? = this.status,
        headers: List<HttpHeader> = this.headers,
        body: ByteArray = this.body
    ): HttpMessage = HttpMessage(phase, method, url, version, status, headers, body)

    /**
     * Structural equality including the body bytes, which a data class would
     * compare by reference and so report two identical messages as different.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HttpMessage) return false
        return phase == other.phase &&
            method == other.method &&
            url == other.url &&
            version == other.version &&
            status == other.status &&
            headers == other.headers &&
            body.contentEquals(other.body)
    }

    override fun hashCode(): Int {
        var result = phase.hashCode()
        result = 31 * result + (method?.hashCode() ?: 0)
        result = 31 * result + (url?.hashCode() ?: 0)
        result = 31 * result + version.hashCode()
        result = 31 * result + (status ?: 0)
        result = 31 * result + headers.hashCode()
        result = 31 * result + body.contentHashCode()
        return result
    }

    override fun toString(): String =
        "HttpMessage(phase=$phase, method=$method, url=$url, version=$version, " +
            "status=$status, headers=$headers, body=${body.size} bytes)"

    companion object {
        /** A request with no body, the common case in tests and for GET. */
        fun request(
            method: String,
            url: String?,
            headers: List<HttpHeader> = emptyList(),
            body: ByteArray = ByteArray(0),
            version: String = "HTTP/1.1"
        ): HttpMessage = HttpMessage(HttpPhase.REQUEST, method, url, version, null, headers, body)

        /** A response; [url] is the originating request's URL, see the class note. */
        fun response(
            status: Int,
            url: String?,
            headers: List<HttpHeader> = emptyList(),
            body: ByteArray = ByteArray(0),
            version: String = "HTTP/1.1"
        ): HttpMessage = HttpMessage(HttpPhase.RESPONSE, null, url, version, status, headers, body)
    }
}
