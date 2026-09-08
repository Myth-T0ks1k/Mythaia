package com.mythaia.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The head a rewrite rule reads and the body it edits. Every assertion here is
 * a place where being slightly wrong changes which header a rule matches, or
 * lets a rewritten value smuggle a second request onto the wire, or reports two
 * identical messages as different — so each is checked against the RFC that
 * defines the shape, not against what the code happens to do.
 */
class HttpMessageTest {

    // --- header name folding (RFC 9110 §5.1: names are ASCII, case-insensitive) ---

    @Test
    fun `a header name matches across ASCII case`() {
        assertTrue(HttpHeader.nameEquals("Host", "host"))
        assertTrue(HttpHeader.nameEquals("HOST", "host"))
        assertTrue(HttpHeader.nameEquals("Content-Length", "content-length"))
        assertTrue(HttpHeader("Host", "example.com").isNamed("HOST"))
    }

    @Test
    fun `names of different length are never equal`() {
        assertFalse(HttpHeader.nameEquals("Host", "Hosts"))
        assertFalse(HttpHeader.nameEquals("Host", "Ho"))
    }

    @Test
    fun `folding is confined to A through Z and does not spill into adjacent bytes`() {
        // '[' (0x5B) and '{' (0x7B) differ only by the 0x20 bit that separates
        // an upper- from a lower-case letter. A fold that blindly OR'd 0x20
        // would call these equal; a correct ASCII fold leaves non-letters
        // alone. Guarding the boundary is the whole point of not lowercasing.
        assertFalse(HttpHeader.nameEquals("[", "{"))
        assertFalse(HttpHeader.nameEquals("@", "`"))
        // Digits and separators still compare literally.
        assertTrue(HttpHeader.nameEquals("X-9_a", "x-9_a"))
    }

    // --- valid names (RFC 9110 §5.6.2: field-name = token = 1*tchar) ---

    @Test
    fun `a token of tchar is a valid name and the empty string is not`() {
        assertTrue(HttpHeader.isValidName("Content-Type"))
        assertTrue(HttpHeader.isValidName("GET"))
        assertTrue(HttpHeader.isValidName("X-Custom.Header_9"))
        assertTrue(HttpHeader.isValidName("!#\$%&'*+-.^_`|~"))
        assertFalse(HttpHeader.isValidName(""))
    }

    @Test
    fun `characters outside the tchar set make a name invalid`() {
        // A space, a colon, and control bytes are all delimiters or forbidden
        // in a field-name; letting any of them through would accept a header
        // line an HTTP/1 parser would split differently.
        assertFalse(HttpHeader.isValidName("Bad Header"))
        assertFalse(HttpHeader.isValidName("Name:"))
        assertFalse(HttpHeader.isValidName("a\tb"))
        assertFalse(HttpHeader.isValidName("na\u0000me"))
        assertFalse(HttpHeader.isValidName("naïve"))
    }

    // --- valid values (CR/LF are the response-splitting primitive) ---

    @Test
    fun `a value carrying CR or LF is invalid`() {
        // CR and LF are exactly what an attacker needs to end one header line
        // and begin another once the value reaches an HTTP/1 wire, so a value
        // that contains either must never be emitted verbatim.
        assertFalse(HttpHeader.isValidValue("text/html\r\nSet-Cookie: x=1"))
        assertFalse(HttpHeader.isValidValue("a\rb"))
        assertFalse(HttpHeader.isValidValue("a\nb"))
    }

    @Test
    fun `an ordinary visible value is valid`() {
        assertTrue(HttpHeader.isValidValue("text/html;charset=utf-8"))
        assertTrue(HttpHeader.isValidValue("gzip"))
        assertTrue(HttpHeader.isValidValue(""))
    }

    // --- phase codes (the .amrs format writes 0 for request, 1 for response) ---

    @Test
    fun `phase codes round-trip and an unknown code is null`() {
        assertEquals(0, HttpPhase.REQUEST.code)
        assertEquals(1, HttpPhase.RESPONSE.code)
        assertEquals(HttpPhase.REQUEST, HttpPhase.fromCode(0))
        assertEquals(HttpPhase.RESPONSE, HttpPhase.fromCode(1))
        assertNull(HttpPhase.fromCode(2))
        assertNull(HttpPhase.fromCode(-1))
    }

    // --- factories and header lookup ---

    @Test
    fun `the request factory fills the request half and defaults the version`() {
        val m = HttpMessage.request("GET", "https://example.com/", listOf(HttpHeader("Host", "example.com")))
        assertEquals(HttpPhase.REQUEST, m.phase)
        assertEquals("GET", m.method)
        assertEquals("https://example.com/", m.url)
        assertEquals("HTTP/1.1", m.version)
        assertNull(m.status)
        assertEquals(0, m.body.size)
    }

    @Test
    fun `the response factory fills the response half`() {
        val m = HttpMessage.response(200, "https://example.com/", version = "HTTP/2")
        assertEquals(HttpPhase.RESPONSE, m.phase)
        assertNull(m.method)
        assertEquals(200, m.status)
        assertEquals("HTTP/2", m.version)
    }

    @Test
    fun `header lookup ignores case and returns the first, headerValues returns every one in order`() {
        val m = HttpMessage.request(
            "GET", "https://example.com/",
            listOf(
                HttpHeader("Set-Cookie", "a=1"),
                HttpHeader("set-cookie", "b=2"),
                HttpHeader("Content-Type", "text/html")
            )
        )
        assertEquals("a=1", m.header("SET-COOKIE"))
        assertEquals("text/html", m.header("content-type"))
        assertNull(m.header("Authorization"))
        assertEquals(listOf("a=1", "b=2"), m.headerValues("Set-Cookie"))
    }

    // --- structural equality including body bytes ---

    @Test
    fun `equals compares body content, not the array reference`() {
        // The whole reason equals is hand-written: a data class would compare
        // the body arrays by identity and call two byte-identical messages
        // different, which every diff-based test would then get wrong.
        val a = HttpMessage.request("GET", "https://h/", listOf(HttpHeader("Host", "h")), byteArrayOf(1, 2, 3))
        val b = HttpMessage.request("GET", "https://h/", listOf(HttpHeader("Host", "h")), byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `a one-byte body difference makes messages unequal`() {
        val a = HttpMessage.request("POST", "https://h/", body = byteArrayOf(1, 2, 3))
        val b = HttpMessage.request("POST", "https://h/", body = byteArrayOf(1, 2, 4))
        assertNotEquals(a, b)
    }

    @Test
    fun `equality also distinguishes the head fields`() {
        val base = HttpMessage.request("GET", "https://h/", listOf(HttpHeader("A", "1")), byteArrayOf(9))
        assertNotEquals(base, base.copy(method = "POST"))
        assertNotEquals(base, base.copy(url = "https://other/"))
        assertNotEquals(base, base.copy(version = "HTTP/2"))
        assertNotEquals(base, base.copy(headers = listOf(HttpHeader("A", "2"))))
        assertNotEquals(base, base.copy(phase = HttpPhase.RESPONSE, status = 200))
    }

    @Test
    fun `copy keeps the body and every field it is not told to change`() {
        val original = HttpMessage.request("GET", "https://h/", listOf(HttpHeader("A", "1")), byteArrayOf(7, 7))
        val edited = original.copy(body = byteArrayOf(8))
        assertEquals("GET", edited.method)
        assertEquals("https://h/", edited.url)
        assertEquals(original.headers, edited.headers)
        assertArrayEqualsBytes(byteArrayOf(8), edited.body)
        // The original is untouched.
        assertArrayEqualsBytes(byteArrayOf(7, 7), original.body)
    }

    private fun assertArrayEqualsBytes(expected: ByteArray, actual: ByteArray) =
        org.junit.Assert.assertArrayEquals(expected, actual)
}
