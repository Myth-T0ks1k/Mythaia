package com.mythaia.data.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPOutputStream

/** The transport-level handling in front of the subscription parsers. */
class SubscriptionFetcherTest {

    private fun gzip(bytes: ByteArray): ByteArray =
        ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(bytes) } }.toByteArray()

    @Test
    fun `a gzipped body is decoded when the header says so`() {
        val plain = "vless://x@y:1#n\n".toByteArray()
        assertArrayEquals(plain, SubscriptionFetcher.gunzipIfNeeded(gzip(plain), "gzip"))
        assertArrayEquals(plain, SubscriptionFetcher.gunzipIfNeeded(gzip(plain), " X-Gzip "))
        // No header, or another encoding: the bytes are what they are.
        assertSame(plain, SubscriptionFetcher.gunzipIfNeeded(plain, null))
        assertSame(plain, SubscriptionFetcher.gunzipIfNeeded(plain, "identity"))
    }

    @Test
    fun `a body that is not gzip under a gzip header is a fetch error`() {
        try {
            SubscriptionFetcher.gunzipIfNeeded("not gzip".toByteArray(), "gzip")
            fail("expected a FetchError")
        } catch (_: SubscriptionFetcher.FetchError) {
            // expected
        }
    }

    @Test
    fun `only http and https subscription URLs are fetched`() {
        for (url in listOf("file:///etc/hosts", "ftp://example.com/sub", "not a url")) {
            try {
                runBlocking { SubscriptionFetcher.fetch(url) }
                fail("expected InvalidUrl for $url")
            } catch (_: SubscriptionFetcher.FetchError.InvalidUrl) {
                // expected
            }
        }
    }

    @Test
    fun `a body is read whole up to the cap and refused past it`() {
        val cap = 16 * 1024 * 1024
        // Not a multiple of the read chunk, so the last one is partial.
        val body = ByteArray(cap) { (it % 251).toByte() }
        assertArrayEquals(body, SubscriptionFetcher.gunzipIfNeeded(gzip(body), "gzip"))
        val small = "vless://x@y:1#n\n".toByteArray()
        assertArrayEquals(small, SubscriptionFetcher.gunzipIfNeeded(gzip(small), "gzip"))
        assertArrayEquals(ByteArray(0), SubscriptionFetcher.gunzipIfNeeded(gzip(ByteArray(0)), "gzip"))
        try {
            SubscriptionFetcher.gunzipIfNeeded(gzip(ByteArray(cap + 1)), "gzip")
            fail("expected a FetchError")
        } catch (_: SubscriptionFetcher.FetchError) {
            // expected
        }
    }

    @Test
    fun `a base64 list broken into lines decodes in either alphabet`() {
        val links = (0 until 300).map { "trojan://p%3F%3E$it@h$it.example.com:443?sni=s$it.example.com#node-$it" }
        val raw = links.joinToString("\r\n").toByteArray()
        for (encoded in listOf(
            Base64.getMimeEncoder().encodeToString(raw),
            Base64.getUrlEncoder().withoutPadding().encodeToString(raw).chunked(76).joinToString("\n")
        )) {
            assertEquals(links.joinToString("\r\n"), SubscriptionFetcher.decodeBody(encoded.toByteArray()))
            assertEquals(links.size, SubscriptionFetcher.parse(encoded.toByteArray()).configurations.size)
        }
        // Text that is not base64, Cyrillic included, comes back as it was.
        val prose = "Подписка истекла\n"
        assertEquals(prose, SubscriptionFetcher.decodeBody(prose.toByteArray()))
    }
}
