package com.mythaia.data.network

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
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
}
