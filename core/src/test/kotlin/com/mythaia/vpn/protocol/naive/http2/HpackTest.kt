package com.mythaia.vpn.protocol.naive.http2

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * HPACK, checked against RFC 7541's own appendix examples.
 *
 * The Huffman table and the integer encoding are the two places a from-scratch
 * HPACK usually goes wrong, and both have published vectors — so this is
 * verified against the RFC rather than against the encoder that produced it.
 */
class HpackTest {

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // MARK: - Huffman (RFC 7541 Appendix C.4)

    @Test
    fun `Huffman decodes the RFC 7541 examples`() {
        // C.4.1: "www.example.com"
        assertEquals(
            "www.example.com",
            String(HpackHuffman.decode(hex("f1e3c2e5f23a6ba0ab90f4ff"))!!, Charsets.UTF_8)
        )
        // C.4.2: "no-cache"
        assertEquals(
            "no-cache",
            String(HpackHuffman.decode(hex("a8eb10649cbf"))!!, Charsets.UTF_8)
        )
        // C.4.3: "custom-key" and "custom-value"
        assertEquals(
            "custom-key",
            String(HpackHuffman.decode(hex("25a849e95ba97d7f"))!!, Charsets.UTF_8)
        )
        assertEquals(
            "custom-value",
            String(HpackHuffman.decode(hex("25a849e95bb8e8b4bf"))!!, Charsets.UTF_8)
        )
    }

    @Test
    fun `Huffman decodes the response examples too`() {
        // C.6.1: "302", "private", "Mon, 21 Oct 2013 20:13:21 GMT"
        assertEquals("302", String(HpackHuffman.decode(hex("6402"))!!, Charsets.UTF_8))
        assertEquals("private", String(HpackHuffman.decode(hex("aec3771a4b"))!!, Charsets.UTF_8))
        assertEquals(
            "Mon, 21 Oct 2013 20:13:21 GMT",
            String(
                HpackHuffman.decode(hex("d07abe941054d444a8200595040b8166e082a62d1bff"))!!,
                Charsets.UTF_8
            )
        )
    }

    @Test
    fun `malformed Huffman input is refused rather than half-decoded`() {
        // A truncated code, and padding that is not all ones, are both errors
        // the RFC says to treat as a decoding failure.
        assertNull(HpackHuffman.decode(hex("ff")))
        // An over-long run of ones is the EOS symbol, which must not appear.
        assertNull(HpackHuffman.decode(hex("ffffffff")))
    }

    // MARK: - Header decoding (RFC 7541 Appendix C.3)

    @Test
    fun `decodes the RFC 7541 request sequence with a dynamic table`() {
        val decoder = HpackDecoder()

        // C.3.1 — first request.
        val first = decoder.decode(hex("828684 41 0f 7777772e6578616d706c652e636f6d"))
        assertNotNull(first)
        assertEquals(
            listOf(
                ":method" to "GET",
                ":scheme" to "http",
                ":path" to "/",
                ":authority" to "www.example.com"
            ),
            first
        )

        // C.3.2 — the second request refers back into the dynamic table the
        // first one populated. Decoding it correctly is the whole point of
        // keeping a decoder across blocks.
        val second = decoder.decode(hex("828684be 58 08 6e6f2d6361636865"))
        assertNotNull(second)
        assertEquals(
            listOf(
                ":method" to "GET",
                ":scheme" to "http",
                ":path" to "/",
                ":authority" to "www.example.com",
                "cache-control" to "no-cache"
            ),
            second
        )
    }

    @Test
    fun `decodes Huffman-coded literals`() {
        // C.4.1 — the same request as C.3.1 with the value Huffman-coded.
        val decoder = HpackDecoder()
        val headers = decoder.decode(hex("828684 41 8c f1e3c2e5f23a6ba0ab90f4ff"))
        assertNotNull(headers)
        assertEquals(":authority" to "www.example.com", headers!!.last())
    }

    @Test
    fun `a decoder without state does not resolve a dynamic reference`() {
        // 0xbe indexes the dynamic table, which is empty here.
        assertNull(HpackDecoder().decode(hex("be")))
    }

    @Test
    fun `truncated header blocks are refused`() {
        // Each of these stops part-way through a field; none may produce a
        // partial header list, because the caller would act on it.
        val complete = hex("828684 41 0f 7777772e6578616d706c652e636f6d")
        for (cut in 1 until complete.size) {
            val partial = complete.copyOfRange(0, cut)
            val result = HpackDecoder().decode(partial)
            if (result != null) {
                // A prefix that happens to be a complete, shorter block is fine;
                // what must never happen is a decode that reads past the end.
                assertTrue("cut=$cut produced $result", result.size <= 4)
            }
        }
    }

    @Test
    fun `an index of zero is not a header`() {
        // RFC 7541 §6.1: index 0 is not usable and must be treated as an error.
        assertNull(HpackDecoder().decode(byteArrayOf(0x80.toByte())))
    }

    // MARK: - CONNECT request encoding

    @Test
    fun `a CONNECT request names the method and authority from the static table`() {
        val block = HpackEncoder.encodeConnectRequest("example.com:443", emptyList())

        val decoded = HpackDecoder().decode(block)
        assertNotNull(decoded)
        assertEquals(
            listOf(":method" to "CONNECT", ":authority" to "example.com:443"),
            decoded
        )
    }

    @Test
    fun `extra headers survive the round trip`() {
        val extras = listOf(
            "user-agent" to "Mozilla/5.0",
            "padding" to "x".repeat(200),
            "x-custom-name" to "value"
        )
        val block = HpackEncoder.encodeConnectRequest("example.com:443", extras)

        val decoded = HpackDecoder().decode(block)
        assertNotNull(decoded)
        assertEquals(
            listOf(":method" to "CONNECT", ":authority" to "example.com:443") + extras,
            decoded
        )
    }

    @Test
    fun `a long value crosses the integer continuation boundary`() {
        // A string of 127 bytes or more needs HPACK's multi-byte integer form,
        // which is the encoder's easiest thing to get wrong.
        for (length in listOf(126, 127, 128, 255, 256, 16383, 16384)) {
            val value = "v".repeat(length)
            val block = HpackEncoder.encodeConnectRequest("h", listOf("padding" to value))
            val decoded = HpackDecoder().decode(block)
            assertNotNull("length $length", decoded)
            assertEquals("length $length", value, decoded!!.last().second)
        }
    }

    @Test
    fun `a non-ASCII header value round-trips as UTF-8`() {
        val value = "значение値"
        val block = HpackEncoder.encodeConnectRequest("h", listOf("x-name" to value))
        assertEquals(value, HpackDecoder().decode(block)!!.last().second)
    }

    @Test
    fun `the decoder can be reset between connections`() {
        val decoder = HpackDecoder()
        decoder.decode(hex("828684 41 0f 7777772e6578616d706c652e636f6d"))
        decoder.reset()
        // The dynamic entry the first block added is gone.
        assertNull(decoder.decode(hex("be")))
    }

    // MARK: - Dynamic table size (RFC 7541 §4)

    @Test
    fun `the dynamic table evicts its oldest entries at its size limit`() {
        // Each entry is 5 + 3 + 32 = 40 bytes: a 100-byte table holds two.
        val decoder = HpackDecoder(maxTableSize = 100)
        decoder.decode(hex("40 05 782d666f6f 03 626172")) // x-foo: bar
        decoder.decode(hex("40 05 782d626172 03 626172")) // x-bar: bar
        decoder.decode(hex("40 05 782d62617a 03 626172")) // x-baz: bar, x-foo evicted

        assertEquals(listOf("x-baz" to "bar", "x-bar" to "bar"), decoder.decode(hex("be bf")))
        // Index 64 was x-foo; the encoder knows it is gone, and so must we.
        assertNull(decoder.decode(hex("c0")))
    }

    @Test
    fun `an entry larger than the table empties it and is not added`() {
        val decoder = HpackDecoder(maxTableSize = 50)
        decoder.decode(hex("40 05 782d666f6f 03 626172")) // 40 bytes
        // 5 + 20 + 32 = 57 bytes: §4.4.
        decoder.decode(hex("40 05 782d626172 14") + ByteArray(20) { 0x61 })
        assertNull(decoder.decode(hex("be")))
    }

    @Test
    fun `a dynamic table size update shrinks the table`() {
        val decoder = HpackDecoder()
        decoder.decode(hex("40 05 782d666f6f 03 626172"))
        // Size update to 0: everything goes.
        assertEquals(emptyList<Pair<String, String>>(), decoder.decode(hex("20")))
        assertNull(decoder.decode(hex("be")))
        // Back up to the maximum, and entries are kept again.
        assertEquals(listOf("x-foo" to "bar"), decoder.decode(hex("3f e1 1f 40 05 782d666f6f 03 626172")))
        assertEquals(listOf("x-foo" to "bar"), decoder.decode(hex("be")))
    }

    @Test
    fun `a size update past what we advertised is a decoding error`() {
        // 5000 with a 5-bit prefix: 0x3f, then 4969 as e9 26. We advertised 4096.
        assertNull(HpackDecoder(maxTableSize = 4096).decode(hex("3f e9 26")))
        // Within a larger advertised size it is fine.
        assertEquals(emptyList<Pair<String, String>>(), HpackDecoder(maxTableSize = 65536).decode(hex("3f e9 26")))
    }
}
