package com.mythaia.vpn.protocol.http3

import com.mythaia.vpn.protocol.quic.QuicVarInt
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * QPACK, checked against RFC 9204's published values rather than against the
 * encoder that produced them.
 *
 * Every expectation below comes from one of three places: the static table in
 * RFC 9204 Appendix A, the prefixed integer algorithm of RFC 9204 §4.1.1 (which
 * is RFC 7541 §5.1, so its Appendix C.1 examples apply verbatim), or the field
 * line diagrams of §4.5. The Huffman strings are RFC 7541 Appendix C.4's own.
 * A codec compared only with itself agrees with its own mistakes.
 */
class QpackEncoderTest {

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ascii(s: String): String =
        s.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) }

    // MARK: - Static table (RFC 9204 Appendix A)

    @Test
    fun `static table entries sit at their published indices`() {
        // A spread across the table, including the pseudo-headers this client
        // encodes by index and the non-contiguous status codes at 63 onwards.
        val published = mapOf(
            0 to (":authority" to ""),
            1 to (":path" to "/"),
            2 to ("age" to "0"),
            4 to ("content-length" to "0"),
            14 to ("set-cookie" to ""),
            15 to (":method" to "CONNECT"),
            16 to (":method" to "DELETE"),
            17 to (":method" to "GET"),
            18 to (":method" to "HEAD"),
            19 to (":method" to "OPTIONS"),
            20 to (":method" to "POST"),
            21 to (":method" to "PUT"),
            22 to (":scheme" to "http"),
            23 to (":scheme" to "https"),
            24 to (":status" to "103"),
            25 to (":status" to "200"),
            26 to (":status" to "304"),
            27 to (":status" to "404"),
            28 to (":status" to "503"),
            29 to ("accept" to "*/*"),
            30 to ("accept" to "application/dns-message"),
            31 to ("accept-encoding" to "gzip, deflate, br"),
            32 to ("accept-ranges" to "bytes"),
            34 to ("access-control-allow-headers" to "content-type"),
            35 to ("access-control-allow-origin" to "*"),
            41 to ("cache-control" to "public, max-age=31536000"),
            44 to ("content-type" to "application/dns-message"),
            52 to ("content-type" to "text/html; charset=utf-8"),
            54 to ("content-type" to "text/plain;charset=utf-8"),
            55 to ("range" to "bytes=0-"),
            58 to ("strict-transport-security" to
                "max-age=31536000; includesubdomains; preload"),
            62 to ("x-xss-protection" to "1; mode=block"),
            63 to (":status" to "100"),
            64 to (":status" to "204"),
            65 to (":status" to "206"),
            66 to (":status" to "302"),
            67 to (":status" to "400"),
            68 to (":status" to "403"),
            69 to (":status" to "421"),
            70 to (":status" to "425"),
            71 to (":status" to "500"),
            73 to ("access-control-allow-credentials" to "FALSE"),
            74 to ("access-control-allow-credentials" to "TRUE"),
            77 to ("access-control-allow-methods" to "get, post, options"),
            85 to ("content-security-policy" to
                "script-src 'none'; object-src 'none'; base-uri 'none'"),
            91 to ("purpose" to "prefetch"),
            95 to ("user-agent" to ""),
            97 to ("x-frame-options" to "deny"),
            98 to ("x-frame-options" to "sameorigin"),
        )

        for ((index, entry) in published) {
            assertEquals("index $index", entry, QpackEncoder.staticTableEntry(index))
        }
    }

    @Test
    fun `the static table stops at 98`() {
        // Appendix A defines 0..98; anything else is a decompression failure
        // rather than an entry to guess at.
        assertEquals(99, QpackEncoder.STATIC_TABLE_SIZE)
        assertNotNull(QpackEncoder.staticTableEntry(98))
        assertNull(QpackEncoder.staticTableEntry(99))
        assertNull(QpackEncoder.staticTableEntry(-1))
        assertNull(QpackEncoder.staticTableEntry(Int.MAX_VALUE))
    }

    // MARK: - Prefixed integers (RFC 9204 section 4.1.1 / RFC 7541 Appendix C.1)

    @Test
    fun `the RFC 7541 Appendix C1 integer examples encode as published`() {
        // C.1.1: 10 in a 5-bit prefix fits, so it is one byte.
        assertArrayEquals(hex("0a"), QpackEncoder.encodePrefixedInteger(10, 5, 0x00))
        // C.1.2: 1337 in a 5-bit prefix fills the prefix and continues.
        assertArrayEquals(hex("1f9a0a"), QpackEncoder.encodePrefixedInteger(1337, 5, 0x00))
        // C.1.3: 42 starting at an octet boundary, i.e. an 8-bit prefix.
        assertArrayEquals(hex("2a"), QpackEncoder.encodePrefixedInteger(42, 8, 0x00))
    }

    @Test
    fun `the RFC 7541 Appendix C1 integer examples decode back`() {
        assertEquals(QpackEncoder.PrefixedInteger(10, 1), QpackEncoder.decodePrefixedInteger(hex("0a"), 0, 5))
        assertEquals(
            QpackEncoder.PrefixedInteger(1337, 3),
            QpackEncoder.decodePrefixedInteger(hex("1f9a0a"), 0, 5)
        )
        assertEquals(QpackEncoder.PrefixedInteger(42, 1), QpackEncoder.decodePrefixedInteger(hex("2a"), 0, 8))
    }

    /**
     * For a prefix of N bits the largest single-byte value is 2^N - 2; 2^N - 1
     * fills the prefix and forces a continuation byte even though the remainder
     * is zero. These expectations are worked out from the RFC's pseudocode, one
     * row per prefix width, rather than taken from the encoder's output.
     */
    @Test
    fun `every prefix width spills into continuation bytes at the same boundary`() {
        // prefixBits to (lastSingleByte, expected) for the four values around
        // and beyond the boundary: mask-1, mask, mask+127, mask+128.
        val cases = listOf(
            Triple(1, 1L, listOf("00", "0100", "017f", "018001")),
            Triple(2, 3L, listOf("02", "0300", "037f", "038001")),
            Triple(3, 7L, listOf("06", "0700", "077f", "078001")),
            Triple(4, 15L, listOf("0e", "0f00", "0f7f", "0f8001")),
            Triple(5, 31L, listOf("1e", "1f00", "1f7f", "1f8001")),
            Triple(6, 63L, listOf("3e", "3f00", "3f7f", "3f8001")),
            Triple(7, 127L, listOf("7e", "7f00", "7f7f", "7f8001")),
            Triple(8, 255L, listOf("fe", "ff00", "ff7f", "ff8001")),
        )

        for ((prefixBits, mask, expected) in cases) {
            val values = listOf(mask - 1, mask, mask + 127, mask + 128)
            for ((value, wanted) in values.zip(expected)) {
                val encoded = QpackEncoder.encodePrefixedInteger(value, prefixBits, 0x00)
                assertArrayEquals("$value in $prefixBits bits", hex(wanted), encoded)
                assertEquals(
                    "$value in $prefixBits bits",
                    QpackEncoder.PrefixedInteger(value, hex(wanted).size),
                    QpackEncoder.decodePrefixedInteger(hex(wanted), 0, prefixBits)
                )
            }
        }
    }

    @Test
    fun `the pattern bits above the prefix are preserved and then ignored`() {
        // An indexed field line is 1 T index(6+); index 6 with T=1 is 0xc6.
        assertArrayEquals(hex("c6"), QpackEncoder.encodePrefixedInteger(6, 6, 0xC0))
        // Index 63 fills the prefix, so the pattern bits ride on a 0xff byte.
        assertArrayEquals(hex("ff00"), QpackEncoder.encodePrefixedInteger(63, 6, 0xC0))
        // Decoding masks the pattern away again.
        assertEquals(
            QpackEncoder.PrefixedInteger(6, 1),
            QpackEncoder.decodePrefixedInteger(hex("c6"), 0, 6)
        )
    }

    @Test
    fun `QPACK prefixed integers are not QUIC varints`() {
        // 15293 is one of RFC 9000 Appendix A.1's worked varint examples. The
        // two encodings share neither length nor bytes, which is exactly why
        // reaching for the wrong one is such an easy interop bug.
        assertArrayEquals(hex("7bbd"), QuicVarInt.encode(15293))
        assertArrayEquals(hex("1f9e77"), QpackEncoder.encodePrefixedInteger(15293, 5, 0x00))

        // And reading one as the other does not merely fail, it lies: the QUIC
        // form read as a 5-bit-prefix integer yields a different number.
        val misread = QpackEncoder.decodePrefixedInteger(hex("7bbd"), 0, 5)
        assertNotNull(misread)
        assertTrue(misread!!.value != 15293L)
    }

    @Test
    fun `an unterminated continuation run is refused`() {
        // Every byte has its high bit set, so the integer never ends.
        assertNull(QpackEncoder.decodePrefixedInteger(hex("1f8080808080"), 0, 5))
        // And an empty or out-of-range offset has nothing to read.
        assertNull(QpackEncoder.decodePrefixedInteger(ByteArray(0), 0, 5))
        assertNull(QpackEncoder.decodePrefixedInteger(hex("1f"), 5, 5))
    }

    @Test
    fun `an integer beyond 2 to the 62 is refused rather than wrapped`() {
        // RFC 9204 section 4.1.1 caps QPACK integers at 2^62 - 1; a longer run
        // of continuation bytes must not fold back into a small positive value.
        assertNull(QpackEncoder.decodePrefixedInteger(hex("ffffffffffffffffffff7f"), 0, 8))

        // The boundary value itself still round-trips.
        val max = QpackEncoder.encodePrefixedInteger(QpackEncoder.MAX_INTEGER, 8, 0x00)
        assertEquals(
            QpackEncoder.PrefixedInteger(QpackEncoder.MAX_INTEGER, max.size),
            QpackEncoder.decodePrefixedInteger(max, 0, 8)
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `encoding a negative integer is a caller error`() {
        QpackEncoder.encodePrefixedInteger(-1, 7, 0x00)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `encoding past the QPACK ceiling is a caller error`() {
        QpackEncoder.encodePrefixedInteger(QpackEncoder.MAX_INTEGER + 1, 7, 0x00)
    }

    // MARK: - Field line representations (RFC 9204 section 4.5)

    @Test
    fun `a CONNECT field section matches the bytes the RFC prescribes`() {
        val block = QpackEncoder.encodeConnectHeaders("example.com:443")

        // 00 00  field section prefix: Required Insert Count 0, Delta Base 0 (4.5.1)
        // cf     indexed field line, T=1, index 15 = :method CONNECT       (4.5.2)
        // 50     literal with name reference, N=0 T=1, index 0 = :authority(4.5.4)
        // 0f     string literal, H=0, length 15                            (4.1.2)
        assertArrayEquals(
            hex("0000 cf 50 0f " + ascii("example.com:443")),
            block
        )
    }

    @Test
    fun `an indexed field line decodes from its published index`() {
        // c0 | 25 = d9 is :status 200.
        assertEquals(
            listOf(":status" to "200"),
            QpackEncoder.decodeHeaders(hex("0000 d9"))
        )
        // Index 63 fills the 6-bit prefix, so it needs a continuation byte.
        assertEquals(
            listOf(":status" to "100"),
            QpackEncoder.decodeHeaders(hex("0000 ff00"))
        )
        // 98 is the last entry: 98 - 63 = 0x23.
        assertEquals(
            listOf("x-frame-options" to "sameorigin"),
            QpackEncoder.decodeHeaders(hex("0000 ff23"))
        )
        // 99 does not exist.
        assertNull(QpackEncoder.decodeHeaders(hex("0000 ff24")))
    }

    @Test
    fun `a literal with name reference resolves the name from the static table`() {
        // 51 = literal with name reference, index 1 = :path; then "/" raw.
        assertEquals(
            listOf(":path" to "/"),
            QpackEncoder.decodeHeaders(hex("0000 51 01 2f"))
        )
        // Index 15 fills the 4-bit prefix: 5f 00. The value overrides CONNECT.
        assertEquals(
            listOf(":method" to "GET"),
            QpackEncoder.decodeHeaders(hex("0000 5f00 03 " + ascii("GET")))
        )
        // Index 95 = user-agent, 95 - 15 = 0x50.
        assertEquals(
            listOf("user-agent" to "Mythaia"),
            QpackEncoder.decodeHeaders(hex("0000 5f50 07 " + ascii("Mythaia")))
        )
        // A name index past the table is a failure, not a skipped field line.
        assertNull(QpackEncoder.decodeHeaders(hex("0000 5f54 01 78")))
    }

    @Test
    fun `a literal field line decodes with and without Huffman`() {
        // Both blocks carry custom-key: custom-value. The Huffman strings are
        // RFC 7541 Appendix C.4.3's own, so this checks the H bit against the
        // spec rather than against whatever this encoder happens to emit.
        //
        // 27 03  literal with literal name, N=0 H=0, name length 10
        // 0c     value string literal, H=0, length 12
        val raw = hex("0000 2703 " + ascii("custom-key") + " 0c " + ascii("custom-value"))
        assertEquals(
            listOf("custom-key" to "custom-value"),
            QpackEncoder.decodeHeaders(raw)
        )

        // 2f 01  literal with literal name, N=0 H=1, name length 8
        // 89     value string literal, H=1, length 9
        val huffman = hex("0000 2f01 25a849e95ba97d7f 89 25a849e95bb8e8b4bf")
        assertEquals(
            listOf("custom-key" to "custom-value"),
            QpackEncoder.decodeHeaders(huffman)
        )

        // The Huffman form really is shorter, which is the only reason the H bit
        // exists; if these were equal one of the two blocks would be wrong.
        assertTrue(huffman.size < raw.size)
    }

    @Test
    fun `a Huffman string that is not a valid code is refused`() {
        // HpackHuffman rejects a lone 0xff (a truncated code that runs into EOS),
        // and that refusal has to reach the caller rather than yield an empty value.
        assertNull(QpackEncoder.decodeHeaders(hex("0000 2703 " + ascii("custom-key") + " 81 ff")))
    }

    @Test
    fun `ill-formed UTF-8 in a value is refused`() {
        // 0xff can never appear in UTF-8. Substituting U+FFFD here would hand the
        // caller a header value that is not what the peer sent.
        assertNull(QpackEncoder.decodeHeaders(hex("0000 2703 " + ascii("custom-key") + " 02 fffe")))
    }

    // MARK: - Dynamic table references

    @Test
    fun `references to the dynamic table are refused`() {
        // We advertise QPACK_MAX_TABLE_CAPACITY = 0, so none of these can be
        // resolved and none may be silently dropped either.
        assertNull(QpackEncoder.decodeHeaders(hex("0000 80")))     // indexed, T=0
        assertNull(QpackEncoder.decodeHeaders(hex("0000 40")))     // name ref, T=0
        assertNull(QpackEncoder.decodeHeaders(hex("0000 10")))     // indexed post-base
        assertNull(QpackEncoder.decodeHeaders(hex("0000 00")))     // name ref post-base
    }

    @Test
    fun `a non-zero Required Insert Count is refused`() {
        // The prefix says the peer inserted entries we never agreed to hold.
        assertNull(QpackEncoder.decodeHeaders(hex("01 00 d9")))
    }

    @Test
    fun `a field section shorter than its prefix is refused`() {
        assertNull(QpackEncoder.decodeHeaders(ByteArray(0)))
        assertNull(QpackEncoder.decodeHeaders(hex("00")))
        // A bare prefix with no field lines is legal and carries nothing.
        assertEquals(emptyList<Pair<String, String>>(), QpackEncoder.decodeHeaders(hex("0000")))
    }

    @Test
    fun `truncated field sections are refused rather than half-decoded`() {
        val complete = QpackEncoder.encodeConnectHeaders(
            authority = "example.com:443",
            extraHeaders = listOf("user-agent" to "Mythaia")
        )
        for (cut in 1 until complete.size) {
            val decoded = QpackEncoder.decodeHeaders(complete.copyOfRange(0, cut))
            if (decoded != null) {
                // A prefix that happens to end on a field line boundary is a
                // shorter but well-formed block; what must never happen is a
                // decode that reads past the end.
                assertTrue("cut=$cut produced $decoded", decoded.size < 3)
            }
        }
    }

    // MARK: - Request encoding

    @Test
    fun `a CONNECT field section round-trips`() {
        val block = QpackEncoder.encodeConnectHeaders("example.com:443")
        assertEquals(
            listOf(":method" to "CONNECT", ":authority" to "example.com:443"),
            QpackEncoder.decodeHeaders(block)
        )
    }

    @Test
    fun `extended CONNECT carries the pseudo-headers RFC 9220 makes mandatory`() {
        val block = QpackEncoder.encodeConnectHeaders(
            authority = "proxy.example:443",
            protocolPseudo = "connect-udp",
            path = "/.well-known/masque/udp/192.0.2.1/443/"
        )
        assertEquals(
            listOf(
                ":method" to "CONNECT",
                ":protocol" to "connect-udp",
                ":scheme" to "https",
                ":path" to "/.well-known/masque/udp/192.0.2.1/443/",
                ":authority" to "proxy.example:443"
            ),
            QpackEncoder.decodeHeaders(block)
        )
    }

    @Test
    fun `extended CONNECT defaults the path when none is given`() {
        val block = QpackEncoder.encodeConnectHeaders(
            authority = "proxy.example:443",
            protocolPseudo = "websocket"
        )
        assertEquals(":path" to "/", QpackEncoder.decodeHeaders(block)!![3])
    }

    @Test
    fun `POST and GET use their static table entries`() {
        // 0000 then c0|20 = d4 for :method POST, then c0|23 = d7 for :scheme https.
        val post = QpackEncoder.encodePostHeaders("example.com", "/upload")
        assertArrayEquals(hex("0000 d4 d7"), post.copyOfRange(0, 4))

        val get = QpackEncoder.encodeRequestHeaders("GET", "example.com", "/")
        assertArrayEquals(hex("0000 d1 d7"), get.copyOfRange(0, 4))

        assertEquals(
            listOf(
                ":method" to "POST",
                ":scheme" to "https",
                ":authority" to "example.com",
                ":path" to "/upload"
            ),
            QpackEncoder.decodeHeaders(post)
        )
    }

    @Test
    fun `a method outside the static table is spelled out`() {
        val block = QpackEncoder.encodeRequestHeaders("PATCH", "example.com", "/thing")
        assertEquals(
            listOf(
                ":method" to "PATCH",
                ":scheme" to "https",
                ":authority" to "example.com",
                ":path" to "/thing"
            ),
            QpackEncoder.decodeHeaders(block)
        )
        // The method is a literal field line, not an index: 001 N H len(3+), and
        // ":method" is 7 bytes, which is exactly where the 3-bit prefix fills.
        assertArrayEquals(hex("0000 27 00 " + ascii(":method")), block.copyOfRange(0, 11))
    }

    @Test
    fun `field names are lowercased because HTTP 3 forbids uppercase`() {
        val block = QpackEncoder.encodeRequestHeaders(
            "GET", "example.com", "/",
            extraHeaders = listOf("X-Custom-Name" to "MixedCaseValue")
        )
        val decoded = QpackEncoder.decodeHeaders(block)!!
        // The name is folded; the value is not, since only names are restricted.
        assertEquals("x-custom-name" to "MixedCaseValue", decoded.last())
    }

    @Test
    fun `values crossing the string length boundary survive`() {
        // A string literal's length uses a 7-bit prefix, so 127 bytes is where a
        // continuation byte appears and 16383 is where a second one does.
        for (length in listOf(0, 1, 126, 127, 128, 254, 255, 16382, 16383, 16384)) {
            val value = "v".repeat(length)
            val block = QpackEncoder.encodeRequestHeaders(
                "GET", "h", "/", extraHeaders = listOf("padding" to value)
            )
            val decoded = QpackEncoder.decodeHeaders(block)
            assertNotNull("length $length", decoded)
            assertEquals("length $length", value, decoded!!.last().second)
        }
    }

    @Test
    fun `a long field name crosses its own 3-bit boundary`() {
        // Names use a 3-bit length prefix, so the continuation starts at 7.
        for (length in listOf(1, 6, 7, 8, 133, 134, 135)) {
            val name = "x".repeat(length)
            val block = QpackEncoder.encodeRequestHeaders(
                "GET", "h", "/", extraHeaders = listOf(name to "v")
            )
            val decoded = QpackEncoder.decodeHeaders(block)
            assertNotNull("length $length", decoded)
            assertEquals("length $length", name to "v", decoded!!.last())
        }
    }

    @Test
    fun `non-ASCII values round-trip as UTF-8`() {
        val value = "значение值"
        val block = QpackEncoder.encodeRequestHeaders(
            "GET", "h", "/", extraHeaders = listOf("x-name" to value)
        )
        assertEquals(value, QpackEncoder.decodeHeaders(block)!!.last().second)
    }

    @Test
    fun `every field section starts with the two-byte prefix`() {
        val blocks = listOf(
            QpackEncoder.encodeConnectHeaders("h"),
            QpackEncoder.encodeConnectHeaders("h", protocolPseudo = "connect-udp"),
            QpackEncoder.encodePostHeaders("h", "/"),
            QpackEncoder.encodeRequestHeaders("HEAD", "h", "/")
        )
        for (block in blocks) {
            assertArrayEquals(hex("0000"), block.copyOfRange(0, 2))
        }
    }
}
