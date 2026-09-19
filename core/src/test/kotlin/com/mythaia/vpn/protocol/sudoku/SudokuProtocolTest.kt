package com.mythaia.vpn.protocol.sudoku

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The expectations here come from the reference implementation's own structure
 * and from outside sources — Go's documented generator output, RFC 8032's
 * Ed25519 vectors, and the layout tables' own bit rules — rather than from this
 * encoder. A codec compared only against itself agrees with its own mistakes,
 * and the wire format is the whole contract with the server.
 *
 * The byte-level encoder vectors were produced by a second, independent
 * transcription of the reference in another language and are pasted in as
 * literals; if this port drifts from the Swift they stop matching.
 */
class SudokuProtocolTest {

    private val key = "sudoku-test-key"

    // Building a codebook shuffles 288 grids and scans 466,000 clue sets, so the
    // tables are shared across the tests rather than rebuilt per method.
    private val entropyTables by lazy { SudokuTablePair(key, SudokuAsciiMode.PREFER_ENTROPY) }
    private val asciiTables by lazy { SudokuTablePair(key, SudokuAsciiMode.PREFER_ASCII) }
    private val customTables by lazy {
        SudokuTablePair(key, SudokuAsciiMode.PREFER_ENTROPY, CUSTOM_PATTERN, CUSTOM_PATTERN)
    }

    private fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) out.append("%02x".format(b.toInt() and 0xFF))
        return out.toString()
    }

    private fun fromHex(text: String) = ByteArray(text.length / 2) {
        ((Character.digit(text[it * 2], 16) shl 4) or Character.digit(text[it * 2 + 1], 16)).toByte()
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    // ---------------------------------------------------------------- constants

    @Test
    fun `the record layer's numbers are the ones the reference names`() {
        assertEquals(2, SudokuProtocol.RECORD_LENGTH_PREFIX_SIZE)
        assertEquals(12, SudokuProtocol.RECORD_HEADER_SIZE)
        assertEquals(65535, SudokuProtocol.RECORD_MAX_BODY_SIZE)
        // 65535 - 12 header - 16 tag, which is what the reference chunks at.
        assertEquals(65507, SudokuProtocol.RECORD_MAX_PLAINTEXT_SIZE)
        assertEquals(33554432L, SudokuProtocol.RECORD_EPOCH_REKEY_BYTES)
        assertEquals(8L, SudokuProtocol.RECORD_MAX_EPOCH_JUMP)
        assertEquals("sudoku-record:", SudokuProtocol.RECORD_KEY_LABEL)

        assertEquals("sudoku-psk-c2s", SudokuProtocol.LABEL_PSK_C2S)
        assertEquals("sudoku-psk-s2c", SudokuProtocol.LABEL_PSK_S2C)
        assertEquals("sudoku-session-c2s", SudokuProtocol.LABEL_SESSION_C2S)
        assertEquals("sudoku-session-s2c", SudokuProtocol.LABEL_SESSION_S2C)
        assertEquals(32, SudokuProtocol.BASE_KEY_SIZE)
    }

    @Test
    fun `the handshake's numbers are the ones the reference names`() {
        assertArrayEquals(bytes(0x6B, 0x69, 0x70), SudokuProtocol.KIP_MAGIC)
        assertEquals("kip", String(SudokuProtocol.KIP_MAGIC, Charsets.US_ASCII))
        assertEquals(6, SudokuProtocol.KIP_HEADER_SIZE)

        assertEquals(0x01.toByte(), SudokuProtocol.KIP_CLIENT_HELLO)
        assertEquals(0x02.toByte(), SudokuProtocol.KIP_SERVER_HELLO)
        assertEquals(0x10.toByte(), SudokuProtocol.KIP_CONNECT_TCP)
        assertEquals(0x11.toByte(), SudokuProtocol.KIP_OPEN_MUX)
        assertEquals(0x12.toByte(), SudokuProtocol.KIP_OPEN_UDP_OVER_TCP)

        assertEquals(0x1F, SudokuProtocol.KIP_FEATURE_FLAGS)
        assertEquals(16, SudokuProtocol.KIP_NONCE_SIZE)
        assertEquals(32, SudokuProtocol.KIP_PUBLIC_KEY_SIZE)
        assertEquals(68, SudokuProtocol.KIP_CLIENT_HELLO_SIZE)
        assertEquals(72, SudokuProtocol.KIP_CLIENT_HELLO_WITH_HINT_SIZE)
        assertEquals(52, SudokuProtocol.KIP_SERVER_HELLO_SIZE)
    }

    @Test
    fun `the framing and camouflage numbers are the ones the reference names`() {
        assertEquals(0x01.toByte(), SudokuProtocol.ADDRESS_IPV4)
        assertEquals(0x03.toByte(), SudokuProtocol.ADDRESS_DOMAIN)
        assertEquals(0x04.toByte(), SudokuProtocol.ADDRESS_IPV6)
        assertEquals(255, SudokuProtocol.MAX_DOMAIN_LENGTH)

        assertEquals(4, SudokuProtocol.UOT_HEADER_SIZE)
        assertEquals(65536, SudokuProtocol.UOT_MAX_ADDRESS_SIZE)
        assertEquals(65536, SudokuProtocol.UOT_MAX_PAYLOAD_SIZE)

        assertEquals(9, SudokuProtocol.MUX_HEADER_SIZE)
        assertEquals(0x01.toByte(), SudokuProtocol.MUX_OPEN)
        assertEquals(0x02.toByte(), SudokuProtocol.MUX_DATA)
        assertEquals(0x03.toByte(), SudokuProtocol.MUX_CLOSE)
        assertEquals(0x04.toByte(), SudokuProtocol.MUX_RESET)
        assertEquals(262144, SudokuProtocol.MUX_MAX_PAYLOAD_SIZE)
        assertEquals(15L, SudokuProtocol.MUX_KEEPALIVE_INTERVAL_SECONDS)

        assertEquals("sudoku-httpmask-auth-v1:", SudokuProtocol.HTTP_MASK_AUTH_PREFIX)
        assertEquals("x-sudoku-stream-eof", SudokuProtocol.HTTP_MASK_STREAM_EOF_HEADER)
        assertEquals(16, SudokuProtocol.HTTP_MASK_AUTH_TAG_SIZE)

        assertEquals("ascii", SudokuProtocol.LAYOUT_ASCII)
        assertEquals("entropy", SudokuProtocol.LAYOUT_ENTROPY)
        assertEquals(8, SudokuProtocol.CUSTOM_PATTERN_LENGTH)
        assertEquals(4294967296L, SudokuProtocol.PROBABILITY_ONE)
        assertEquals(131072, SudokuProtocol.OBFS_READ_CHUNK_SIZE)
        assertEquals(64, SudokuProtocol.OBFS_MIN_DECODE_READ_SIZE)
        assertEquals("sudoku-table-hint", SudokuTablePair.HINT_LABEL)
    }

    // ------------------------------------------------------------- read sizing

    @Test
    fun `a sized wire read allows for the obfuscation's expansion`() {
        // Nothing wanted, or a chunk too small to size against: read a full chunk.
        assertEquals(1024, SudokuProtocol.wireReadSize(0, pureDownlink = true, maxRaw = 1024))
        assertEquals(64, SudokuProtocol.wireReadSize(10, pureDownlink = true, maxRaw = 64))

        // Five wire bytes per decoded byte pure, two packed, plus the floor.
        assertEquals(114, SudokuProtocol.wireReadSize(10, pureDownlink = true, maxRaw = 1024))
        assertEquals(84, SudokuProtocol.wireReadSize(10, pureDownlink = false, maxRaw = 1024))

        // Past the point where the estimate would exceed the chunk, take the chunk.
        assertEquals(1024, SudokuProtocol.wireReadSize(500, pureDownlink = true, maxRaw = 1024))
        assertEquals(
            SudokuProtocol.OBFS_READ_CHUNK_SIZE,
            SudokuProtocol.wireReadSize(1 shl 20, pureDownlink = true)
        )
    }

    // --------------------------------------------------------- the generators

    @Test
    fun `the Go source reproduces Go's own documented output`() {
        // math/rand's source seeded with 1 is the most widely quoted sequence
        // there is; Int63 masks off the sign bit of the raw draw.
        val source = SudokuGoSource(1)
        assertEquals(5577006791947779410L, source.nextUInt64() and Long.MAX_VALUE)
        assertEquals(8674665223082153551L, source.nextUInt64() and Long.MAX_VALUE)
        assertEquals(6129484611666145821L, source.nextUInt64() and Long.MAX_VALUE)
    }

    @Test
    fun `the Go source's bounded draws stay in range and are reproducible`() {
        val first = SudokuGoSource(1)
        assertEquals(174, first.int31n(288))

        val second = SudokuGoSource(1)
        val drawn = IntArray(6) { second.int31n(288) }
        assertArrayEquals(intArrayOf(174, 270, 191, 126, 122, 197), drawn)

        val bounded = SudokuGoSource(99)
        repeat(2000) {
            val value = bounded.int31n(288)
            assertTrue("out of range: $value", value in 0 until 288)
        }
    }

    @Test
    fun `xorshift64 star hands out the high word first and caches the low one`() {
        assertEquals(5180492295206395165L, SudokuXorshift64Star(1).nextUInt64())

        val words = SudokuXorshift64Star(1)
        val high = words.nextUInt32()
        val low = words.nextUInt32()
        assertEquals(5180492295206395165L ushr 32, high)
        assertEquals(5180492295206395165L and 0xFFFFFFFFL, low)

        // A full draw discards the cached half rather than returning it.
        val mixed = SudokuXorshift64Star(1)
        mixed.nextUInt32()
        assertEquals(-6066446928794000099L, mixed.nextUInt64())

        // Seed zero is replaced, because a zero state never leaves zero.
        assertEquals(973819730272012410L, SudokuXorshift64Star(0).nextUInt64())
    }

    @Test
    fun `a padding threshold lands inside the configured percentage band`() {
        assertEquals(0L, SudokuXorshift64Star(1).pickPaddingThreshold(0, 0))
        assertEquals(SudokuProtocol.PROBABILITY_ONE, SudokuXorshift64Star(1).pickPaddingThreshold(100, 100))
        assertEquals(274297263L, SudokuXorshift64Star(0x1234).pickPaddingThreshold(5, 15))

        val low = 5L * SudokuProtocol.PROBABILITY_ONE / 100
        val high = 15L * SudokuProtocol.PROBABILITY_ONE / 100
        val rng = SudokuXorshift64Star(20260906)
        repeat(500) {
            val threshold = rng.pickPaddingThreshold(5, 15)
            assertTrue("$threshold outside [$low, $high]", threshold in low..high)
        }

        // Out-of-order and out-of-range bounds are clamped, not rejected.
        assertEquals(SudokuProtocol.PROBABILITY_ONE, SudokuXorshift64Star(3).pickPaddingThreshold(200, 1))
        assertEquals(0L, SudokuXorshift64Star(3).pickPaddingThreshold(-5, -5))
    }

    // ------------------------------------------------------------ static tables

    @Test
    fun `there are exactly 288 grids and 1820 clue positions, in a fixed order`() {
        assertEquals(288, SudokuStaticTables.grids.size)
        assertEquals(1820, SudokuStaticTables.hintPositions.size)

        // Depth-first from cell 0 with values ascending, so the first grid is
        // the lexicographically smallest and the last the largest.
        assertArrayEquals(bytes(1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1), SudokuStaticTables.grids[0])
        assertArrayEquals(bytes(4, 3, 2, 1, 2, 1, 4, 3, 3, 4, 1, 2, 1, 2, 3, 4), SudokuStaticTables.grids[287])

        assertArrayEquals(bytes(0, 1, 2, 3), SudokuStaticTables.hintPositions[0])
        assertArrayEquals(bytes(0, 1, 2, 4), SudokuStaticTables.hintPositions[1])
        assertArrayEquals(bytes(12, 13, 14, 15), SudokuStaticTables.hintPositions[1819])
    }

    @Test
    fun `every generated grid really is a complete Sudoku`() {
        for (grid in SudokuStaticTables.grids) {
            for (unit in 0 until 4) {
                val row = (0 until 4).map { grid[unit * 4 + it].toInt() }.toSet()
                val column = (0 until 4).map { grid[it * 4 + unit].toInt() }.toSet()
                val boxRow = (unit / 2) * 2
                val boxColumn = (unit % 2) * 2
                val box = (0 until 4)
                    .map { grid[(boxRow + it / 2) * 4 + boxColumn + it % 2].toInt() }
                    .toSet()
                assertEquals(setOf(1, 2, 3, 4), row)
                assertEquals(setOf(1, 2, 3, 4), column)
                assertEquals(setOf(1, 2, 3, 4), box)
            }
        }
    }

    @Test
    fun `the clue positions are every ascending four-cell combination, once each`() {
        val seen = HashSet<List<Int>>()
        for (position in SudokuStaticTables.hintPositions) {
            val cells = position.map { it.toInt() }
            assertEquals(4, cells.size)
            assertTrue(cells == cells.sorted())
            assertEquals(4, cells.toSet().size)
            assertTrue("duplicate $cells", seen.add(cells))
        }
        assertEquals(1820, seen.size)
    }

    // ------------------------------------------------------------------ layouts

    @Test
    fun `the ascii layout keeps every octet printable`() {
        val layout = SudokuLayout.ascii()
        assertEquals("ascii", layout.name)
        assertEquals(0x3F.toByte(), layout.padMarker)
        assertEquals(32, layout.paddingPool.size)
        assertArrayEquals(ByteArray(32) { (0x20 + it).toByte() }, layout.paddingPool)

        for (value in 0 until 4) {
            for (position in 0 until 16) {
                val expected = 0x40 or (value shl 4) or position
                val actual = layout.encodeHint[value][position].toInt() and 0xFF
                // 0x7F is delete rather than printable, so that one hint moves.
                assertEquals(if (expected == 0x7F) 0x0A else expected, actual)
            }
        }

        for (octet in 0 until 256) {
            val isHint = (octet and 0x40) == 0x40 || octet == 0x0A
            assertEquals("octet $octet", isHint, layout.hintTable[octet])
            assertEquals("octet $octet", isHint, layout.groupValid[octet])
            if (!isHint) continue
            val group = if (octet == 0x0A) 0x3F else octet and 0x3F
            assertEquals("octet $octet", group, layout.decodeGroup[octet].toInt() and 0xFF)
        }

        // No padding octet may be mistaken for a hint.
        for (pad in layout.paddingPool) assertFalse(layout.hintTable[pad.toInt() and 0xFF])
    }

    @Test
    fun `the entropy layout spreads hints across the octet space`() {
        val layout = SudokuLayout.entropy()
        assertEquals("entropy", layout.name)
        assertEquals(0x80.toByte(), layout.padMarker)
        assertEquals(16, layout.paddingPool.size)
        // The pool alternates between the two bands either side of the hints.
        assertArrayEquals(
            bytes(0x80, 0x10, 0x81, 0x11, 0x82, 0x12, 0x83, 0x13, 0x84, 0x14, 0x85, 0x15, 0x86, 0x16, 0x87, 0x17),
            layout.paddingPool
        )

        for (value in 0 until 4) {
            for (position in 0 until 16) {
                assertEquals(
                    (value shl 5) or position,
                    layout.encodeHint[value][position].toInt() and 0xFF
                )
            }
        }

        for (octet in 0 until 256) {
            val isHint = (octet and 0x90) == 0
            assertEquals("octet $octet", isHint, layout.hintTable[octet])
            assertEquals("octet $octet", isHint, layout.groupValid[octet])
            if (!isHint) continue
            assertEquals(
                "octet $octet",
                ((octet shr 1) and 0x30) or (octet and 0x0F),
                layout.decodeGroup[octet].toInt() and 0xFF
            )
        }
        for (pad in layout.paddingPool) assertFalse(layout.hintTable[pad.toInt() and 0xFF])
    }

    @Test
    fun `a custom layout places the fields where its pattern says`() {
        val layout = SudokuLayout.custom(CUSTOM_PATTERN)
        assertEquals("custom(xpvvxpvv)", layout.name)

        // xpvvxpvv reading from bit 7 down: x at 7 and 3, p at 6 and 2,
        // v at 5, 4, 1, 0.
        val xMask = (1 shl 7) or (1 shl 3)
        for (value in 0 until 4) {
            for (position in 0 until 16) {
                var expected = xMask
                if ((value and 2) != 0) expected = expected or (1 shl 6)
                if ((value and 1) != 0) expected = expected or (1 shl 2)
                if ((position and 0x8) != 0) expected = expected or (1 shl 5)
                if ((position and 0x4) != 0) expected = expected or (1 shl 4)
                if ((position and 0x2) != 0) expected = expected or (1 shl 1)
                if ((position and 0x1) != 0) expected = expected or (1 shl 0)
                assertEquals(expected, layout.encodeHint[value][position].toInt() and 0xFF)
            }
        }
        assertEquals(0x88, layout.encodeHint[0][0].toInt() and 0xFF)
        assertEquals(0xFF, layout.encodeHint[3][15].toInt() and 0xFF)

        for (octet in 0 until 256) {
            assertEquals("octet $octet", (octet and xMask) == xMask, layout.hintTable[octet])
        }

        // Padding is sorted, never a hint, and always at least five bits set.
        assertEquals(0x1F.toByte(), layout.padMarker)
        assertEquals(44, layout.paddingPool.size)
        var previous = -1
        for (pad in layout.paddingPool) {
            val value = pad.toInt() and 0xFF
            assertTrue("not ascending", value > previous)
            previous = value
            assertFalse(layout.hintTable[value])
            assertTrue(Integer.bitCount(value) >= 5)
        }
    }

    @Test
    fun `a custom pattern that is not two x, two p and four v is refused`() {
        for (pattern in listOf("", "xpvv", "xpvvxpvvx", "xpvvxpvz", "xxvvxpvv", "ppvvxpvv", "xpvvvpvv")) {
            try {
                SudokuLayout.custom(pattern)
                fail("accepted \"$pattern\"")
            } catch (error: SudokuError.InvalidConfiguration) {
                assertEquals("invalid custom Sudoku table", error.message)
            }
        }
        // Spaces are decoration and case does not matter.
        assertEquals("custom(xpvvxpvv)", SudokuLayout.custom("XP VV XP VV").name)
    }

    // ---------------------------------------------------------- hint packing

    @Test
    fun `packing four hints is order-independent`() {
        val quadruple = bytes(0x6F, 0x02, 0x41, 0x2D)
        val sorted = quadruple.map { it.toInt() and 0xFF }.sorted()
        val expected = (sorted[0] shl 24) or (sorted[1] shl 16) or (sorted[2] shl 8) or sorted[3]

        assertEquals(expected, SudokuProtocol.packHints(quadruple[0], quadruple[1], quadruple[2], quadruple[3]))
        assertEquals(expected, SudokuProtocol.packHints(quadruple[3], quadruple[2], quadruple[1], quadruple[0]))
        assertEquals(expected, SudokuProtocol.packHints(quadruple[2], quadruple[0], quadruple[3], quadruple[1]))

        // High octets must not sort as negative numbers.
        assertEquals(
            (0x02 shl 24) or (0x41 shl 16) or (0x80 shl 8) or 0xFF,
            SudokuProtocol.packHints(0xFF.toByte(), 0x02, 0x80.toByte(), 0x41)
        )
    }

    // ------------------------------------------------------------ the codebook

    @Test
    fun `a codebook gives every byte at least one puzzle and decodes each back`() {
        val table = entropyTables.uplink
        for (value in 0 until 256) assertTrue("byte $value has no puzzle", table.puzzleCount(value) > 0)

        // The key shuffles the deck, so these counts are a property of this key.
        assertEquals(12, table.puzzleCount(0))
        assertEquals(128, table.puzzleCount(1))
        assertEquals(128, table.puzzleCount(2))
        assertEquals(12, table.puzzleCount(255))
    }

    @Test
    fun `four hints that name no grid are refused rather than guessed at`() {
        val layout = entropyTables.uplink.layout
        // Four identical hints: legal octets, but no puzzle repeats a cell.
        assertTrue(layout.hintTable[0])
        assertEquals(-1, entropyTables.uplink.decodePackedHints(SudokuProtocol.packHints(0, 0, 0, 0)))

        try {
            SudokuPureDecoder(entropyTables.uplink).decode(bytes(0, 0, 0, 0))
            fail("decoded a quadruple that names no grid")
        } catch (error: SudokuError.ProtocolViolation) {
            assertEquals("Sudoku decode failed", error.message)
        }
    }

    @Test
    fun `the encoder produces the bytes the reference produces`() {
        val payload = bytes(0x00, 0x01, 0x41, 0xFF)

        // No padding: four hints per byte and nothing else.
        val plain = entropyTables.uplink.encode(payload, SudokuXorshift64Star(1), 0)
        assertEquals(16, plain.size)
        assertEquals("4c61230e082546636d0b43450c2e6341", hex(plain))

        // Padding at every opportunity: one before the byte, one before each of
        // the four hints, and one closing byte for the whole message.
        val padded = entropyTables.uplink.encode(payload, SudokuXorshift64Star(1), SudokuProtocol.PROBABILITY_ONE)
        assertEquals(4 * (1 + 8) + 1, padded.size)
        assertEquals(
            "828768150e874282241586638240160e1664858767156d8224134e12810b8220156d864616",
            hex(padded)
        )

        // A drawn threshold pads some slots and not others.
        val rng = SudokuXorshift64Star(0x1234)
        val threshold = rng.pickPaddingThreshold(5, 15)
        val sparse = entropyTables.uplink.encode(payload, rng, threshold)
        assertEquals("4209246f076a2c0167294e0c2e64024814", hex(sparse))

        // The ascii and custom layouts use the same deck, different octets.
        assertEquals(
            "650a5349487a5c6659706377504c7a66",
            hex(asciiTables.uplink.encode(payload, SudokuXorshift64Star(7), 0))
        )
        assertEquals(
            "f8cd8fbaa89ddacffdabcbd9b8becfc9",
            hex(customTables.uplink.encode(payload, SudokuXorshift64Star(1), 0))
        )
    }

    @Test
    fun `an ascii stream really is printable and an entropy stream is not confined`() {
        val payload = ByteArray(256) { it.toByte() }

        val printable = asciiTables.uplink.encode(payload, SudokuXorshift64Star(5), SudokuProtocol.PROBABILITY_ONE)
        for (byte in printable) {
            val value = byte.toInt() and 0xFF
            assertTrue("$value is not printable", value == 0x0A || value in 0x20..0x7E)
        }

        val spread = entropyTables.uplink.encode(payload, SudokuXorshift64Star(5), SudokuProtocol.PROBABILITY_ONE)
        assertTrue(spread.any { (it.toInt() and 0xFF) >= 0x80 })
    }

    // ------------------------------------------------------------ round trips

    @Test
    fun `everything that is encoded decodes back, on every layout`() {
        val payload = ByteArray(1024) { (it * 31 + 7).toByte() }
        for (pair in listOf(entropyTables, asciiTables, customTables)) {
            for (threshold in listOf(0L, 1L shl 30, SudokuProtocol.PROBABILITY_ONE)) {
                val wire = pair.uplink.encode(payload, SudokuXorshift64Star(0xABCDEF), threshold)
                val decoded = SudokuPureDecoder(pair.uplink).decode(wire)
                assertArrayEquals("${pair.uplink.layout.name} at $threshold", payload, decoded)
            }
        }
    }

    @Test
    fun `a puzzle split across reads decodes the same as one that arrived whole`() {
        val payload = ByteArray(300) { (it * 7).toByte() }
        val wire = entropyTables.uplink.encode(payload, SudokuXorshift64Star(11), 1L shl 31)

        // One byte at a time is the worst case: every puzzle straddles a call.
        val trickle = SudokuPureDecoder(entropyTables.uplink)
        val gathered = java.io.ByteArrayOutputStream()
        for (byte in wire) gathered.write(trickle.decode(byteArrayOf(byte)))
        assertArrayEquals(payload, gathered.toByteArray())

        // Uneven chunks, none of them a multiple of four.
        val chunked = SudokuPureDecoder(entropyTables.uplink)
        val rebuilt = java.io.ByteArrayOutputStream()
        var at = 0
        var size = 1
        while (at < wire.size) {
            val end = minOf(wire.size, at + size)
            rebuilt.write(chunked.decode(wire.copyOfRange(at, end)))
            at = end
            size = size % 7 + 1
        }
        assertArrayEquals(payload, rebuilt.toByteArray())
    }

    @Test
    fun `a decode limit holds the surplus back instead of dropping it`() {
        val payload = ByteArray(64) { it.toByte() }
        val wire = entropyTables.uplink.encode(payload, SudokuXorshift64Star(13), 0)

        val decoder = SudokuPureDecoder(entropyTables.uplink)
        val first = decoder.decode(wire, limit = 10)
        assertEquals(10, first.size)
        assertArrayEquals(payload.copyOf(10), first)
        assertEquals(54, decoder.pendingCount)

        // Nothing more goes in; the rest comes out of the held bytes.
        val second = decoder.decode(ByteArray(0), limit = 40)
        assertArrayEquals(payload.copyOfRange(10, 50), second)
        assertEquals(14, decoder.pendingCount)

        val third = decoder.decode(ByteArray(0))
        assertArrayEquals(payload.copyOfRange(50, 64), third)
        assertEquals(0, decoder.pendingCount)

        // A zero limit is a no-op rather than a loss.
        val untouched = SudokuPureDecoder(entropyTables.uplink)
        assertEquals(0, untouched.decode(wire, limit = 0).size)
        assertEquals(0, untouched.pendingCount)
        assertArrayEquals(payload, untouched.decode(wire))
    }

    @Test
    fun `padding octets are dropped wherever they land`() {
        val payload = bytes(0x11, 0x22, 0x33)
        val bare = entropyTables.uplink.encode(payload, SudokuXorshift64Star(17), 0)

        // Splice the layout's own padding octets into every gap by hand, which
        // is a stream the encoder itself would never emit in this order.
        val pool = entropyTables.uplink.layout.paddingPool
        val noisy = java.io.ByteArrayOutputStream()
        bare.forEachIndexed { index, byte ->
            noisy.write(pool[index % pool.size].toInt())
            noisy.write(pool[(index * 3) % pool.size].toInt())
            noisy.write(byte.toInt())
        }
        noisy.write(pool[0].toInt())

        assertArrayEquals(payload, SudokuPureDecoder(entropyTables.uplink).decode(noisy.toByteArray()))
    }

    // ------------------------------------------------------- the packed downlink

    @Test
    fun `the packed downlink turns four hint octets into three bytes`() {
        for (pair in listOf(entropyTables, asciiTables)) {
            val layout = pair.downlink.layout
            val payload = "Hi!".toByteArray(Charsets.US_ASCII)
            val wire = packBySixBits(layout, payload)
            assertEquals(4, wire.size)
            assertArrayEquals(payload, SudokuPackedDecoder(pair.downlink).decode(wire))
        }

        // Built from the entropy layout's own rule, independently of the packer.
        assertArrayEquals(
            "Hi!".toByteArray(Charsets.US_ASCII),
            SudokuPackedDecoder(entropyTables.downlink).decode(bytes(0x22, 0x06, 0x44, 0x41))
        )
    }

    @Test
    fun `the pad marker clears a partial group in the packed downlink`() {
        val layout = entropyTables.downlink.layout
        val payload = "Hi!".toByteArray(Charsets.US_ASCII)
        val wire = packBySixBits(layout, payload)

        // Two groups is twelve bits: one whole byte comes out and four bits are
        // left over, which the marker then discards.
        val interrupted = wire.copyOf(2) + byteArrayOf(layout.padMarker) + wire
        assertArrayEquals(
            byteArrayOf(payload[0]) + payload,
            SudokuPackedDecoder(entropyTables.downlink).decode(interrupted)
        )
    }

    @Test
    fun `the packed downlink keeps its bit buffer across reads`() {
        val layout = entropyTables.downlink.layout
        val payload = ByteArray(96) { (it * 5 + 1).toByte() }
        val wire = packBySixBits(layout, payload)

        val decoder = SudokuPackedDecoder(entropyTables.downlink)
        val gathered = java.io.ByteArrayOutputStream()
        for (byte in wire) gathered.write(decoder.decode(byteArrayOf(byte)))
        assertArrayEquals(payload, gathered.toByteArray())

        // And it respects a limit the same way the pure decoder does.
        val limited = SudokuPackedDecoder(entropyTables.downlink)
        assertArrayEquals(payload.copyOf(5), limited.decode(wire, limit = 5))
        assertEquals(payload.size - 5, limited.pendingCount)
    }

    /**
     * Packs whole bytes into six-bit groups and writes each as the octet the
     * layout's own decode table maps back to it — the server's side of the
     * packed downlink, built from the layout rather than from this port's
     * decoder.
     */
    private fun packBySixBits(layout: SudokuLayout, payload: ByteArray): ByteArray {
        require(payload.size % 3 == 0)
        val inverse = IntArray(64) { -1 }
        for (octet in 255 downTo 0) {
            if (layout.hintTable[octet] && layout.groupValid[octet]) {
                inverse[layout.decodeGroup[octet].toInt() and 0xFF] = octet
            }
        }
        val out = ByteArray(payload.size / 3 * 4)
        var at = 0
        for (block in payload.indices step 3) {
            val packed = ((payload[block].toInt() and 0xFF) shl 16) or
                ((payload[block + 1].toInt() and 0xFF) shl 8) or
                (payload[block + 2].toInt() and 0xFF)
            for (group in 3 downTo 0) {
                val six = (packed shr (group * 6)) and 0x3F
                assertNotEquals("no octet carries group $six", -1, inverse[six])
                out[at++] = inverse[six].toByte()
            }
        }
        return out
    }

    // ------------------------------------------------------------ table pairing

    @Test
    fun `a fingerprint covers the key, the mode and both custom patterns`() {
        assertEquals(0xEDAE9975L, SudokuTablePair(key, SudokuAsciiMode.PREFER_ENTROPY).hint)
        assertEquals(0x9C738E9FL, SudokuTablePair(key, SudokuAsciiMode.PREFER_ASCII).hint)

        // A pattern only counts for a direction that is actually entropy, so the
        // uplink pattern of an up-ascii mode is dropped from the fingerprint.
        assertEquals(
            0x331CFD26L,
            SudokuTablePair(key, SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY, CUSTOM_PATTERN, CUSTOM_PATTERN).hint
        )
        assertEquals(
            0x2CAAEB3CL,
            SudokuTablePair(key, SudokuAsciiMode.UP_ENTROPY_DOWN_ASCII, CUSTOM_PATTERN, CUSTOM_PATTERN).hint
        )

        assertEquals(
            0xEDAE9975L,
            SudokuTablePair.tableHintFingerprint(key, "prefer_entropy", "", "")
        )
        // The separators keep a longer key from colliding with a longer mode.
        assertNotEquals(
            SudokuTablePair.tableHintFingerprint("ab", "cd", "", ""),
            SudokuTablePair.tableHintFingerprint("a", "bcd", "", "")
        )
    }

    @Test
    fun `a symmetric mode builds one table and a mixed one builds two`() {
        val symmetric = SudokuTablePair(key, SudokuAsciiMode.PREFER_ENTROPY)
        assertSame(symmetric.uplink, symmetric.downlink)

        val mixed = SudokuTablePair(key, SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY)
        assertEquals("ascii", mixed.uplink.layout.name)
        assertEquals("entropy", mixed.downlink.layout.name)
        assertEquals(mixed.uplink.hint, mixed.downlink.hint)
    }

    @Test
    fun `a different key shuffles a different deck`() {
        val other = SudokuTablePair("some-other-key", SudokuAsciiMode.PREFER_ENTROPY)
        val payload = bytes(0x00, 0x01, 0x41, 0xFF)
        val mine = entropyTables.uplink.encode(payload, SudokuXorshift64Star(1), 0)
        val theirs = other.uplink.encode(payload, SudokuXorshift64Star(1), 0)
        assertNotEquals(hex(mine), hex(theirs))
    }

    // ----------------------------------------------------------- key schedule

    @Test
    fun `the pre-shared key expands to the two direction secrets`() {
        val bases = SudokuProtocol.pskBases("hunter2")
        assertEquals("528895de7b111eb692ebbf855ae0bb680b1ae81a79394a923ea1875fc8f140cb", hex(bases.clientToServer))
        assertEquals("6e09af7ea043328876349333c7f36ef06a79479b95e9ee4dbd84e632cbc80325", hex(bases.serverToClient))
        assertEquals(32, bases.clientToServer.size)
        assertEquals(32, bases.serverToClient.size)
    }

    @Test
    fun `the session secrets take in the shared secret and the nonce`() {
        val shared = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(16) { (0x10 + it).toByte() }
        val bases = SudokuProtocol.sessionBases("hunter2", shared, nonce)
        assertEquals("e25fdba2ea246124f554164cb8403d46152208ee87bcf2aaafe0ee441e9c4b84", hex(bases.clientToServer))
        assertEquals("7c3c0524cbb9f2c4f5d70818c60b29b5e3ea7a816f39c16b159bbd196125b836", hex(bases.serverToClient))
    }

    @Test
    fun `an epoch key binds the base secret, the cipher's name and the epoch`() {
        val base = SudokuProtocol.pskBases("hunter2").clientToServer
        assertEquals(
            "0c23dc891ce91d8bc057699d186825f51b6859be17f6d6ca5812bb55ec8d9824",
            hex(SudokuProtocol.recordEpochKey(base, SudokuAeadMethod.CHACHA20_POLY1305, 7))
        )
        assertEquals(
            "cf62596b1dbb0a482dbaf9d6c4fa67bf838696fb78d0d7f328ec46cd6f7dac5d",
            hex(SudokuProtocol.recordEpochKey(base, SudokuAeadMethod.AES_128_GCM, 0))
        )
        // The two ciphers never share a key for the same epoch.
        assertNotEquals(
            hex(SudokuProtocol.recordEpochKey(base, SudokuAeadMethod.CHACHA20_POLY1305, 3)),
            hex(SudokuProtocol.recordEpochKey(base, SudokuAeadMethod.AES_128_GCM, 3))
        )
    }

    @Test
    fun `hkdf expand agrees with RFC 5869's construction over more than one block`() {
        val prk = ByteArray(32) { (it + 1).toByte() }
        val long = SudokuProtocol.hkdfExpand(prk, "label", 80)
        assertEquals(80, long.size)

        // T(1) = HMAC(prk, info || 0x01), T(n) = HMAC(prk, T(n-1) || info || n).
        val info = "label".toByteArray(Charsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val t1 = mac.doFinal(info + byteArrayOf(1))
        mac.reset()
        val t2 = mac.doFinal(t1 + info + byteArrayOf(2))
        mac.reset()
        val t3 = mac.doFinal(t2 + info + byteArrayOf(3))
        assertEquals(hex((t1 + t2 + t3).copyOf(80)), hex(long))
    }

    // ---------------------------------------------------------- record framing

    @Test
    fun `a record header puts the epoch and sequence where the reference reads them`() {
        val header = SudokuProtocol.recordHeader(0xDEADBEEFL, 0x0102030405060708L)
        assertEquals(12, header.size)
        assertEquals("deadbeef0102030405060708", hex(header))
        assertEquals(0xDEADBEEFL, SudokuProtocol.recordEpoch(header))
        assertEquals(0x0102030405060708L, SudokuProtocol.recordSequence(header))

        // The top bit of a sequence is data, not a sign.
        val high = SudokuProtocol.recordHeader(0, -1L)
        assertEquals("00000000ffffffffffffffff", hex(high))
        assertEquals(-1L, SudokuProtocol.recordSequence(high))
    }

    @Test
    fun `a sealed record is a length, that header, and a tagged body`() {
        for (method in listOf(SudokuAeadMethod.CHACHA20_POLY1305, SudokuAeadMethod.AES_128_GCM)) {
            val base = SudokuProtocol.pskBases("hunter2").clientToServer
            val plaintext = "the quick brown fox".toByteArray(Charsets.UTF_8)
            val record = SudokuProtocol.sealRecord(method, base, epoch = 5, sequence = 9, plaintext = plaintext)

            val bodyLength = 12 + plaintext.size + 16
            assertEquals(2 + bodyLength, record.size)
            assertEquals(bodyLength, SudokuProtocol.parseRecordLength(record))
            assertEquals(
                hex(SudokuProtocol.recordHeader(5, 9)),
                hex(record.copyOfRange(2, 14))
            )

            val body = record.copyOfRange(2, record.size)
            assertArrayEquals(plaintext, SudokuProtocol.openRecord(method, base, body))

            // The header is the associated data, so touching it breaks the tag.
            val tampered = body.copyOf()
            tampered[11] = (tampered[11] + 1).toByte()
            try {
                SudokuProtocol.openRecord(method, base, tampered)
                fail("$method opened a record with a rewritten header")
            } catch (error: SudokuError.ProtocolViolation) {
                assertTrue(error.message!!.contains("open failed"))
            }

            // ...and so does touching the ciphertext.
            val corrupted = body.copyOf()
            corrupted[20] = (corrupted[20].toInt() xor 0x40).toByte()
            try {
                SudokuProtocol.openRecord(method, base, corrupted)
                fail("$method opened a corrupted record")
            } catch (_: SudokuError.ProtocolViolation) {
                // expected
            }
        }
    }

    @Test
    fun `the none method leaves the payload alone`() {
        val plaintext = "plain".toByteArray(Charsets.UTF_8)
        val record = SudokuProtocol.sealRecord(SudokuAeadMethod.NONE, ByteArray(32), 1, 1, plaintext)
        assertArrayEquals(plaintext, record)
        assertArrayEquals(plaintext, SudokuProtocol.openRecord(SudokuAeadMethod.NONE, ByteArray(32), plaintext))
    }

    @Test
    fun `a record length that cannot hold a header is refused`() {
        for (length in 0 until 12) {
            try {
                SudokuProtocol.parseRecordLength(bytes(length shr 8, length and 0xFF))
                fail("accepted a body length of $length")
            } catch (error: SudokuError.ProtocolViolation) {
                assertEquals("bad record length: $length", error.message)
            }
        }
        assertEquals(12, SudokuProtocol.parseRecordLength(bytes(0x00, 0x0C)))
        assertEquals(65535, SudokuProtocol.parseRecordLength(bytes(0xFF, 0xFF)))

        try {
            SudokuProtocol.parseRecordLength(bytes(0x00))
            fail("read a length out of one byte")
        } catch (error: SudokuError.ProtocolViolation) {
            assertEquals("truncated record length", error.message)
        }
    }

    @Test
    fun `a body too short to hold a header and a tag is refused`() {
        val base = SudokuProtocol.pskBases("hunter2").serverToClient
        for (size in listOf(0, 11, 12, 27)) {
            try {
                SudokuProtocol.openRecord(SudokuAeadMethod.CHACHA20_POLY1305, base, ByteArray(size))
                fail("opened a $size-byte body")
            } catch (error: SudokuError.ProtocolViolation) {
                assertEquals("short record body: $size", error.message)
            }
        }
    }

    @Test
    fun `records out of order are refused and a modest epoch step is not`() {
        // In the same epoch, the sequence has to be exactly the expected one.
        SudokuProtocol.validateRecordOrder(4, 100, 4, 100)
        expectViolation("out of order record") { SudokuProtocol.validateRecordOrder(4, 100, 4, 101) }
        expectViolation("out of order record") { SudokuProtocol.validateRecordOrder(4, 100, 4, 99) }

        // A newer epoch resets the sequence, so anything goes there.
        SudokuProtocol.validateRecordOrder(4, 100, 5, 0)
        SudokuProtocol.validateRecordOrder(4, 100, 12, 77)
        expectViolation("record epoch jump") { SudokuProtocol.validateRecordOrder(4, 100, 13, 0) }
        expectViolation("replayed record epoch") { SudokuProtocol.validateRecordOrder(4, 100, 3, 0) }

        // Epochs are unsigned, so one past the sign boundary is still ahead.
        SudokuProtocol.validateRecordOrder(0x7FFFFFFFL, 0, 0x80000000L, 0)
    }

    // ------------------------------------------------------------ KIP framing

    @Test
    fun `a KIP frame is the magic, a type and a 16-bit length`() {
        val payload = ByteArray(300) { it.toByte() }
        val frame = SudokuProtocol.encodeKip(SudokuProtocol.KIP_CONNECT_TCP, payload)

        assertEquals(6 + 300, frame.size)
        assertEquals("kip", String(frame.copyOf(3), Charsets.US_ASCII))
        assertEquals(0x10.toByte(), frame[3])
        assertEquals(0x01.toByte(), frame[4])
        assertEquals(0x2C.toByte(), frame[5])
        assertArrayEquals(payload, frame.copyOfRange(6, frame.size))

        val parsed = SudokuProtocol.parseKip(frame)
        assertEquals(SudokuProtocol.KIP_CONNECT_TCP, parsed.type)
        assertArrayEquals(payload, parsed.payload)
        assertEquals(306, parsed.consumed)

        // An empty payload is legal, and is what opening a mux or UoT stream sends.
        val empty = SudokuProtocol.encodeKip(SudokuProtocol.KIP_OPEN_MUX, ByteArray(0))
        assertEquals("6b6970110000", hex(empty))
        assertEquals(0, SudokuProtocol.parseKip(empty).payload.size)
    }

    @Test
    fun `a short, misnamed or truncated KIP frame is refused rather than misparsed`() {
        val frame = SudokuProtocol.encodeKip(SudokuProtocol.KIP_CLIENT_HELLO, bytes(1, 2, 3, 4))

        for (size in 0 until 6) {
            expectViolation("short KIP frame") { SudokuProtocol.parseKip(frame.copyOf(size)) }
        }
        for (size in 6 until frame.size) {
            expectViolation("truncated KIP frame ${size}/10") { SudokuProtocol.parseKip(frame.copyOf(size)) }
        }

        val wrongMagic = frame.copyOf()
        wrongMagic[2] = 'q'.code.toByte()
        expectViolation("bad KIP magic") { SudokuProtocol.parseKip(wrongMagic) }

        // The magic is checked at the offset, not at the start of the buffer.
        val prefixed = bytes(0xFF, 0xFF) + frame
        assertEquals(4, SudokuProtocol.parseKip(prefixed, offset = 2).payload.size)
        expectViolation("bad KIP magic") { SudokuProtocol.parseKip(prefixed) }
    }

    @Test
    fun `a client hello lays its fields out where the server reads them`() {
        val source = "the-account-key".toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(16) { (0xA0 + it).toByte() }
        val publicKey = ByteArray(32) { (it * 3).toByte() }

        val hello = SudokuProtocol.encodeClientHello(0x0000000163ABCDEFL, source, nonce, publicKey)
        assertEquals(68, hello.size)
        assertEquals("0000000163abcdef", hex(hello.copyOf(8)))
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(source).copyOf(8),
            hello.copyOfRange(8, 16)
        )
        assertArrayEquals(nonce, hello.copyOfRange(16, 32))
        assertArrayEquals(publicKey, hello.copyOfRange(32, 64))
        assertEquals("0000001f", hex(hello.copyOfRange(64, 68)))

        val hinted = SudokuProtocol.encodeClientHello(0, source, nonce, publicKey, tableHint = 0xEDAE9975L)
        assertEquals(72, hinted.size)
        assertEquals("0000001fedae9975", hex(hinted.copyOfRange(64, 72)))
        assertArrayEquals(hello.copyOfRange(8, 68), hinted.copyOfRange(8, 68))
    }

    @Test
    fun `a server hello is accepted only at the right size and with our nonce back`() {
        val nonce = ByteArray(16) { (0xA0 + it).toByte() }
        val serverKey = ByteArray(32) { (0x40 + it).toByte() }
        val payload = nonce + serverKey + bytes(0, 0, 0, 0x1F)

        assertArrayEquals(serverKey, SudokuProtocol.parseServerHello(payload, nonce))

        expectViolation("bad KIP server hello") { SudokuProtocol.parseServerHello(payload.copyOf(51), nonce) }
        expectViolation("bad KIP server hello") { SudokuProtocol.parseServerHello(payload + ByteArray(1), nonce) }

        val replayed = payload.copyOf()
        replayed[15] = (replayed[15] + 1).toByte()
        expectViolation("KIP nonce mismatch") { SudokuProtocol.parseServerHello(replayed, nonce) }
    }

    // ----------------------------------------------------------- addresses

    @Test
    fun `a destination goes out in SOCKS5 address form`() {
        assertEquals("01c0a80001" + "01bb", hex(SudokuProtocol.encodeAddress("192.168.0.1", 443)))
        assertEquals(
            "04" + "20010db8000000000000000000000001" + "0050",
            hex(SudokuProtocol.encodeAddress("2001:db8::1", 80))
        )
        assertEquals(
            "03" + "0b" + hex("example.com".toByteArray(Charsets.UTF_8)) + "1f90",
            hex(SudokuProtocol.encodeAddress("example.com", 8080))
        )

        // Port 0 and port 65535 both fit the two trailing bytes.
        assertEquals("0100000000" + "0000", hex(SudokuProtocol.encodeAddress("0.0.0.0", 0)))
        assertEquals("01ffffffff" + "ffff", hex(SudokuProtocol.encodeAddress("255.255.255.255", 65535)))
    }

    @Test
    fun `a name too long for its one-byte length is refused, not truncated`() {
        val longest = "a".repeat(255)
        assertEquals(1 + 1 + 255 + 2, SudokuProtocol.encodeAddress(longest, 1).size)
        try {
            SudokuProtocol.encodeAddress("a".repeat(256), 1)
            fail("accepted a 256-byte name")
        } catch (error: SudokuError.InvalidConfiguration) {
            assertEquals("domain too long", error.message)
        }
    }

    // -------------------------------------------------------- UDP over TCP

    @Test
    fun `a UDP over TCP frame names both its lengths up front`() {
        val payload = ByteArray(600) { it.toByte() }
        val frame = SudokuProtocol.encodeUdpOverTcp("1.2.3.4", 53, payload)
        val address = SudokuProtocol.encodeAddress("1.2.3.4", 53)

        assertEquals(4 + address.size + payload.size, frame.size)
        assertEquals("0007", hex(frame.copyOf(2)))
        assertEquals("0258", hex(frame.copyOfRange(2, 4)))
        assertArrayEquals(address, frame.copyOfRange(4, 4 + address.size))
        assertArrayEquals(payload, frame.copyOfRange(4 + address.size, frame.size))

        val header = SudokuProtocol.parseUdpOverTcpHeader(frame)
        assertEquals(7, header.addressLength)
        assertEquals(600, header.payloadLength)
    }

    @Test
    fun `a UDP over TCP header with no address or a runaway length is refused`() {
        expectViolation("bad UoT address length: 0") {
            SudokuProtocol.parseUdpOverTcpHeader(bytes(0, 0, 0, 4))
        }
        for (size in 0 until 4) {
            expectViolation("truncated UoT header") {
                SudokuProtocol.parseUdpOverTcpHeader(ByteArray(size))
            }
        }
        // Both lengths are 16-bit, so the caps are reachable but not exceedable.
        val largest = SudokuProtocol.parseUdpOverTcpHeader(bytes(0xFF, 0xFF, 0xFF, 0xFF))
        assertEquals(65535, largest.addressLength)
        assertEquals(65535, largest.payloadLength)

        // An empty payload is legal; an empty address is not.
        assertEquals(0, SudokuProtocol.parseUdpOverTcpHeader(bytes(0, 1, 0, 0)).payloadLength)
    }

    // ---------------------------------------------------------- mux framing

    @Test
    fun `a mux frame is a type, a stream id and a 32-bit length`() {
        val payload = ByteArray(70000) { it.toByte() }
        val frame = SudokuProtocol.encodeMuxFrame(SudokuProtocol.MUX_DATA, 0xFEDCBA98L, payload)

        assertEquals(9 + 70000, frame.size)
        assertEquals("02", hex(frame.copyOf(1)))
        assertEquals("fedcba98", hex(frame.copyOfRange(1, 5)))
        assertEquals("00011170", hex(frame.copyOfRange(5, 9)))

        val header = SudokuProtocol.parseMuxHeader(frame)
        assertEquals(SudokuProtocol.MUX_DATA, header.type)
        assertEquals(0xFEDCBA98L, header.streamId)
        assertEquals(70000, header.length)

        // A keepalive is a data frame on stream 0 with nothing in it.
        assertEquals(
            "020000000000000000",
            hex(SudokuProtocol.encodeMuxFrame(SudokuProtocol.MUX_DATA, 0, ByteArray(0)))
        )
    }

    @Test
    fun `a mux frame with an unknown type or an impossible length is refused`() {
        expectViolation("truncated mux header") { SudokuProtocol.parseMuxHeader(ByteArray(8)) }
        expectViolation("bad mux frame") { SudokuProtocol.parseMuxHeader(bytes(0x00, 0, 0, 0, 1, 0, 0, 0, 0)) }
        expectViolation("bad mux frame") { SudokuProtocol.parseMuxHeader(bytes(0x05, 0, 0, 0, 1, 0, 0, 0, 0)) }

        // 256 KiB exactly is allowed; one more is not, in either direction.
        val atCap = bytes(0x02, 0, 0, 0, 1, 0x00, 0x04, 0x00, 0x00)
        assertEquals(262144, SudokuProtocol.parseMuxHeader(atCap).length)
        expectViolation("mux frame too large: 262145") {
            SudokuProtocol.parseMuxHeader(bytes(0x02, 0, 0, 0, 1, 0x00, 0x04, 0x00, 0x01))
        }
        expectViolation("mux frame too large: 262145") {
            SudokuProtocol.encodeMuxFrame(SudokuProtocol.MUX_DATA, 1, ByteArray(262145))
        }
        // A length with the top bit set must not read back as negative.
        expectViolation("mux frame too large: 4294967295") {
            SudokuProtocol.parseMuxHeader(bytes(0x02, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF))
        }
    }

    // ------------------------------------------------------ HTTP camouflage

    @Test
    fun `a mask token is a timestamp and half a MAC over the request`() {
        val token = SudokuProtocol.httpMaskAuthToken("hunter2", "ws", "GET", "/ws", 1767225600L)

        // URL-safe alphabet, no padding: it goes in a query string as well as a
        // header.
        assertFalse(token.contains('+'))
        assertFalse(token.contains('/'))
        assertFalse(token.contains('='))

        val decoded = Base64.getUrlDecoder().decode(token)
        assertEquals(24, decoded.size)
        assertEquals("000000006955b900", hex(decoded.copyOf(8)))

        // Rebuilt here from the reference's construction rather than taken from
        // the implementation: sha256("prefix" + key) keys an HMAC over the mode,
        // method, path and timestamp, each separated by a zero byte.
        val authKey = MessageDigest.getInstance("SHA-256")
            .digest("sudoku-httpmask-auth-v1:hunter2".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(authKey, "HmacSHA256"))
        val zero = byteArrayOf(0)
        val expected = mac.doFinal(
            "ws".toByteArray(Charsets.UTF_8) + zero +
                "GET".toByteArray(Charsets.UTF_8) + zero +
                "/ws".toByteArray(Charsets.UTF_8) + zero +
                decoded.copyOf(8)
        )
        assertEquals(hex(expected.copyOf(16)), hex(decoded.copyOfRange(8, 24)))

        // Every input is covered, so nothing can be swapped after the fact.
        val base = SudokuProtocol.httpMaskAuthToken("k", "ws", "GET", "/ws", 1)
        assertNotEquals(base, SudokuProtocol.httpMaskAuthToken("k2", "ws", "GET", "/ws", 1))
        assertNotEquals(base, SudokuProtocol.httpMaskAuthToken("k", "poll", "GET", "/ws", 1))
        assertNotEquals(base, SudokuProtocol.httpMaskAuthToken("k", "ws", "POST", "/ws", 1))
        assertNotEquals(base, SudokuProtocol.httpMaskAuthToken("k", "ws", "GET", "/wss", 1))
        assertNotEquals(base, SudokuProtocol.httpMaskAuthToken("k", "ws", "GET", "/ws", 2))
    }

    @Test
    fun `a path root prefixes the request path when it is usable`() {
        assertEquals("/cdn/api", SudokuProtocol.applyPathRoot("cdn", "/api"))
        assertEquals("/cdn/api", SudokuProtocol.applyPathRoot("/cdn/", "api"))
        assertEquals("/api", SudokuProtocol.applyPathRoot("", "/api"))
        // A root that is not one unreserved segment is dropped, not escaped.
        assertEquals("/api", SudokuProtocol.applyPathRoot("a/b", "/api"))
        assertEquals("/api", SudokuProtocol.applyPathRoot("../etc", "/api"))

        assertEquals("/ws?auth=T", SudokuProtocol.appendAuth("/ws", "T"))
        assertEquals("/ws?x=1&auth=T", SudokuProtocol.appendAuth("/ws?x=1", "T"))
    }

    // -------------------------------------------------------- key recovery

    @Test
    fun `base point multiplication agrees with RFC 8032`() {
        // RFC 8032 section 7.1: the public key is the clamped SHA-512 prefix of
        // the seed times the base point. Two of the document's own vectors.
        for ((seed, publicKey) in listOf(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" to
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb" to
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )) {
            val expanded = MessageDigest.getInstance("SHA-512").digest(fromHex(seed))
            val scalar = expanded.copyOf(32)
            scalar[0] = (scalar[0].toInt() and 248).toByte()
            scalar[31] = ((scalar[31].toInt() and 127) or 64).toByte()
            assertEquals(publicKey, hex(SudokuKeyRecovery.scalarBaseMultiply(scalar)))
        }

        // Scalar one is the base point itself and scalar zero the identity.
        assertEquals(
            "5866666666666666666666666666666666666666666666666666666666666666",
            hex(SudokuKeyRecovery.scalarBaseMultiply(bytes(1) + ByteArray(31)))
        )
        assertEquals(
            "0100000000000000000000000000000000000000000000000000000000000000",
            hex(SudokuKeyRecovery.scalarBaseMultiply(ByteArray(32)))
        )
    }

    @Test
    fun `the group order is the one Ed25519 uses`() {
        // 2^252 + 27742317777372353535851937790883648493, little-endian.
        assertEquals(32, SudokuKeyRecovery.GROUP_ORDER.size)
        assertEquals(
            "edd3f55c1a631258d69cf7a2def9de14" + "00".repeat(15) + "10",
            hex(SudokuKeyRecovery.GROUP_ORDER)
        )
    }

    @Test
    fun `an expanded private key recovers the public key both halves add up to`() {
        val expanded = ByteArray(64) { it.toByte() }
        assertEquals(
            "26be0d3449c2f1a4112a9a82a6f68c9f58817eec042d8b6c6af4d7b5cd1595cd",
            SudokuKeyRecovery.recoverPublicKeyHex(hex(expanded))
        )
        assertEquals(
            "334e2ec90dc719d659953c9359405d2940424446484a4c4e50525456585a5c4e",
            hex(SudokuKeyRecovery.scalarAdd(expanded.copyOf(32), expanded.copyOfRange(32, 64)))
        )

        // A 32-byte key is already public and comes back normalised.
        assertEquals(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            SudokuKeyRecovery.recoverPublicKeyHex(hex(ByteArray(32) { it.toByte() }).uppercase())
        )

        // Anything that is not a key is a passphrase; the caller uses it as-is.
        assertNull(SudokuKeyRecovery.recoverPublicKeyHex("hunter2"))
        assertNull(SudokuKeyRecovery.recoverPublicKeyHex(""))
        assertNull(SudokuKeyRecovery.recoverPublicKeyHex("abc"))
        assertNull(SudokuKeyRecovery.recoverPublicKeyHex("00".repeat(31)))
        assertNull(SudokuKeyRecovery.recoverPublicKeyHex("zz".repeat(32)))
    }

    // ------------------------------------------------------- configuration

    @Test
    fun `a configuration clamps its padding band and tidies its tables`() {
        val defaults = SudokuConfiguration(key = "  secret  ")
        assertEquals("secret", defaults.key)
        assertEquals(SudokuAeadMethod.CHACHA20_POLY1305, defaults.aeadMethod)
        assertEquals(5, defaults.paddingMin)
        assertEquals(15, defaults.paddingMax)
        assertEquals(SudokuAsciiMode.PREFER_ENTROPY, defaults.asciiMode)
        assertTrue(defaults.enablePureDownlink)
        assertEquals(SudokuMultiplex.OFF, defaults.multiplex)
        assertFalse(defaults.sendsTableHint)

        val clamped = SudokuConfiguration(key = "k", paddingMin = -10, paddingMax = 500)
        assertEquals(0, clamped.paddingMin)
        assertEquals(100, clamped.paddingMax)

        // A maximum under the minimum is raised to it rather than rejected.
        val inverted = SudokuConfiguration(key = "k", paddingMin = 40, paddingMax = 10)
        assertEquals(40, inverted.paddingMin)
        assertEquals(40, inverted.paddingMax)

        val tables = SudokuConfiguration(key = "k", customTables = listOf(" a ", "a", "", "b"))
        assertEquals(listOf("a", "b"), tables.customTables)
        assertTrue(tables.sendsTableHint)
        assertFalse(SudokuConfiguration(key = "k", customTables = listOf("a")).sendsTableHint)

        assertEquals(listOf("legacy"), SudokuConfiguration.normalizeCustomTables(listOf(" "), " legacy "))
        assertEquals(listOf("a"), SudokuConfiguration.normalizeCustomTables(listOf("a"), "legacy"))
        assertEquals(emptyList<String>(), SudokuConfiguration.normalizeCustomTables(emptyList(), ""))
    }

    @Test
    fun `the enums keep the spellings a subscription link uses`() {
        assertEquals("chacha20-poly1305", SudokuAeadMethod.CHACHA20_POLY1305.id)
        assertEquals("aes-128-gcm", SudokuAeadMethod.AES_128_GCM.id)
        assertEquals("none", SudokuAeadMethod.NONE.id)
        assertEquals(SudokuAeadMethod.AES_128_GCM, SudokuAeadMethod.fromId(" AES-128-GCM "))
        assertNull(SudokuAeadMethod.fromId("aes-256-gcm"))

        assertEquals("prefer_entropy", SudokuAsciiMode.PREFER_ENTROPY.id)
        assertEquals("prefer_ascii", SudokuAsciiMode.PREFER_ASCII.id)
        assertEquals("up_ascii_down_entropy", SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY.id)
        assertEquals("up_entropy_down_ascii", SudokuAsciiMode.UP_ENTROPY_DOWN_ASCII.id)
        assertEquals(SudokuAsciiMode.PREFER_ENTROPY, SudokuAsciiMode.fromNormalized(""))
        assertEquals(SudokuAsciiMode.PREFER_ENTROPY, SudokuAsciiMode.fromNormalized("entropy"))
        assertEquals(SudokuAsciiMode.PREFER_ASCII, SudokuAsciiMode.fromNormalized("ASCII"))
        assertEquals(
            SudokuAsciiMode.UP_ENTROPY_DOWN_ASCII,
            SudokuAsciiMode.fromNormalized(" up_entropy_down_ascii ")
        )
        assertNull(SudokuAsciiMode.fromNormalized("up_ascii_down_ascii"))
        assertEquals("entropy", SudokuAsciiMode.PREFER_ENTROPY.shortLinkToken)
        assertEquals("ascii", SudokuAsciiMode.PREFER_ASCII.shortLinkToken)
        assertEquals("up_ascii_down_entropy", SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY.shortLinkToken)

        assertEquals(SudokuMultiplex.OFF, SudokuMultiplex.fromNormalized("nonsense"))
        assertEquals(SudokuMultiplex.ON, SudokuMultiplex.fromNormalized(" ON "))
        assertEquals(SudokuMultiplex.AUTO, SudokuMultiplex.fromNormalized("auto"))
        assertEquals("OFF", SudokuMultiplex.OFF.displayName)

        assertEquals(SudokuHttpMaskMode.WS, SudokuHttpMaskMode.fromId("ws"))
        assertEquals(SudokuHttpMaskMode.LEGACY, SudokuHttpMaskMode.fromId("Legacy"))
        assertNull(SudokuHttpMaskMode.fromId("http3"))
    }

    @Test
    fun `each mode names a layout for each direction`() {
        assertEquals("entropy", SudokuAsciiMode.PREFER_ENTROPY.uplinkToken)
        assertEquals("entropy", SudokuAsciiMode.PREFER_ENTROPY.downlinkToken)
        assertEquals("ascii", SudokuAsciiMode.PREFER_ASCII.uplinkToken)
        assertEquals("ascii", SudokuAsciiMode.PREFER_ASCII.downlinkToken)
        assertEquals("ascii", SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY.uplinkToken)
        assertEquals("entropy", SudokuAsciiMode.UP_ASCII_DOWN_ENTROPY.downlinkToken)
        assertEquals("entropy", SudokuAsciiMode.UP_ENTROPY_DOWN_ASCII.uplinkToken)
        assertEquals("ascii", SudokuAsciiMode.UP_ENTROPY_DOWN_ASCII.downlinkToken)
    }

    @Test
    fun `a path root has to be one unreserved segment`() {
        assertEquals("cdn", SudokuHttpMaskConfiguration.normalizePathRoot("  /cdn/  "))
        assertEquals("a-b_9", SudokuHttpMaskConfiguration.normalizePathRoot("a-b_9"))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot(""))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot("///"))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot("a/b"))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot("a?b"))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot("a.b"))
        assertEquals("", SudokuHttpMaskConfiguration.normalizePathRoot("café"))

        val mask = SudokuHttpMaskConfiguration(host = "  cdn.example.com ", pathRoot = "/root/")
        assertEquals("cdn.example.com", mask.host)
        assertEquals("root", mask.pathRoot)
        assertEquals(SudokuHttpMaskMode.LEGACY, mask.mode)
        assertFalse(mask.disable)
        assertFalse(mask.tls)
    }

    private fun expectViolation(message: String, body: () -> Unit) {
        try {
            body()
            fail("expected \"$message\"")
        } catch (error: SudokuError.ProtocolViolation) {
            assertEquals(message, error.message)
        }
    }

    private companion object {
        const val CUSTOM_PATTERN = "xpvvxpvv"
    }
}
