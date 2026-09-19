package com.mythaia.vpn.protocol.hysteria

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hysteria2 obfuscation against fixed vectors rather than against itself.
 *
 * The chain is deliberate. First BouncyCastle's digest is pinned to the
 * published BLAKE2b-256 vectors, which establishes that the primitive is the
 * one the protocol names. Then the keystream is pinned to
 * `BLAKE2b-256(password ‖ salt)` for a fixed password and salt. Then whole
 * datagrams — salamander ones and gecko fragments alike — are built by hand
 * from those bytes and fed to `open`, so the decoder is exercised against
 * input this code never produced.
 *
 * That ordering matters because a round trip is nearly worthless here on its
 * own: hashing `salt ‖ password` instead of `password ‖ salt`, using
 * BLAKE2b-512 truncated, or cycling the key at the wrong period all round-trip
 * perfectly and all fail against a real server, which drops the packet without
 * saying anything.
 */
class HysteriaObfuscatorTest {

    private val password = "gecko-and-salamander"

    private fun bytes(hex: String) =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** The salt used for every hand-built salamander vector below: 00 01 .. 07. */
    private val salt = ByteArray(8) { it.toByte() }

    /**
     * BLAKE2b-256("gecko-and-salamander" ‖ 00 01 02 03 04 05 06 07).
     *
     * Computed with an independent BLAKE2b (Python's `hashlib.blake2b`,
     * `digest_size=32`), which the first test below cross-checks against the
     * published BLAKE2b-256 digests so the oracle itself is not taken on trust.
     */
    private val keystream =
        bytes("4b573de086e062590efde6ab76057f96c276f1ff61806ada148f8c209140da13")

    // MARK: The primitive

    @Test
    fun `bouncycastle blake2b-256 matches the published digests`() {
        // These two are the standard BLAKE2b-256 vectors. If this fails,
        // everything below is measuring the wrong hash.
        fun digest(input: ByteArray): ByteArray {
            val d = Blake2bDigest(256)
            d.update(input, 0, input.size)
            return ByteArray(32).also { d.doFinal(it, 0) }
        }
        assertEquals(
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
            hex(digest(ByteArray(0)))
        )
        assertEquals(
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
            hex(digest("abc".toByteArray()))
        )
    }

    // MARK: Salamander

    @Test
    fun `the keystream is blake2b-256 over password then salt`() {
        // XORing a run of zeroes leaves the keystream itself in the clear, so
        // this reads the derived key straight back out of the decoder.
        val obfuscator = SalamanderPacketObfuscator(password)
        val recovered = obfuscator.open(salt + ByteArray(32))!!
        assertArrayEquals(keystream, recovered)
    }

    @Test
    fun `the keystream cycles every 32 bytes, so a long packet reuses it`() {
        // Hand-built: 48 bytes of 0x00..0x2f XORed with the keystream, which
        // wraps back to its first byte at offset 32.
        val payload = ByteArray(48) { it.toByte() }
        val ciphertext = bytes(
            "4b563fe382e5645e06f4eca07a087199d267e3ec75957ccd0c96963b8d5dc40c" +
                "6b761fc3a2c5447e26d4cc805a2851b9"
        )
        val recovered = SalamanderPacketObfuscator(password).open(salt + ciphertext)!!
        assertArrayEquals(payload, recovered)

        // The wrap is the part a hand-rolled keystream gets wrong, so assert it
        // directly too: byte 32 of the stream equals byte 0.
        val stream = ByteArray(48) { (ciphertext[it].toInt() xor payload[it].toInt()).toByte() }
        assertArrayEquals(keystream, stream.copyOfRange(0, 32))
        assertArrayEquals(keystream.copyOfRange(0, 16), stream.copyOfRange(32, 48))
    }

    @Test
    fun `seal then open is the identity`() {
        val obfuscator = HysteriaObfuscator.of(HysteriaObfuscation.Salamander(password))
        for (size in intArrayOf(1, 16, 32, 33, 1200, 1500)) {
            val packet = ByteArray(size) { (it * 31 + 7).toByte() }
            val sealed = obfuscator.seal(packet)
            assertEquals(1, sealed.size)
            assertArrayEquals(packet, obfuscator.open(sealed[0]))
        }
    }

    @Test
    fun `a salamander datagram is exactly salt plus packet`() {
        val obfuscator = SalamanderPacketObfuscator(password)
        for (size in intArrayOf(1, 64, 1200)) {
            assertEquals(
                SalamanderObfuscator.SALT_LENGTH + size,
                obfuscator.seal(ByteArray(size))[0].size
            )
        }
    }

    @Test
    fun `a different password does not recover the packet`() {
        // Fixed bytes, so this is a statement about the key derivation and not
        // a lucky draw: the same datagram under the wrong password must not
        // come back as 0x00..0x2f.
        val payload = ByteArray(48) { it.toByte() }
        val datagram = salt + bytes(
            "4b563fe382e5645e06f4eca07a087199d267e3ec75957ccd0c96963b8d5dc40c" +
                "6b761fc3a2c5447e26d4cc805a2851b9"
        )
        val wrong = SalamanderPacketObfuscator("wrong-password").open(datagram)!!
        assertEquals(payload.size, wrong.size)
        assertFalse(wrong.contentEquals(payload))

        // And the failure is total, not a near miss: BLAKE2b-256 of the wrong
        // password with the same salt begins 0xa1, so the first byte comes out
        // 0x4b xor 0xa1 = 0xea instead of 0x00.
        assertEquals(0xea, wrong[0].toInt() and 0xFF)
    }

    // MARK: Gecko wire format

    private fun gecko(
        pw: String = password,
        min: Int = HysteriaObfuscation.GECKO_MIN_PACKET_SIZE_DEFAULT,
        max: Int = HysteriaObfuscation.GECKO_MAX_PACKET_SIZE_DEFAULT
    ) = GeckoObfuscator(pw, min, max)

    /** The 16-byte long-header packet the hand-built fragments below carry. */
    private val fragmentedPacket = bytes("c00102030405060708090a0b0c0d0e0f")

    /**
     * Fragment 0 of message 0x2a, 2 chunks, 3 bytes of padding, carrying
     * `c0 01 .. 07`.
     *
     * Built by hand as `80 2a 02 00 03 | aa bb cc | c001020304050607`, then
     * XORed with BLAKE2b-256(password ‖ 10*8) and prefixed with that salt.
     */
    private val handBuiltFragment0 =
        bytes("10101010101010100ee3dece31812ab3813ff3d3b1d690ab")

    /**
     * Fragment 1 of the same message: `80 2a 12 00 00 | 08090a0b0c0d0e0f`,
     * XORed with BLAKE2b-256(password ‖ 20*8) under that salt. No padding, to
     * cover the zero-pad path where the payload starts right after the header.
     */
    private val handBuiltFragment1 =
        bytes("20202020202020201b6d65d965c5af5fed871954dd")

    @Test
    fun `hand-built fragments reassemble into the original packet`() {
        val obfuscator = gecko()
        // The first fragment yields nothing: there is no packet to deliver yet.
        assertNull(obfuscator.open(handBuiltFragment0))
        assertArrayEquals(fragmentedPacket, obfuscator.open(handBuiltFragment1))
    }

    @Test
    fun `fragments arriving out of order still reassemble`() {
        // Reassembly is keyed by the index in the header, not by arrival order,
        // which is the only thing that makes this safe over UDP.
        val obfuscator = gecko()
        assertNull(obfuscator.open(handBuiltFragment1))
        assertArrayEquals(fragmentedPacket, obfuscator.open(handBuiltFragment0))
    }

    @Test
    fun `a repeated fragment is ignored rather than counted twice`() {
        val obfuscator = gecko()
        assertNull(obfuscator.open(handBuiltFragment0))
        assertNull(obfuscator.open(handBuiltFragment0))
        // If the duplicate had counted, the message would have "completed" here
        // holding a null second chunk.
        assertArrayEquals(fragmentedPacket, obfuscator.open(handBuiltFragment1))
    }

    @Test
    fun `an incomplete message yields nothing`() {
        assertNull(gecko().open(handBuiltFragment0))
    }

    @Test
    fun `a different password does not reassemble the fragments`() {
        val obfuscator = gecko(pw = "wrong-password")
        val results = listOfNotNull(
            obfuscator.open(handBuiltFragment0),
            obfuscator.open(handBuiltFragment1)
        )
        assertTrue(results.none { it.contentEquals(fragmentedPacket) })
    }

    // MARK: Gecko behaviour

    @Test
    fun `a long-header packet round trips through fragmentation`() {
        val sender = gecko()
        val receiver = gecko()
        val packet = ByteArray(1200) { (it * 13 + 5).toByte() }.also { it[0] = 0xC0.toByte() }

        repeat(50) {
            val datagrams = sender.seal(packet)
            assertTrue(datagrams.size in GeckoObfuscator.MIN_CHUNKS..GeckoObfuscator.MAX_CHUNKS)

            val delivered = datagrams.mapNotNull { receiver.open(it) }
            assertEquals(1, delivered.size)
            assertArrayEquals(packet, delivered[0])
        }
    }

    @Test
    fun `a short-header packet is not fragmented`() {
        // 1-RTT traffic reveals little on its own, so it rides salamander alone
        // rather than paying the per-fragment overhead.
        val obfuscator = gecko()
        val packet = ByteArray(600) { (it * 3).toByte() }.also { it[0] = 0x40 }
        val datagrams = obfuscator.seal(packet)
        assertEquals(1, datagrams.size)
        assertEquals(SalamanderObfuscator.SALT_LENGTH + packet.size, datagrams[0].size)
        assertArrayEquals(packet, obfuscator.open(datagrams[0]))
    }

    @Test
    fun `an empty packet produces no datagrams`() {
        assertTrue(gecko().seal(ByteArray(0)).isEmpty())
    }

    @Test
    fun `every fragment is padded into the configured size window`() {
        val obfuscator = gecko(min = 512, max = 1200)
        val packet = ByteArray(1200) { it.toByte() }.also { it[0] = 0xC0.toByte() }
        val counts = mutableSetOf<Int>()

        repeat(300) {
            val datagrams = obfuscator.seal(packet)
            counts += datagrams.size
            for (datagram in datagrams) {
                assertTrue("size ${datagram.size} outside 512..1200", datagram.size in 512..1200)
            }
        }
        // The whole 2..8 range should have been exercised; otherwise the bound
        // above was only checked for one chunk count.
        assertEquals((2..8).toSet(), counts)
    }

    @Test
    fun `a chunk larger than the maximum is sent unpadded rather than split again`() {
        // 8000 bytes over at most 8 chunks leaves every chunk above 600, so the
        // window is unreachable and padding must be skipped entirely. Sealed
        // size is then exactly salt + header + chunk.
        val obfuscator = gecko(min = 512, max = 600)
        val packet = ByteArray(8000) { it.toByte() }.also { it[0] = 0xC0.toByte() }

        repeat(50) {
            val datagrams = obfuscator.seal(packet)
            val overhead = SalamanderObfuscator.SALT_LENGTH + GeckoObfuscator.HEADER_LENGTH
            assertEquals(
                packet.size + overhead * datagrams.size,
                datagrams.sumOf { it.size }
            )
            assertTrue(datagrams.all { it.size > 600 })
        }
    }

    @Test
    fun `fragments of different messages do not bleed into each other`() {
        val sender = gecko()
        val receiver = gecko()
        val first = ByteArray(400) { it.toByte() }.also { it[0] = 0xC0.toByte() }
        val second = ByteArray(400) { (255 - it).toByte() }.also { it[0] = 0xC0.toByte() }

        val a = sender.seal(first)
        val b = sender.seal(second)
        // Interleaved, which is what a real network produces. The two messages
        // rarely have the same fragment count, so this cannot be a zip.
        val interleaved = ArrayList<ByteArray>(a.size + b.size)
        for (i in 0 until maxOf(a.size, b.size)) {
            a.getOrNull(i)?.let(interleaved::add)
            b.getOrNull(i)?.let(interleaved::add)
        }
        val delivered = interleaved.mapNotNull { receiver.open(it) }

        assertEquals(2, delivered.size)
        assertTrue(delivered.any { it.contentEquals(first) })
        assertTrue(delivered.any { it.contentEquals(second) })
    }

    @Test
    fun `a truncated or nonsensical fragment header is rejected`() {
        val obfuscator = gecko()
        val inner = SalamanderObfuscator(password)

        // A chunk count outside 2..8 cannot have come from a real sender; the
        // count lives in a nibble, so 0, 1 and 9..15 are all reachable by a
        // corrupted or hostile byte.
        for (total in intArrayOf(0, 1, 9, 15)) {
            val frame = byteArrayOf(0x80.toByte(), 0x01, total.toByte(), 0x00, 0x00, 0x11)
            assertNull("total=$total", obfuscator.open(inner.seal(frame)))
        }
        // An index at or beyond the count has nowhere to go.
        assertNull(
            obfuscator.open(inner.seal(byteArrayOf(0x80.toByte(), 0x02, 0x22, 0x00, 0x00, 0x11)))
        )
        // A pad length that runs off the end of the frame.
        assertNull(
            obfuscator.open(inner.seal(byteArrayOf(0x80.toByte(), 0x03, 0x02, 0x00, 0xFF.toByte())))
        )
        // Fewer bytes than the header itself.
        assertNull(obfuscator.open(inner.seal(byteArrayOf(0x80.toByte(), 0x04))))
        // Not even a salt.
        assertNull(obfuscator.open(ByteArray(4)))
    }

    @Test
    fun `a message id reused with a different chunk count starts over`() {
        // Otherwise a stale half-message would poison the id until it expired.
        val obfuscator = gecko()
        val inner = SalamanderObfuscator(password)
        fun fragment(msgId: Int, index: Int, total: Int, payload: ByteArray): ByteArray =
            inner.seal(
                byteArrayOf(
                    0x80.toByte(), msgId.toByte(), ((index shl 4) or total).toByte(), 0x00, 0x00
                ) + payload
            )

        assertNull(obfuscator.open(fragment(7, 0, 3, byteArrayOf(0x11))))
        // Same id, now claiming two chunks: the three-chunk attempt is dropped.
        assertNull(obfuscator.open(fragment(7, 0, 2, byteArrayOf(0x22))))
        assertArrayEquals(
            byteArrayOf(0x22, 0x33),
            obfuscator.open(fragment(7, 1, 2, byteArrayOf(0x33)))
        )
    }

    // MARK: Configuration

    @Test
    fun `gecko sizes fall back, clamp, and un-invert`() {
        val defaults = HysteriaObfuscation.GECKO_MIN_PACKET_SIZE_DEFAULT to
            HysteriaObfuscation.GECKO_MAX_PACKET_SIZE_DEFAULT

        assertEquals(defaults, HysteriaObfuscation.normalizedGeckoSizes(null, null))
        assertEquals(defaults, HysteriaObfuscation.normalizedGeckoSizes(0, 0))
        assertEquals(defaults, HysteriaObfuscation.normalizedGeckoSizes(-5, -1))

        assertEquals(100 to 900, HysteriaObfuscation.normalizedGeckoSizes(100, 900))
        // Clamped to the 0..2048 range.
        assertEquals(2048 to 2048, HysteriaObfuscation.normalizedGeckoSizes(9000, 9000))
        assertEquals(100 to 2048, HysteriaObfuscation.normalizedGeckoSizes(100, 99999))
        // An inverted maximum is raised to the minimum, not swapped with it.
        assertEquals(900 to 900, HysteriaObfuscation.normalizedGeckoSizes(900, 100))
    }

    @Test
    fun `a config is built from the wire tag`() {
        assertEquals(
            HysteriaObfuscation.Salamander("s3cret"),
            HysteriaObfuscation.make("salamander", "s3cret")
        )
        // Tags arrive from links and YAML in whatever case the author used.
        assertEquals(
            HysteriaObfuscation.Salamander("s3cret"),
            HysteriaObfuscation.make("SALAMANDER", "s3cret")
        )
        assertEquals(
            HysteriaObfuscation.Gecko("s3cret", 512, 1200),
            HysteriaObfuscation.make("Gecko", "s3cret")
        )
        assertEquals(
            HysteriaObfuscation.Gecko("s3cret", 300, 700),
            HysteriaObfuscation.make("gecko", "s3cret", 300, 700)
        )
        // Unknown, empty and absent types are all "the caller decides".
        assertNull(HysteriaObfuscation.make("chameleon", "s3cret"))
        assertNull(HysteriaObfuscation.make("", "s3cret"))
        assertNull(HysteriaObfuscation.make(null, "s3cret"))
        // A missing password is not an error here; it becomes empty.
        assertEquals("", HysteriaObfuscation.make("salamander", null)!!.password)
    }

    @Test
    fun `the wire tags are the ones the protocol names`() {
        assertEquals("salamander", HysteriaObfuscation.Salamander("x").typeTag)
        assertEquals("gecko", HysteriaObfuscation.Gecko("x", 512, 1200).typeTag)
    }

    @Test
    fun `the factory returns the mode the config asked for`() {
        assertTrue(
            HysteriaObfuscator.of(HysteriaObfuscation.Salamander(password))
                is SalamanderPacketObfuscator
        )
        val geckoConfig = HysteriaObfuscation.Gecko(password, 512, 1200)
        assertTrue(HysteriaObfuscator.of(geckoConfig) is GeckoObfuscator)
    }

    @Test
    fun `a password the reference would reject is refused at setup`() {
        // Failing here beats a connection that silently never completes.
        for (config in listOf(
            HysteriaObfuscation.Salamander("abc"),
            HysteriaObfuscation.Gecko("abc", 512, 1200)
        )) {
            try {
                HysteriaObfuscator.of(config)
                org.junit.Assert.fail("expected a refusal for ${config.typeTag}")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
    }
}
