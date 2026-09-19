package com.mythaia.vpn.protocol.tls.ech

import org.bouncycastle.crypto.hpke.HPKE
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class EchTest {

    // MARK: - Builders

    private fun u16(value: Int) = byteArrayOf(
        ((value shr 8) and 0xFF).toByte(), (value and 0xFF).toByte()
    )

    /** One ECHConfig record: version, length, body. */
    private fun record(
        version: Int = ECH_EXTENSION_CODEPOINT,
        configId: Int = 7,
        kemId: Int = EchKem.DHKEM_X25519_HKDF_SHA256,
        publicKey: ByteArray = ByteArray(32) { it.toByte() },
        suites: List<EchCipherSuite> = listOf(
            EchCipherSuite(EchKdf.HKDF_SHA256, EchAead.AES_GCM_128)
        ),
        maxNameLength: Int = 64,
        publicName: String = "public.example",
        extensions: ByteArray = ByteArray(0)
    ): ByteArray {
        val nameBytes = publicName.toByteArray(Charsets.UTF_8)
        val suiteBytes = suites.fold(ByteArray(0)) { acc, s -> acc + u16(s.kdfId) + u16(s.aeadId) }

        val body = byteArrayOf(configId.toByte()) +
            u16(kemId) +
            u16(publicKey.size) + publicKey +
            u16(suiteBytes.size) + suiteBytes +
            byteArrayOf(maxNameLength.toByte()) +
            byteArrayOf(nameBytes.size.toByte()) + nameBytes +
            u16(extensions.size) + extensions

        return u16(version) + u16(body.size) + body
    }

    private fun list(vararg records: ByteArray): ByteArray {
        val joined = records.fold(ByteArray(0)) { acc, r -> acc + r }
        return u16(joined.size) + joined
    }

    // MARK: - Parsing

    @Test
    fun `parses a config list`() {
        val configs = EchConfig.parseList(list(record()))
        assertEquals(1, configs.size)

        val config = configs.single()
        assertEquals(ECH_EXTENSION_CODEPOINT, config.version)
        assertEquals(7, config.configId)
        assertEquals(EchKem.DHKEM_X25519_HKDF_SHA256, config.kemId)
        assertEquals(32, config.publicKey.size)
        assertEquals(listOf(EchCipherSuite(EchKdf.HKDF_SHA256, EchAead.AES_GCM_128)), config.cipherSuites)
        assertEquals(64, config.maxNameLength)
        assertEquals("public.example", config.publicName)
        assertTrue(config.extensions.isEmpty())
    }

    @Test
    fun `raw keeps the record byte-exact, header included`() {
        // It feeds the HPKE info string; a re-serialised copy that differed
        // anywhere would derive a different key and the server would reject the
        // hello rather than fail visibly.
        val bytes = record()
        val config = EchConfig.parseList(list(bytes)).single()
        assertArrayEquals(bytes, config.raw)

        val info = EchClientContext.info(config)
        assertArrayEquals("tls ech".toByteArray() + byteArrayOf(0) + bytes, info)
    }

    @Test
    fun `a record of an unknown version is skipped, not rejected`() {
        // Forward compatibility: a list carrying a future version alongside a
        // usable one still works.
        val configs = EchConfig.parseList(list(record(version = 0xFE0C), record()))
        assertEquals(1, configs.size)
        assertEquals(ECH_EXTENSION_CODEPOINT, configs.single().version)
    }

    @Test
    fun `malformed lists are refused`() {
        for (bad in listOf(
            ByteArray(0),
            byteArrayOf(0),
            // Length field disagrees with the payload.
            u16(99) + record(),
            // Record runs past the end of the list.
            u16(6) + u16(ECH_EXTENSION_CODEPOINT) + u16(200) + byteArrayOf(1, 2),
        )) {
            try {
                EchConfig.parseList(bad)
                fail("expected EchError for ${bad.size} bytes")
            } catch (_: EchError) {
                // expected
            }
        }
    }

    @Test
    fun `trailing bytes in a record are refused`() {
        val good = record()
        // Grow the declared body length and append a stray byte.
        val bodyLength = ((good[2].toInt() and 0xFF) shl 8) or (good[3].toInt() and 0xFF)
        val tampered = good.copyOf(good.size + 1)
        tampered[2] = (((bodyLength + 1) shr 8) and 0xFF).toByte()
        tampered[3] = ((bodyLength + 1) and 0xFF).toByte()

        try {
            EchConfig.parseList(list(tampered))
            fail("expected EchError")
        } catch (_: EchError) {
            // expected
        }
    }

    // MARK: - Selection

    @Test
    fun `pick skips configs this build cannot use`() {
        val unusableKem = record(kemId = 0x0010)
        val unusableSuite = record(suites = listOf(EchCipherSuite(0x0099, 0x0099)))
        val badName = record(publicName = "not a hostname")
        val mandatoryExtension = record(extensions = u16(0x8001) + u16(0))
        val usable = record(configId = 42)

        val configs = EchConfig.parseList(
            list(unusableKem, unusableSuite, badName, mandatoryExtension, usable)
        )
        assertEquals(5, configs.size)

        val picked = EchConfig.pick(configs)
        assertNotNull(picked)
        assertEquals(42, picked!!.configId)
    }

    @Test
    fun `pick returns null when nothing is usable`() {
        assertNull(EchConfig.pick(EchConfig.parseList(list(record(kemId = 0x0010)))))
        assertNull(EchConfig.pick(emptyList()))
    }

    @Test
    fun `public names have to look like hostnames`() {
        // The public name goes out as the outer SNI in the clear; anything that
        // is not a plausible hostname would stand out.
        for (good in listOf("example.com", "a.b.c.example", "xn--80ak6aa92e.com", "A-b.example")) {
            assertTrue(good, EchConfig.isValidDnsName(good))
        }
        for (bad in listOf(
            "", "example", "example..com", ".example.com", "example.com.",
            "-bad.example", "bad-.example", "under_score.example", "a b.example",
            "x".repeat(254) + ".com"
        )) {
            assertTrue(bad, !EchConfig.isValidDnsName(bad))
        }
    }

    // MARK: - Base64

    @Test
    fun `config base64 tolerates url-safe and unpadded input`() {
        val raw = list(record())
        val padded = java.util.Base64.getEncoder().encodeToString(raw)
        val unpadded = padded.trimEnd('=')
        val urlSafe = padded.replace('+', '-').replace('/', '_')

        for (form in listOf(padded, unpadded, urlSafe, "  $padded  ")) {
            assertArrayEquals(form, raw, EchConfig.decodeBase64(form))
        }
        assertNull(EchConfig.decodeBase64(""))
        assertNull(EchConfig.decodeBase64("!!!"))
    }

    // MARK: - HPKE

    /**
     * Seals with our sender and opens with BouncyCastle's receiver.
     *
     * This is what proves the setup is right rather than merely
     * self-consistent: the receiver is code we did not write, driven straight
     * from the RFC 9180 API, and it only opens the message if the mode, suite,
     * info string and AAD all match.
     */
    @Test
    fun `a sealed inner hello opens with an independent receiver`() {
        val hpke = HPKE(
            HPKE.mode_base, HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128
        )
        val serverKeyPair = hpke.generatePrivateKey()
        val serverPublic = hpke.serializePublicKey(serverKeyPair.public)

        val config = EchConfig.parseList(list(record(publicKey = serverPublic))).single()
        val suite = config.pickCipherSuite()!!
        val context = EchClientContext.create(config, suite)

        val plaintext = "the inner ClientHello".toByteArray()
        val aad = "the outer ClientHello with a zeroed payload".toByteArray()
        val sealed = context.seal(plaintext, aad)

        assertEquals(plaintext.size + EchClientContext.AEAD_TAG_LENGTH, sealed.size)
        assertEquals(32, context.enc.size)

        val receiver = hpke.setupBaseR(context.enc, serverKeyPair, EchClientContext.info(config))
        assertArrayEquals(plaintext, receiver.open(aad, sealed))
    }

    @Test
    fun `the wrong AAD does not open`() {
        val hpke = HPKE(
            HPKE.mode_base, HPKE.kem_X25519_SHA256,
            HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128
        )
        val serverKeyPair = hpke.generatePrivateKey()
        val config = EchConfig.parseList(
            list(record(publicKey = hpke.serializePublicKey(serverKeyPair.public)))
        ).single()

        val context = EchClientContext.create(config, config.pickCipherSuite()!!)
        val sealed = context.seal("inner".toByteArray(), "outer".toByteArray())

        val receiver = hpke.setupBaseR(context.enc, serverKeyPair, EchClientContext.info(config))
        try {
            receiver.open("a different outer".toByteArray(), sealed)
            fail("expected the tag to fail")
        } catch (_: Exception) {
            // expected
        }
    }

    @Test
    fun `every supported cipher suite sets up`() {
        for (kdf in listOf(EchKdf.HKDF_SHA256, EchKdf.HKDF_SHA384, EchKdf.HKDF_SHA512)) {
            for (aead in listOf(
                EchAead.AES_GCM_128, EchAead.AES_GCM_256, EchAead.CHACHA20_POLY1305
            )) {
                val hpke = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, kdf.toShort(), aead.toShort())
                val keyPair = hpke.generatePrivateKey()
                val config = EchConfig.parseList(
                    list(
                        record(
                            publicKey = hpke.serializePublicKey(keyPair.public),
                            suites = listOf(EchCipherSuite(kdf, aead))
                        )
                    )
                ).single()

                val label = "kdf=$kdf aead=$aead"
                val suite = config.pickCipherSuite()
                assertNotNull(label, suite)

                val context = EchClientContext.create(config, suite!!)
                val sealed = context.seal("x".toByteArray(), "y".toByteArray())
                val receiver = hpke.setupBaseR(context.enc, keyPair, EchClientContext.info(config))
                assertArrayEquals(label, "x".toByteArray(), receiver.open("y".toByteArray(), sealed))
            }
        }
    }

    @Test
    fun `an unsupported suite is refused rather than silently downgraded`() {
        val config = EchConfig.parseList(list(record())).single()
        try {
            EchClientContext.create(config, EchCipherSuite(0x0099, EchAead.AES_GCM_128))
            fail("expected EchError")
        } catch (e: EchError) {
            assertTrue(e.message!!.contains("KDF"))
        }
    }

    @Test
    fun `a public key that is not an X25519 point is refused`() {
        val config = EchConfig.parseList(list(record(publicKey = ByteArray(5)))).single()
        try {
            EchClientContext.create(config, config.pickCipherSuite()!!)
            fail("expected EchError")
        } catch (_: EchError) {
            // expected
        }
    }

    // MARK: - Encoding

    @Test
    fun `the encoded inner hello is padded to a multiple of 32`() {
        // Two helloes for names of different lengths must come out the same
        // size, or the ciphertext length leaks what the encryption hides.
        val maxNameLength = 64
        val header = byteArrayOf(1, 0, 0, 0)   // handshake type + uint24 length

        // In a real hello the body grows with the name, so the padded length is
        // measured against a body that stands in for that growth.
        for (name in listOf("a.example", "much-longer-name.example", "x".repeat(40) + ".example")) {
            val nameLength = name.toByteArray().size
            val body = ByteArray(200 + nameLength)
            val encoded = EchEncryption.encodeInnerClientHello(header + body, name, maxNameLength)

            // Every name in this set produces the SAME padded length, which is
            // the property that stops the ciphertext length leaking it.
            assertEquals(name, 288, encoded.size)
            assertEquals(name, 0, encoded.size % 32)
        }

        // A name with nothing to hide pads as if for the longest one, so an
        // empty SNI is not distinguishable by length either.
        val empty = EchEncryption.encodeInnerClientHello(header + ByteArray(200), "", maxNameLength)
        assertEquals(0, empty.size % 32)
        assertTrue(empty.size >= 200 + maxNameLength + 9)
    }

    @Test
    fun `the encoded inner hello drops the handshake header`() {
        val body = ByteArray(64) { it.toByte() }
        val encoded = EchEncryption.encodeInnerClientHello(
            byteArrayOf(1, 0, 0, 64) + body, "a.example", 0
        )
        assertArrayEquals(body, encoded.copyOfRange(0, body.size))
        // Anything past the body is padding, and it is zeroes.
        assertTrue(encoded.drop(body.size).all { it == 0.toByte() })
    }

    @Test
    fun `a message too short to be a handshake message is refused`() {
        try {
            EchEncryption.encodeInnerClientHello(byteArrayOf(1, 0), "a.example", 32)
            fail("expected EchError")
        } catch (_: EchError) {
            // expected
        }
    }

    @Test
    fun `the outer extension body has the shape the server parses`() {
        val enc = ByteArray(32) { 0x11 }
        val payload = ByteArray(50) { 0x22 }
        val data = EchEncryption.outerExtensionData(
            configId = 7,
            kdfId = EchKdf.HKDF_SHA256,
            aeadId = EchAead.AES_GCM_128,
            enc = enc,
            payload = payload
        )

        var at = 0
        assertEquals(0x00.toByte(), data[at]); at += 1          // outer
        assertEquals(EchKdf.HKDF_SHA256, be16(data, at)); at += 2
        assertEquals(EchAead.AES_GCM_128, be16(data, at)); at += 2
        assertEquals(7, data[at].toInt() and 0xFF); at += 1
        assertEquals(enc.size, be16(data, at)); at += 2
        assertArrayEquals(enc, data.copyOfRange(at, at + enc.size)); at += enc.size
        assertEquals(payload.size, be16(data, at)); at += 2
        assertArrayEquals(payload, data.copyOfRange(at, at + payload.size)); at += payload.size
        assertEquals(data.size, at)
    }

    private fun be16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
}
