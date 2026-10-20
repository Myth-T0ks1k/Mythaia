package com.mythaia.vpn.protocol.vmess

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.bouncycastle.crypto.digests.SHAKEDigest
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class VmessTest {

    private val id: UUID = UUID.fromString("b831381d-6324-4d53-ad4f-8cda48b30811")

    // MARK: - KDF

    /**
     * With no path elements the KDF is plain HMAC-SHA256 under the root salt,
     * which `javax.crypto.Mac` computes independently — so this pins the
     * hand-written HMAC (block size, ipad/opad, key padding) rather than just
     * agreeing with itself.
     */
    @Test
    fun `the base case matches javax HMAC-SHA256`() {
        val key = "the key".toByteArray()
        val expected = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec("VMess AEAD KDF".toByteArray(), "HmacSHA256"))
            doFinal(key)
        }
        assertArrayEquals(expected, VmessKdf.kdf(key))
    }

    /**
     * One path element is HMAC keyed by that element, over a hash that is
     * itself the base HMAC. Written out here with explicit ipad/opad so the
     * nesting is checked against the RFC, not against the same code.
     */
    @Test
    fun `one path element nests HMAC over HMAC`() {
        val key = "the key".toByteArray()
        val path = "Some Salt".toByteArray()

        fun rootHmac(message: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec("VMess AEAD KDF".toByteArray(), "HmacSHA256"))
            doFinal(message)
        }

        val padded = ByteArray(64)
        path.copyInto(padded)
        val ipad = ByteArray(64) { (padded[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(64) { (padded[it].toInt() xor 0x5C).toByte() }

        val expected = rootHmac(opad + rootHmac(ipad + key))
        assertArrayEquals(expected, VmessKdf.kdf(key, path))
    }

    @Test
    fun `a path element longer than the block is reduced by the parent hash`() {
        // RFC 2104 replaces an over-long key with its hash — and the hash here
        // is the enclosing layer, not SHA-256, which is what Go's hmac.New does
        // with a custom hash function. Getting this wrong would only show up
        // against a real server, never in a self-consistent round trip.
        val longKey = ByteArray(100) { it.toByte() }
        val message = "msg".toByteArray()

        // The parent of a single-element path is the root HMAC, and kdf with no
        // path elements is exactly that.
        val reduced = VmessKdf.kdf(longKey)
        assertEquals(32, reduced.size)

        assertArrayEquals(
            VmessKdf.kdf(message, reduced),
            VmessKdf.kdf(message, longKey)
        )
        // ...and specifically NOT the plain SHA-256 reduction.
        assertNotEquals(
            VmessKdf.kdf(message, MessageDigest.getInstance("SHA-256").digest(longKey)).toList(),
            VmessKdf.kdf(message, longKey).toList()
        )
    }

    @Test
    fun `path elements are raw bytes, not text`() {
        // A non-UTF-8 byte must survive; encoding it on the way in would change
        // the derived key and break every handshake against a real server.
        val binary = byteArrayOf(0x00, 0xFF.toByte(), 0x80.toByte(), 0x7F)
        val a = VmessKdf.kdf("k".toByteArray(), binary)
        val b = VmessKdf.kdf("k".toByteArray(), String(binary, Charsets.ISO_8859_1).toByteArray(Charsets.UTF_8))
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun `kdf slices are prefixes of the full derivation`() {
        val key = "k".toByteArray()
        val full = VmessKdf.kdf(key, VmessKdf.salt("x"))
        assertArrayEquals(full.copyOfRange(0, 16), VmessKdf.kdf16(key, VmessKdf.salt("x")))
        assertArrayEquals(full.copyOfRange(0, 12), VmessKdf.kdf12(key, VmessKdf.salt("x")))
    }

    // MARK: - FNV-1a

    @Test
    fun `fnv1a matches its published vectors`() {
        assertEquals(-0x7ee3623b, VmessKdf.fnv1a32(ByteArray(0)))          // offset basis
        assertEquals(0xe40c292c.toInt(), VmessKdf.fnv1a32("a".toByteArray()))
        assertEquals(0xbf9cf968.toInt(), VmessKdf.fnv1a32("foobar".toByteArray()))
    }

    // MARK: - UUID bytes

    @Test
    fun `a UUID becomes its sixteen big-endian bytes`() {
        val bytes = VmessKdf.uuidBytes(id)
        assertEquals(16, bytes.size)
        assertEquals(0xb8.toByte(), bytes[0])
        assertEquals(0x31.toByte(), bytes[1])
        assertEquals(0x11.toByte(), bytes[15])
    }

    // MARK: - Request header

    @Test
    fun `a sealed request has the shape the server reads`() {
        val sealed = VmessProtocol.sealRequest(
            id, "example.com", 443, VmessProtocol.COMMAND_TCP, VmessSecurity.AES_128_GCM
        )
        // authID(16) + sealed length(2+16) + nonce(8) + sealed header(n+16).
        assertTrue(sealed.bytes.size > 16 + 18 + 8 + 16)
        assertEquals(16, sealed.session.requestBodyKey.size)
        assertEquals(16, sealed.session.requestBodyIv.size)
        assertEquals(16, sealed.session.responseBodyKey.size)
        assertEquals(16, sealed.session.responseBodyIv.size)
    }

    @Test
    fun `two requests never repeat their auth ID`() {
        val a = VmessProtocol.sealRequest(
            id, "example.com", 443, VmessProtocol.COMMAND_TCP, VmessSecurity.AES_128_GCM
        )
        val b = VmessProtocol.sealRequest(
            id, "example.com", 443, VmessProtocol.COMMAND_TCP, VmessSecurity.AES_128_GCM
        )
        // Replaying an auth ID is what a server rejects, so the randomness has
        // to actually be there.
        assertNotEquals(
            a.bytes.copyOfRange(0, 16).toList(),
            b.bytes.copyOfRange(0, 16).toList()
        )
    }

    @Test
    fun `the response body keys derive from the request's`() {
        val sealed = VmessProtocol.sealRequest(
            id, "example.com", 443, VmessProtocol.COMMAND_TCP, VmessSecurity.AES_128_GCM
        )
        val session = sealed.session
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(session.requestBodyKey).copyOfRange(0, 16),
            session.responseBodyKey
        )
        assertArrayEquals(
            MessageDigest.getInstance("SHA-256").digest(session.requestBodyIv).copyOfRange(0, 16),
            session.responseBodyIv
        )
    }

    // MARK: - Chunk stream

    private fun streams(security: VmessSecurity, masking: Boolean, padding: Boolean):
        Pair<VmessChunkStream, VmessChunkStream> {
        val key = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it * 3).toByte() }
        return VmessChunkStream(key, iv, security, masking, padding) to
            VmessChunkStream(key, iv, security, masking, padding)
    }

    @Test
    fun `chunks round-trip in every mode`() {
        for (security in listOf(
            VmessSecurity.AES_128_GCM, VmessSecurity.CHACHA20_POLY1305, VmessSecurity.NONE
        )) {
            for (masking in listOf(true, false)) {
                for (padding in listOf(true, false)) {
                    val label = "$security masking=$masking padding=$padding"
                    val (writer, reader) = streams(security, masking, padding)

                    val payloads = listOf(
                        "hello".toByteArray(),
                        ByteArray(1) { 7 },
                        ByteArray(5000) { (it % 251).toByte() }
                    )
                    var wire = ByteArray(0)
                    for (p in payloads) wire += writer.encode(p)

                    var at = 0
                    val received = ArrayList<ByteArray>()
                    while (at < wire.size) {
                        when (val decoded = reader.decode(wire, at)) {
                            is VmessChunkStream.Decoded.Chunk -> {
                                received.add(decoded.payload)
                                at += decoded.consumed
                            }
                            VmessChunkStream.Decoded.NeedMore -> fail("truncated at $at ($label)")
                            VmessChunkStream.Decoded.EndOfStream -> fail("unexpected end ($label)")
                        }
                    }
                    assertArrayEquals(
                        label,
                        payloads.reduce { a, b -> a + b },
                        received.reduce { a, b -> a + b }
                    )
                }
            }
        }
    }

    /**
     * Pins the draw ORDER against the reference, which a round trip cannot.
     *
     * Both ends of every other chunk test are this same class, so a wrong draw
     * order is symmetric and cancels out — the bug it hides only appears
     * against a real server. Here the expected length field is computed from a
     * SHAKE128 stream driven independently, in v2ray's order: the padding draw
     * first, then the mask draw.
     */
    @Test
    fun `the length field matches a stream driven in v2ray draw order`() {
        val key = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it * 3).toByte() }

        // The reference stream, read the way AuthenticationWriter.seal does.
        val reference = SHAKEDigest(128).apply { update(iv, 0, iv.size) }
        fun draw(): Int {
            val b = ByteArray(2)
            reference.doOutput(b, 0, 2)
            return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
        }

        val writer = VmessChunkStream(
            key, iv, VmessSecurity.AES_128_GCM, masking = true, globalPadding = true
        )
        val payload = "hello".toByteArray()
        val wire = writer.encode(payload)

        val paddingLength = draw() % 64
        val mask = draw()
        val sealedLength = payload.size + 16          // GCM tag
        val expected = (sealedLength + paddingLength) xor mask

        val actual = ((wire[0].toInt() and 0xFF) shl 8) or (wire[1].toInt() and 0xFF)
        assertEquals(
            "length field disagrees with the reference draw order",
            expected, actual
        )
        assertEquals(2 + sealedLength + paddingLength, wire.size)
    }

    /**
     * The same order on the read side, and that a chunk written by the
     * reference order decodes.
     */
    @Test
    fun `a chunk framed in reference order decodes`() {
        val key = ByteArray(16) { it.toByte() }
        val iv = ByteArray(16) { (it * 7).toByte() }
        val payload = "some payload".toByteArray()

        val reference = SHAKEDigest(128).apply { update(iv, 0, iv.size) }
        fun draw(): Int {
            val b = ByteArray(2)
            reference.doOutput(b, 0, 2)
            return ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
        }

        // Seal exactly as the peer would, then frame it by hand.
        val nonce = ByteArray(12).also { iv.copyInto(it, 2, 2, 12) }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, nonce)
        )
        val sealed = cipher.doFinal(payload)

        val paddingLength = draw() % 64
        val mask = draw()
        val onWire = sealed.size + paddingLength
        val length = onWire xor mask

        val wire = byteArrayOf(
            ((length shr 8) and 0xFF).toByte(),
            (length and 0xFF).toByte()
        ) + sealed + ByteArray(paddingLength)

        val reader = VmessChunkStream(
            key, iv, VmessSecurity.AES_128_GCM, masking = true, globalPadding = true
        )
        val decoded = reader.decode(wire, 0)
        assertTrue("expected a chunk, got $decoded", decoded is VmessChunkStream.Decoded.Chunk)
        decoded as VmessChunkStream.Decoded.Chunk
        assertArrayEquals(payload, decoded.payload)
        assertEquals(wire.size, decoded.consumed)
    }

    @Test
    fun `a partial chunk can be retried without losing the draw stream`() {
        // The mask and the chunk counter advance once per complete chunk. If a
        // short read consumed a draw, every later chunk would decode as garbage.
        val (writer, reader) = streams(VmessSecurity.AES_128_GCM, masking = true, padding = true)
        val payload = ByteArray(300) { it.toByte() }
        val wire = writer.encode(payload) + writer.encode(payload)

        for (cut in 1 until minOf(wire.size, 40)) {
            assertEquals(
                "cut=$cut",
                VmessChunkStream.Decoded.NeedMore,
                VmessChunkStream(
                    ByteArray(16) { it.toByte() }, ByteArray(16) { (it * 3).toByte() },
                    VmessSecurity.AES_128_GCM, true, true
                ).decode(wire.copyOfRange(0, cut), 0)
            )
        }

        var at = 0
        repeat(2) {
            val decoded = reader.decode(wire, at)
            assertTrue(decoded is VmessChunkStream.Decoded.Chunk)
            decoded as VmessChunkStream.Decoded.Chunk
            assertArrayEquals(payload, decoded.payload)
            at += decoded.consumed
        }
        assertEquals(wire.size, at)
    }

    @Test
    fun `an empty payload writes nothing, and the terminator ends the stream`() {
        val (writer, reader) = streams(VmessSecurity.AES_128_GCM, masking = true, padding = true)
        // An empty chunk IS the end-of-stream marker, so encode must not emit
        // one by accident.
        assertEquals(0, writer.encode(ByteArray(0)).size)

        val wire = writer.encodeTerminator()
        assertEquals(VmessChunkStream.Decoded.EndOfStream, reader.decode(wire, 0))
    }

    @Test
    fun `a chunk as large as the length field allows is accepted`() {
        // sing-box frames 16384-byte chunks; the field is sixteen bits, so a
        // peer may send up to 65535. Rejecting either as "not plausible" broke
        // the stream on its first large download chunk.
        val reader = VmessChunkStream(
            ByteArray(16) { it.toByte() }, ByteArray(16) { (it * 3).toByte() },
            VmessSecurity.NONE, masking = false, globalPadding = false
        )
        val payload = ByteArray(16384) { (it % 251).toByte() }
        val wire = byteArrayOf(0x40, 0x00) + payload
        val decoded = reader.decode(wire, 0)
        assertTrue("expected a chunk, got $decoded", decoded is VmessChunkStream.Decoded.Chunk)
        decoded as VmessChunkStream.Decoded.Chunk
        assertArrayEquals(payload, decoded.payload)
        assertEquals(wire.size, decoded.consumed)

        // The field's maximum is waited for, not refused.
        assertEquals(
            VmessChunkStream.Decoded.NeedMore,
            reader.decode(byteArrayOf(0xFF.toByte(), 0xFF.toByte()) + ByteArray(10), 0)
        )
    }

    @Test
    fun `a tampered chunk fails authentication rather than decoding`() {
        val (writer, reader) = streams(VmessSecurity.AES_128_GCM, masking = false, padding = false)
        val wire = writer.encode("secret".toByteArray())
        // Flip a bit in the ciphertext, past the two-byte length.
        wire[4] = (wire[4].toInt() xor 0x01).toByte()

        try {
            reader.decode(wire, 0)
            fail("expected a protocol error")
        } catch (_: ProxyError.ProtocolError) {
            // expected
        }
    }

    // MARK: - Links

    @Test
    fun `parses a v2rayN vmess link`() {
        val json = """
            {"v":"2","ps":"Tokyo","add":"example.com","port":"443","id":"$id",
             "aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com",
             "path":"/ray","tls":"tls","sni":"cdn.example.com"}
        """.trimIndent()
        val link = "vmess://" + java.util.Base64.getEncoder()
            .encodeToString(json.toByteArray(Charsets.UTF_8))

        val config = ProxyConfiguration.fromUrl(link)
        assertEquals(OutboundProtocol.VMESS, config.outboundProtocol)
        assertEquals("Tokyo", config.name)
        assertEquals("example.com", config.serverAddress)
        assertEquals(443.toUShort(), config.serverPort)
        assertEquals(id, config.uuid)
        assertEquals("ws", config.transport)
        assertEquals("tls", config.security)
        assertEquals("cdn.example.com", config.tls?.serverName)
        assertEquals("/ray", config.websocket?.path)
        assertEquals("cdn.example.com", config.websocket?.host)
        // "auto" is not a cipher; it means "let the client choose".
        assertNull(config.vmessSecurity)
    }

    @Test
    fun `base64 without padding or in the URL alphabet still decodes`() {
        val json = """{"v":"2","ps":"N","add":"example.com","port":"443","id":"$id","aid":"0"}"""
        val padded = java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        val unpadded = padded.trimEnd('=')
        val urlSafe = padded.replace('+', '-').replace('/', '_')

        for (form in listOf(padded, unpadded, urlSafe)) {
            val config = ProxyConfiguration.fromUrl("vmess://$form")
            assertEquals(form, "example.com", config.serverAddress)
        }
    }

    @Test
    fun `a non-zero alterId is coerced to zero for AEAD compatibility`() {
        val json = """{"v":"2","ps":"N","add":"example.com","port":"443","id":"$id","aid":"64"}"""
        val link = "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        val config = ProxyConfiguration.fromUrl(link)
        assertEquals(OutboundProtocol.VMESS, config.outboundProtocol)
        assertEquals("example.com", config.serverAddress)
        assertEquals(id, config.uuid)
    }

    @Test
    fun `malformed links are rejected cleanly`() {
        for (link in listOf(
            "vmess://",
            "vmess://!!!not base64!!!",
            "vmess://" + java.util.Base64.getEncoder().encodeToString("not json".toByteArray()),
            "vmess://" + java.util.Base64.getEncoder()
                .encodeToString("""{"add":"example.com"}""".toByteArray())
        )) {
            try {
                ProxyConfiguration.fromUrl(link)
                fail("expected InvalidUrl for $link")
            } catch (_: ProxyError.InvalidUrl) {
                // expected
            }
        }
    }

    @Test
    fun `a vmess config round-trips through its link`() {
        val json = """
            {"v":"2","ps":"Tokyo","add":"example.com","port":"443","id":"$id",
             "aid":"0","scy":"chacha20-poly1305","net":"ws","host":"cdn.example.com",
             "path":"/ray","tls":"tls","sni":"cdn.example.com"}
        """.trimIndent()
        val original = ProxyConfiguration.fromUrl(
            "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        )
        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())

        assertEquals(original.name, reparsed.name)
        assertEquals(original.serverAddress, reparsed.serverAddress)
        assertEquals(original.serverPort, reparsed.serverPort)
        assertEquals(original.uuid, reparsed.uuid)
        assertEquals(original.transport, reparsed.transport)
        assertEquals(original.security, reparsed.security)
        assertEquals(original.vmessSecurity, reparsed.vmessSecurity)
        assertEquals(original.websocket?.path, reparsed.websocket?.path)
        assertEquals(original.websocket?.host, reparsed.websocket?.host)
        assertEquals(original.tls?.serverName, reparsed.tls?.serverName)
    }

    @Test
    fun `security names map to their protocol ids and wire ids`() {
        assertEquals(0x02, VmessSecurity.AUTO.id)
        assertEquals(0x03, VmessSecurity.AES_128_GCM.id)
        assertEquals(0x04, VmessSecurity.CHACHA20_POLY1305.id)
        assertEquals(0x05, VmessSecurity.NONE.id)
        assertEquals(0x06, VmessSecurity.ZERO.id)
        assertEquals(0x05, VmessSecurity.ZERO.wireId)
        assertEquals(VmessSecurity.AES_128_GCM, VmessSecurity.fromRaw("auto"))
        assertEquals(VmessSecurity.AES_128_GCM, VmessSecurity.AUTO.resolve())
        assertEquals(VmessSecurity.AES_128_GCM, VmessSecurity.fromRaw(null))
        assertEquals(VmessSecurity.CHACHA20_POLY1305, VmessSecurity.fromRaw("chacha20-ietf-poly1305"))
        assertEquals(VmessSecurity.NONE, VmessSecurity.fromRaw("none"))
        assertEquals(VmessSecurity.ZERO, VmessSecurity.fromRaw("zero"))

        assertEquals(0, VmessProtocol.optionsFor(VmessSecurity.ZERO))
        assertEquals(VmessProtocol.OPTION_CHUNK_STREAM, VmessProtocol.optionsFor(VmessSecurity.NONE))
        assertEquals(
            VmessProtocol.OPTION_CHUNK_STREAM or
                VmessProtocol.OPTION_CHUNK_MASKING or
                VmessProtocol.OPTION_GLOBAL_PADDING,
            VmessProtocol.optionsFor(VmessSecurity.AES_128_GCM, authenticatedLength = false)
        )
        assertEquals(
            VmessProtocol.OPTION_CHUNK_STREAM or
                VmessProtocol.OPTION_CHUNK_MASKING or
                VmessProtocol.OPTION_GLOBAL_PADDING or
                VmessProtocol.OPTION_AUTHENTICATED_LENGTH,
            VmessProtocol.optionsFor(VmessSecurity.AES_128_GCM, authenticatedLength = true)
        )
    }

    @Test
    fun `authenticated length chunks round-trip in AES-128-GCM and ChaCha20-Poly1305`() {
        for (security in listOf(VmessSecurity.AES_128_GCM, VmessSecurity.CHACHA20_POLY1305)) {
            for (padding in listOf(true, false)) {
                val key = ByteArray(16) { (it + 1).toByte() }
                val iv = ByteArray(16) { (it * 5 + 3).toByte() }
                val writer = VmessChunkStream(
                    key = key,
                    iv = iv,
                    security = security,
                    masking = true,
                    globalPadding = padding,
                    authenticatedLength = true
                )
                val reader = VmessChunkStream(
                    key = key,
                    iv = iv,
                    security = security,
                    masking = true,
                    globalPadding = padding,
                    authenticatedLength = true
                )

                val payloads = listOf(
                    "auth-len-hello".toByteArray(),
                    ByteArray(1) { 42 },
                    ByteArray(4096) { (it % 251).toByte() }
                )
                var wire = ByteArray(0)
                for (p in payloads) wire += writer.encode(p)
                wire += writer.encodeTerminator()

                var at = 0
                val received = ArrayList<ByteArray>()
                var ended = false
                while (at < wire.size) {
                    when (val decoded = reader.decode(wire, at)) {
                        is VmessChunkStream.Decoded.Chunk -> {
                            received.add(decoded.payload)
                            at += decoded.consumed
                        }
                        VmessChunkStream.Decoded.EndOfStream -> {
                            ended = true
                            break
                        }
                        VmessChunkStream.Decoded.NeedMore -> fail("truncated at $at ($security padding=$padding)")
                    }
                }
                assertTrue("expected EndOfStream ($security padding=$padding)", ended)
                assertArrayEquals(
                    payloads.reduce { a, b -> a + b },
                    received.reduce { a, b -> a + b }
                )
            }
        }
    }

    @Test
    fun `zero security leaves request option zero and passes body unchunked`() {
        val sealed = VmessProtocol.sealRequest(
            id, "example.com", 443, VmessProtocol.COMMAND_TCP, VmessSecurity.ZERO
        )
        assertEquals(0, sealed.session.option)
        assertEquals(VmessSecurity.ZERO, sealed.session.security)

        val sent = ArrayList<ByteArray>()
        val inbound = ArrayDeque<ByteArray>()

        // Craft a valid AEAD response header from the server for this session.
        val respPlain = byteArrayOf(sealed.session.responseHeader, 0, 0, 0)
        val respLenKey = VmessKdf.kdf16(sealed.session.responseBodyKey, VmessKdf.salt(VmessKdf.SALT_RESP_HEADER_LEN_KEY))
        val respLenIv = VmessKdf.kdf12(sealed.session.responseBodyIv, VmessKdf.salt(VmessKdf.SALT_RESP_HEADER_LEN_IV))
        val respKey = VmessKdf.kdf16(sealed.session.responseBodyKey, VmessKdf.salt(VmessKdf.SALT_RESP_HEADER_PAYLOAD_KEY))
        val respIv = VmessKdf.kdf12(sealed.session.responseBodyIv, VmessKdf.salt(VmessKdf.SALT_RESP_HEADER_PAYLOAD_IV))
        val lenCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                SecretKeySpec(respLenKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, respLenIv)
            )
        }
        val payloadCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                SecretKeySpec(respKey, "AES"),
                javax.crypto.spec.GCMParameterSpec(128, respIv)
            )
        }
        val sealedRespHeader = lenCipher.doFinal(byteArrayOf(0, 4)) + payloadCipher.doFinal(respPlain)
        val serverPayload = "raw unchunked reply".toByteArray()
        inbound.add(sealedRespHeader + serverPayload)

        val transport = object : com.mythaia.vpn.protocol.Transport {
            override suspend fun send(data: ByteArray) { sent.add(data) }
            override fun sendAsync(data: ByteArray) { sent.add(data) }
            override suspend fun receive(): ByteArray? = if (inbound.isEmpty()) null else inbound.removeFirst()
            override fun forceCancel() {}
        }

        val conn = VmessConnection(transport, sealed.session, sealed.bytes)
        kotlinx.coroutines.runBlocking {
            val clientPayload = "raw unchunked request".toByteArray()
            conn.send(clientPayload)
            assertEquals(1, sent.size)
            // First write is exact header + raw clientPayload (no 2-byte chunk length prefix).
            assertArrayEquals(sealed.bytes + clientPayload, sent[0])

            val reply = conn.receive()
            assertArrayEquals(serverPayload, reply)

            conn.cancel()
            // Cancelling a ZERO stream must not emit a 2-byte 0x0000 chunk terminator.
            assertEquals(1, sent.size)
        }
    }

    @Test
    fun `vmess xhttp and reality links round-trip through v2rayN JSON and standard URI`() {
        val pbk = "YsP5Y9uw0OTS6d1DXoDZH33a2CBIfsVid9j_3DPZcxc"
        val sid = "0123456789abcdef"
        val extra = """{"noGRPCHeader":true,"noSSEHeader":true,"scMaxBufferedPosts":40,"scStreamUpServerSecs":"15-30","headers":{"X-Test":"1"}}"""
        val json = org.json.JSONObject().apply {
            put("v", "2")
            put("ps", "VMess-XHTTP-Reality")
            put("add", "example.com")
            put("port", "443")
            put("id", id.toString())
            put("aid", "0")
            put("scy", "zero")
            put("net", "xhttp")
            put("type", "stream-one")
            put("host", "cdn.example.com")
            put("path", "/xhttp")
            put("extra", extra)
            put("tls", "reality")
            put("sni", "www.microsoft.com")
            put("fp", "chrome")
            put("pbk", pbk)
            put("sid", sid)
        }
        val link = "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toString().toByteArray())
        val parsed = ProxyConfiguration.fromUrl(link)
        assertEquals(OutboundProtocol.VMESS, parsed.outboundProtocol)
        assertEquals("xhttp", parsed.transport)
        assertEquals("reality", parsed.security)
        assertEquals("zero", parsed.vmessSecurity)
        assertEquals(com.mythaia.data.model.XHttpMode.STREAM_ONE, parsed.xhttp?.mode)
        assertEquals("/xhttp", parsed.xhttp?.path)
        assertEquals("cdn.example.com", parsed.xhttp?.host)
        assertEquals(true, parsed.xhttp?.noGrpcHeader)
        assertEquals(true, parsed.xhttp?.noSseHeader)
        assertEquals(40, parsed.xhttp?.scMaxBufferedPosts)
        assertEquals(15, parsed.xhttp?.scStreamUpServerSecsFrom)
        assertEquals(30, parsed.xhttp?.scStreamUpServerSecsTo)
        assertEquals("www.microsoft.com", parsed.reality?.serverName)

        val reparsed = ProxyConfiguration.fromUrl(parsed.toUrl())
        assertEquals(parsed.name, reparsed.name)
        assertEquals(parsed.transport, reparsed.transport)
        assertEquals(parsed.security, reparsed.security)
        assertEquals(parsed.vmessSecurity, reparsed.vmessSecurity)
        assertEquals(parsed.xhttp?.mode, reparsed.xhttp?.mode)
        assertEquals(parsed.xhttp?.path, reparsed.xhttp?.path)
        assertEquals(parsed.xhttp?.noGrpcHeader, reparsed.xhttp?.noGrpcHeader)
        assertEquals(parsed.xhttp?.noSseHeader, reparsed.xhttp?.noSseHeader)
        assertEquals(parsed.xhttp?.scMaxBufferedPosts, reparsed.xhttp?.scMaxBufferedPosts)
        assertEquals(parsed.xhttp?.scStreamUpServerSecsFrom, reparsed.xhttp?.scStreamUpServerSecsFrom)
        assertEquals(parsed.xhttp?.scStreamUpServerSecsTo, reparsed.xhttp?.scStreamUpServerSecsTo)
        assertEquals(parsed.reality?.serverName, reparsed.reality?.serverName)
        assertArrayEquals(parsed.reality?.publicKey, reparsed.reality?.publicKey)
        assertArrayEquals(parsed.reality?.shortId, reparsed.reality?.shortId)

        // Standard URI format: vmess://uuid@host:port?...#name
        val stdUri = "vmess://$id@example.com:443?type=xhttp&encryption=chacha20-poly1305" +
            "&security=reality&pbk=$pbk&sid=$sid&sni=www.microsoft.com&path=%2Fxh&mode=packet-up#StdVMess"
        val stdParsed = ProxyConfiguration.fromUrl(stdUri)
        assertEquals(OutboundProtocol.VMESS, stdParsed.outboundProtocol)
        assertEquals("StdVMess", stdParsed.name)
        assertEquals("xhttp", stdParsed.transport)
        assertEquals("reality", stdParsed.security)
        assertEquals("chacha20-poly1305", stdParsed.vmessSecurity)
        assertEquals(com.mythaia.data.model.XHttpMode.PACKET_UP, stdParsed.xhttp?.mode)
        assertEquals("/xh", stdParsed.xhttp?.path)
    }

    @Test
    fun `xhttp extra JSON preserves sessionIDPlacement aliases xmux and downloadSettings`() {
        val extra = """
            {
              "sessionIDPlacement": "header",
              "sessionIDKey": "X-Session-ID",
              "seqPlacement": "cookie",
              "seqKey": "seq_id",
              "uplinkDataPlacement": "body",
              "xmux": {"maxConcurrency": "8-16", "maxConnections": 2},
              "downloadSettings": {
                "address": "down.example.com",
                "port": 8443,
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": "down.example.com", "allowInsecure": true},
                "xhttpSettings": {"path": "/down", "host": "down.example.com", "mode": "stream-up"}
              }
            }
        """.trimIndent()
        val xhttp = com.mythaia.data.model.XHttpConfiguration.fromExtraJson(
            host = "up.example.com",
            path = "/up",
            mode = com.mythaia.data.model.XHttpMode.PACKET_UP,
            extraJson = extra
        )
        assertEquals(com.mythaia.data.model.XHttpPlacement.HEADER, xhttp.sessionPlacement)
        assertEquals("X-Session-ID", xhttp.sessionKey)
        assertEquals(com.mythaia.data.model.XHttpPlacement.COOKIE, xhttp.seqPlacement)
        assertEquals("seq_id", xhttp.seqKey)
        assertEquals(com.mythaia.data.model.XHttpPlacement.BODY, xhttp.uplinkDataPlacement)

        val roundTripped = com.mythaia.data.model.XHttpConfiguration.fromExtraJson(
            host = xhttp.host,
            path = xhttp.path,
            mode = xhttp.mode,
            extraJson = xhttp.toExtraJson()
        )
        assertEquals(xhttp.sessionPlacement, roundTripped.sessionPlacement)
        assertEquals(xhttp.sessionKey, roundTripped.sessionKey)
        assertEquals(xhttp.xmuxJson, roundTripped.xmuxJson)
        assertEquals(xhttp.downloadSettingsJson, roundTripped.downloadSettingsJson)

        val parent = ProxyConfiguration(
            name = "Parent",
            serverAddress = "up.example.com",
            serverPort = 443u,
            uuid = id,
            encryption = "none",
            outboundProtocol = OutboundProtocol.VMESS,
            transport = "xhttp",
            security = "tls",
            xhttp = xhttp
        )
        val resolved = roundTripped.resolveDownloadConfiguration(parent)
        org.junit.Assert.assertNotNull(resolved)
        val (downProxy, downXhttp) = resolved!!
        assertEquals("down.example.com", downProxy.serverAddress)
        assertEquals(8443.toUShort(), downProxy.serverPort)
        assertEquals("tls", downProxy.security)
        assertEquals("down.example.com", downProxy.tls?.serverName)
        assertEquals(true, downProxy.tls?.allowInsecure)
        assertEquals("/down", downXhttp.path)
        assertEquals("down.example.com", downXhttp.host)
    }

    @Test
    fun `ClashProxyParser parses VMess with xhttp reality and non-zero alterId`() {
        val pbk = "YsP5Y9uw0OTS6d1DXoDZH33a2CBIfsVid9j_3DPZcxc"
        val doc = org.json.JSONObject(
            """
            {
              "proxies": [
                {
                  "name": "vmess-xhttp-reality",
                  "type": "vmess",
                  "server": "example.com",
                  "port": 443,
                  "uuid": "$id",
                  "alterId": 16,
                  "cipher": "zero",
                  "tls": true,
                  "servername": "www.microsoft.com",
                  "client-fingerprint": "chrome",
                  "network": "xhttp",
                  "reality-opts": {
                    "public-key": "$pbk",
                    "short-id": "0123456789abcdef"
                  },
                  "xhttp-opts": {
                    "path": "/xh",
                    "host": "cdn.example.com",
                    "mode": "packet-up",
                    "no-grpc-header": true
                  }
                }
              ]
            }
            """.trimIndent()
        )
        val configs = com.mythaia.data.network.ClashProxyParser.parseDocument(doc).configurations
        assertEquals(1, configs.size)
        val c = configs[0]
        assertEquals(OutboundProtocol.VMESS, c.outboundProtocol)
        assertEquals("vmess-xhttp-reality", c.name)
        assertEquals("xhttp", c.transport)
        assertEquals("reality", c.security)
        assertEquals("zero", c.vmessSecurity)
        assertEquals("/xh", c.xhttp?.path)
        assertEquals("cdn.example.com", c.xhttp?.host)
        assertEquals(com.mythaia.data.model.XHttpMode.PACKET_UP, c.xhttp?.mode)
        assertEquals(true, c.xhttp?.noGrpcHeader)
        assertEquals("www.microsoft.com", c.reality?.serverName)
    }

    @Test
    fun `live Xray integration tests for VMess over XHTTP`() {
        val binaries = listOfNotNull(
            System.getenv("MYTHAIA_XRAY")?.takeIf { it.isNotBlank() }?.let { java.io.File(it) },
            System.getenv("XRAY")?.takeIf { it.isNotBlank() }?.let { java.io.File(it) }
        ).distinctBy { it.canonicalPath }.filter { it.isFile }
        org.junit.Assume.assumeTrue("No local xray binary found for live test", binaries.isNotEmpty())

        // Start a local TCP echo server that echoes every chunk back and closes when client half-closes or sends "EOF".
        val echoServer = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
        val echoPort = echoServer.localPort
        val echoThread = Thread {
            try {
                while (!echoServer.isClosed) {
                    val client = try { echoServer.accept() } catch (_: Exception) { break }
                    Thread {
                        client.use { sock ->
                            sock.soTimeout = 10_000
                            val inp = sock.getInputStream()
                            val out = sock.getOutputStream()
                            val buf = ByteArray(16384)
                            while (true) {
                                val n = try { inp.read(buf) } catch (_: Exception) { -1 }
                                if (n <= 0) break
                                out.write(buf, 0, n)
                                out.flush()
                            }
                        }
                    }.apply { isDaemon = true }.start()
                }
            } catch (_: Exception) {}
        }.apply { isDaemon = true; start() }

        try {
            for (xrayBin in binaries) {
                runXrayMatrix(xrayBin, echoPort)
            }
        } finally {
            runCatching { echoServer.close() }
            echoThread.join(1000)
        }
    }

    private fun freePort(): Int =
        java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }

    private fun runXrayMatrix(xrayBin: java.io.File, echoPort: Int) {
        // Generate TLS certificate via `xray tls cert --domain=localhost`
        val certProc = ProcessBuilder(xrayBin.absolutePath, "tls", "cert", "--domain=localhost")
            .redirectErrorStream(true)
            .start()
        val certJsonText = certProc.inputStream.bufferedReader().readText()
        certProc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)
        val certObj = org.json.JSONObject(certJsonText.substring(certJsonText.indexOf('{')).trim())

        val realityPrivateKey = "aLU54PDyo85Mn2JietGWthdOImxFonHn3jq7_hmPOUQ"
        val realityPublicKey = "YsP5Y9uw0OTS6d1DXoDZH33a2CBIfsVid9j_3DPZcxc"
        val realityShortId = "0123456789abcdef"

        val portPlain = freePort()
        val portPlacement = freePort()
        val portTls = freePort()
        val portReality = freePort()

        val configJson = org.json.JSONObject().apply {
            put("log", org.json.JSONObject().put("loglevel", "warning"))
            put(
                "inbounds",
                org.json.JSONArray()
                    .put(
                        org.json.JSONObject()
                            .put("tag", "in-plain")
                            .put("listen", "127.0.0.1")
                            .put("port", portPlain)
                            .put("protocol", "vmess")
                            .put(
                                "settings",
                                org.json.JSONObject().put(
                                    "clients",
                                    org.json.JSONArray().put(org.json.JSONObject().put("id", id.toString()))
                                )
                            )
                            .put(
                                "streamSettings",
                                org.json.JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "none")
                                    .put(
                                        "xhttpSettings",
                                        org.json.JSONObject()
                                            .put("path", "/xh")
                                            .put("mode", "auto")
                                    )
                            )
                    )
                    .put(
                        org.json.JSONObject()
                            .put("tag", "in-placement")
                            .put("listen", "127.0.0.1")
                            .put("port", portPlacement)
                            .put("protocol", "vmess")
                            .put(
                                "settings",
                                org.json.JSONObject().put(
                                    "clients",
                                    org.json.JSONArray().put(org.json.JSONObject().put("id", id.toString()))
                                )
                            )
                            .put(
                                "streamSettings",
                                org.json.JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "none")
                                    .put(
                                        "xhttpSettings",
                                        org.json.JSONObject()
                                            .put("path", "/custom")
                                            .put("mode", "packet-up")
                                            .put(
                                                "extra",
                                                org.json.JSONObject()
                                                    .put("sessionIDPlacement", "header")
                                                    .put("sessionIDKey", "X-My-Session")
                                                    .put("seqPlacement", "cookie")
                                                    .put("seqKey", "my_seq")
                                                    .put("uplinkDataPlacement", "header")
                                                    .put("uplinkDataKey", "X-Up-Data")
                                                    .put("uplinkChunkSize", 256)
                                                    .put("serverMaxHeaderBytes", 65536)
                                                    .put("noSSEHeader", true)
                                            )
                                    )
                            )
                    )
                    .put(
                        org.json.JSONObject()
                            .put("tag", "in-tls")
                            .put("listen", "127.0.0.1")
                            .put("port", portTls)
                            .put("protocol", "vmess")
                            .put(
                                "settings",
                                org.json.JSONObject().put(
                                    "clients",
                                    org.json.JSONArray().put(org.json.JSONObject().put("id", id.toString()))
                                )
                            )
                            .put(
                                "streamSettings",
                                org.json.JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "tls")
                                    .put(
                                        "tlsSettings",
                                        org.json.JSONObject()
                                            .put("alpn", org.json.JSONArray().put("h2").put("http/1.1"))
                                            .put("certificates", org.json.JSONArray().put(certObj))
                                    )
                                    .put(
                                        "xhttpSettings",
                                        org.json.JSONObject()
                                            .put("path", "/tlsxh")
                                            .put("mode", "auto")
                                    )
                            )
                    )
                    .put(
                        org.json.JSONObject()
                            .put("tag", "in-reality")
                            .put("listen", "127.0.0.1")
                            .put("port", portReality)
                            .put("protocol", "vmess")
                            .put(
                                "settings",
                                org.json.JSONObject().put(
                                    "clients",
                                    org.json.JSONArray().put(org.json.JSONObject().put("id", id.toString()))
                                )
                            )
                            .put(
                                "streamSettings",
                                org.json.JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "reality")
                                    .put(
                                        "realitySettings",
                                        org.json.JSONObject()
                                            .put("show", true)
                                            .put("dest", "127.0.0.1:$portTls")
                                            .put("serverNames", org.json.JSONArray().put("localhost"))
                                            .put("privateKey", realityPrivateKey)
                                            .put("shortIds", org.json.JSONArray().put(realityShortId))
                                    )
                                    .put(
                                        "xhttpSettings",
                                        org.json.JSONObject()
                                            .put("path", "/realityxh")
                                            .put("mode", "auto")
                                    )
                            )
                    )
            )
            put(
                "outbounds",
                org.json.JSONArray().put(
                    org.json.JSONObject()
                        .put("protocol", "freedom")
                        .put("tag", "direct")
                        .put(
                            "settings",
                            org.json.JSONObject().put(
                                "finalRules",
                                org.json.JSONArray().put(org.json.JSONObject().put("action", "allow"))
                            )
                        )
                )
            )
        }

        val tempConfig = java.io.File.createTempFile("xray-vmess-xhttp-", ".json")
        tempConfig.writeText(configJson.toString(2))
        val process = ProcessBuilder(xrayBin.absolutePath, "run", "-c", tempConfig.absolutePath)
            .redirectErrorStream(true)
            .start()
        val xrayLog = StringBuffer()
        val logReader = Thread {
            try {
                process.inputStream.bufferedReader().forEachLine { line ->
                    xrayLog.append(line).append('\n')
                }
            } catch (_: Exception) {}
        }.apply { isDaemon = true; start() }

        try {
            // Wait until Xray is listening on portPlain.
            var ready = false
            val deadline = System.currentTimeMillis() + 5_000
            while (System.currentTimeMillis() < deadline) {
                try {
                    java.net.Socket("127.0.0.1", portPlain).use { ready = true }
                    if (ready) break
                } catch (_: Exception) {
                    Thread.sleep(50)
                }
            }
            if (!ready) {
                fail("Xray (${xrayBin.absolutePath}) failed to start:\n$xrayLog")
            }

            val supportsNoneAndZero = xrayBin.readBytes().let { bytes ->
                // Xray 26.10+ removed NONE (0x05) and ZERO (0x06) from xray.common.protocol.SecurityType,
                // whereas Xray <= 26.6 supports them.
                val pattern = byteArrayOf(0x04, 'N'.code.toByte(), 'O'.code.toByte(), 'N'.code.toByte(), 'E'.code.toByte(), 0x10, 0x05)
                bytes.indices.any { i ->
                    i + pattern.size <= bytes.size && pattern.indices.all { j -> bytes[i + j] == pattern[j] }
                }
            }

            // 6. REALITY + XHTTP (mode = AUTO -> stream-one)
            val realitySecurities = buildList {
                add(VmessSecurity.AES_128_GCM)
                if (supportsNoneAndZero) add(VmessSecurity.ZERO)
            }
            for (realitySec in realitySecurities) {
                val realityCfg = ProxyConfiguration(
                    name = "reality-xhttp-$realitySec",
                    serverAddress = "127.0.0.1",
                    serverPort = portReality.toUShort(),
                    uuid = id,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VMESS,
                    transport = "xhttp",
                    security = "reality",
                    vmessSecurity = realitySec.raw,
                    reality = com.mythaia.data.model.RealityConfiguration.parse(
                        mapOf(
                            "security" to "reality",
                            "sni" to "localhost",
                            "pbk" to realityPublicKey,
                            "sid" to realityShortId,
                            "fp" to "chrome_133"
                        )
                    ),
                    xhttp = com.mythaia.data.model.XHttpConfiguration(
                        host = "localhost",
                        path = "/realityxh",
                        mode = com.mythaia.data.model.XHttpMode.AUTO
                    )
                )
                verifyVmessEcho(realityCfg, echoPort, realitySec, authenticatedLength = false, label = "${xrayBin.parentFile.name}/reality/auto/$realitySec")
            }

            // 1. Plain HTTP XHTTP: modes (packet-up, stream-up, stream-one, auto) x ciphers (aes-128-gcm, chacha20-poly1305, auto, none, zero)
            val securities = buildList {
                add(VmessSecurity.AES_128_GCM)
                add(VmessSecurity.CHACHA20_POLY1305)
                add(VmessSecurity.AUTO)
                if (supportsNoneAndZero) {
                    add(VmessSecurity.NONE)
                    add(VmessSecurity.ZERO)
                }
            }
            for (mode in listOf(
                com.mythaia.data.model.XHttpMode.PACKET_UP,
                com.mythaia.data.model.XHttpMode.STREAM_UP,
                com.mythaia.data.model.XHttpMode.STREAM_ONE,
                com.mythaia.data.model.XHttpMode.AUTO
            )) {
                for (security in securities) {
                    val cfg = ProxyConfiguration(
                        name = "plain-$mode-$security",
                        serverAddress = "127.0.0.1",
                        serverPort = portPlain.toUShort(),
                        uuid = id,
                        encryption = "none",
                        outboundProtocol = OutboundProtocol.VMESS,
                        transport = "xhttp",
                        security = "none",
                        vmessSecurity = security.raw,
                        xhttp = com.mythaia.data.model.XHttpConfiguration(
                            host = "localhost",
                            path = "/xh",
                            mode = mode,
                            noGrpcHeader = mode == com.mythaia.data.model.XHttpMode.STREAM_ONE
                        )
                    )
                    verifyVmessEcho(cfg, echoPort, security, authenticatedLength = false, label = "${xrayBin.parentFile.name}/plain/$mode/$security")
                }
            }

            // 2. Authenticated Length (OPTION_AUTHENTICATED_LENGTH = 0x10) with AES-128-GCM and ChaCha20-Poly1305
            for (security in listOf(VmessSecurity.AES_128_GCM, VmessSecurity.CHACHA20_POLY1305)) {
                val cfg = ProxyConfiguration(
                    name = "authlen-$security",
                    serverAddress = "127.0.0.1",
                    serverPort = portPlain.toUShort(),
                    uuid = id,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VMESS,
                    transport = "xhttp",
                    security = "none",
                    vmessSecurity = security.raw,
                    xhttp = com.mythaia.data.model.XHttpConfiguration(
                        host = "localhost",
                        path = "/xh",
                        mode = com.mythaia.data.model.XHttpMode.STREAM_ONE,
                        noGrpcHeader = true
                    )
                )
                verifyVmessEcho(cfg, echoPort, security, authenticatedLength = true, label = "${xrayBin.parentFile.name}/authlen/$security")
            }

            // 3. Custom metadata placements (session in header, seq in cookie, uplink data in header, noSSEHeader)
            val placementCfg = ProxyConfiguration(
                name = "placement",
                serverAddress = "127.0.0.1",
                serverPort = portPlacement.toUShort(),
                uuid = id,
                encryption = "none",
                outboundProtocol = OutboundProtocol.VMESS,
                transport = "xhttp",
                security = "none",
                vmessSecurity = VmessSecurity.AES_128_GCM.raw,
                xhttp = com.mythaia.data.model.XHttpConfiguration(
                    host = "localhost",
                    path = "/custom",
                    mode = com.mythaia.data.model.XHttpMode.PACKET_UP,
                    sessionPlacement = com.mythaia.data.model.XHttpPlacement.HEADER,
                    sessionKey = "X-My-Session",
                    seqPlacement = com.mythaia.data.model.XHttpPlacement.COOKIE,
                    seqKey = "my_seq",
                    uplinkDataPlacement = com.mythaia.data.model.XHttpPlacement.HEADER,
                    uplinkDataKey = "X-Up-Data",
                    uplinkChunkSize = 256,
                    noSseHeader = true
                )
            )
            verifyVmessEcho(placementCfg, echoPort, VmessSecurity.AES_128_GCM, authenticatedLength = false, label = "${xrayBin.parentFile.name}/placement")

            // 4. TLS XHTTP (HTTP/2 and HTTP/1.1) across modes
            for (alpn in listOf(listOf("h2"), listOf("http/1.1"))) {
                for (mode in listOf(
                    com.mythaia.data.model.XHttpMode.PACKET_UP,
                    com.mythaia.data.model.XHttpMode.STREAM_UP,
                    com.mythaia.data.model.XHttpMode.STREAM_ONE,
                    com.mythaia.data.model.XHttpMode.AUTO
                )) {
                    val tlsCfg = ProxyConfiguration(
                        name = "tls-$alpn-$mode",
                        serverAddress = "127.0.0.1",
                        serverPort = portTls.toUShort(),
                        uuid = id,
                        encryption = "none",
                        outboundProtocol = OutboundProtocol.VMESS,
                        transport = "xhttp",
                        security = "tls",
                        vmessSecurity = VmessSecurity.CHACHA20_POLY1305.raw,
                        tls = com.mythaia.data.model.TlsConfiguration(
                            serverName = "localhost",
                            alpn = alpn,
                            allowInsecure = true
                        ),
                        xhttp = com.mythaia.data.model.XHttpConfiguration(
                            host = "localhost",
                            path = "/tlsxh",
                            mode = mode
                        )
                    )
                    verifyVmessEcho(tlsCfg, echoPort, VmessSecurity.CHACHA20_POLY1305, authenticatedLength = false, label = "${xrayBin.parentFile.name}/tls/$alpn/$mode")
                }
            }

            // 5. Split downloadSettings (upload on portTls with stream-up, download on portTls via separate downloadSettings)
            val splitExtra = """
                {
                  "downloadSettings": {
                    "address": "127.0.0.1",
                    "port": $portTls,
                    "network": "xhttp",
                    "security": "tls",
                    "tlsSettings": {"serverName": "localhost", "allowInsecure": true, "alpn": ["h2"]},
                    "xhttpSettings": {"path": "/tlsxh", "host": "localhost"}
                  }
                }
            """.trimIndent()
            val splitCfg = ProxyConfiguration(
                name = "split-download",
                serverAddress = "127.0.0.1",
                serverPort = portTls.toUShort(),
                uuid = id,
                encryption = "none",
                outboundProtocol = OutboundProtocol.VMESS,
                transport = "xhttp",
                security = "tls",
                vmessSecurity = VmessSecurity.AES_128_GCM.raw,
                tls = com.mythaia.data.model.TlsConfiguration(
                    serverName = "localhost",
                    alpn = listOf("h2"),
                    allowInsecure = true
                ),
                xhttp = com.mythaia.data.model.XHttpConfiguration.fromExtraJson(
                    host = "localhost",
                    path = "/tlsxh",
                    mode = com.mythaia.data.model.XHttpMode.STREAM_UP,
                    extraJson = splitExtra
                )
            )
            verifyVmessEcho(splitCfg, echoPort, VmessSecurity.AES_128_GCM, authenticatedLength = false, label = "${xrayBin.parentFile.name}/split-download")
        } catch (e: Throwable) {
            Thread.sleep(100)
            throw AssertionError("${e.message}\n--- Xray log ---\n$xrayLog", e)
        } finally {
            process.destroyForcibly()
            process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
            logReader.join(1000)
            tempConfig.delete()
        }
    }

    private fun verifyVmessEcho(
        config: ProxyConfiguration,
        echoPort: Int,
        security: VmessSecurity,
        authenticatedLength: Boolean,
        label: String
    ) {
        try {
            kotlinx.coroutines.runBlocking {
                kotlinx.coroutines.withTimeout(10_000) {
                    val transport = com.mythaia.vpn.protocol.StreamTransports.open(config, config.tls, null).transport
                    val sealed = VmessProtocol.sealRequest(
                        id = config.uuid,
                        host = "127.0.0.1",
                        port = echoPort,
                        command = VmessProtocol.COMMAND_TCP,
                        security = security,
                        authenticatedLength = authenticatedLength
                    )
                    val conn = VmessConnection(transport, sealed.session, sealed.bytes)
                    try {
                        val payload1 = "Hello VMess+XHTTP [$label]!".toByteArray(Charsets.UTF_8)
                        val payload2 = ByteArray(8192) { (it * 31 + 7).toByte() }
                        conn.send(payload1)
                        val recv1 = readExactFromConn(conn, payload1.size, "payload1")
                        assertArrayEquals("mismatch on payload1 for $label", payload1, recv1)

                        conn.send(payload2)
                        val recv2 = readExactFromConn(conn, payload2.size, "payload2")
                        assertArrayEquals("mismatch on payload2 for $label", payload2, recv2)
                    } finally {
                        conn.cancel()
                    }
                }
            }
        } catch (e: Throwable) {
            throw AssertionError("Failed on $label: ${e.message}", e)
        }
    }

    private suspend fun readExactFromConn(conn: VmessConnection, size: Int, stage: String = ""): ByteArray {
        val out = java.io.ByteArrayOutputStream(size)
        try {
            while (out.size() < size) {
                val chunk = conn.receive() ?: throw IllegalStateException("unexpected EOF at $stage after ${out.size()}/$size bytes")
                out.write(chunk)
            }
        } catch (e: Throwable) {
            throw IllegalStateException("at $stage (${out.size()}/$size bytes): ${e.message}", e)
        }
        return out.toByteArray()
    }
}

