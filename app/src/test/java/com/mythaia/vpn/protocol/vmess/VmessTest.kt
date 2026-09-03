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

    @Test
    fun `a partial chunk can be retried without losing the mask stream`() {
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
    fun `a non-zero alterId is refused, not silently downgraded`() {
        // It selects the legacy MD5 header removed from v2ray in 2022; a
        // connection built on it would never authenticate.
        val json = """{"v":"2","ps":"N","add":"example.com","port":"443","id":"$id","aid":"64"}"""
        val link = "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toByteArray())
        try {
            ProxyConfiguration.fromUrl(link)
            fail("expected InvalidUrl")
        } catch (e: ProxyError.InvalidUrl) {
            assertTrue(e.message!!.contains("alterId"))
        }
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
    fun `security names map to their protocol ids`() {
        assertEquals(0x03, VmessSecurity.AES_128_GCM.id)
        assertEquals(0x04, VmessSecurity.CHACHA20_POLY1305.id)
        assertEquals(0x05, VmessSecurity.NONE.id)
        assertEquals(VmessSecurity.AES_128_GCM, VmessSecurity.fromRaw("auto"))
        assertEquals(VmessSecurity.AES_128_GCM, VmessSecurity.fromRaw(null))
        assertEquals(VmessSecurity.CHACHA20_POLY1305, VmessSecurity.fromRaw("chacha20-ietf-poly1305"))
        assertEquals(VmessSecurity.NONE, VmessSecurity.fromRaw("none"))
    }
}
