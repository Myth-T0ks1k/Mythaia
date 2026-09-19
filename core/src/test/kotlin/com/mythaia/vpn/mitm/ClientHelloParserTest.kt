package com.mythaia.vpn.mitm

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The server-side ClientHello reader. The hello it parses is built here by hand
 * from RFC 8446 §4.1.2 — every length prefix computed from the bytes it frames —
 * so the offsets are asserted against the wire format itself, not against the
 * parser's own idea of the layout.
 *
 * A server that threw on a malformed hello would let any client raise an
 * exception in it; the contract is a null and a closed connection, so every
 * truncated and over-long field is checked to yield null rather than a crash or
 * a half-read field.
 */
class ClientHelloParserTest {

    // --- little wire-format builders (lengths computed from the framed bytes) ---

    private fun u16(v: Int) = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
    private fun u24(v: Int) =
        byteArrayOf(((v ushr 16) and 0xFF).toByte(), ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    /** Prefix [body] with an 8/16/24-bit big-endian length, as the RFC vectors do. */
    private fun lp8(body: ByteArray) = byteArrayOf(body.size.toByte()) + body
    private fun lp16(body: ByteArray) = u16(body.size) + body
    private fun lp24(body: ByteArray) = u24(body.size) + body

    private fun ext(type: Int, data: ByteArray) = u16(type) + lp16(data)

    private val random = ByteArray(32) { (0xA0 + it).toByte() }
    private val sessionId = ByteArray(32) { it.toByte() }
    private val x25519Key = ByteArray(32) { (it + 1).toByte() }

    // server_name (0): ServerNameList { NameType host_name(0), HostName<..> }
    private fun serverNameExt(host: String): ByteArray {
        val entry = byteArrayOf(0x00) + lp16(host.toByteArray(Charsets.US_ASCII))
        return ext(0, lp16(entry))
    }

    // key_share (51): client_shares { group, key_exchange<..> }
    private fun keyShareExt(group: Int, key: ByteArray): ByteArray {
        val entry = u16(group) + lp16(key)
        return ext(51, lp16(entry))
    }

    // supported_versions (43) on a ClientHello: ProtocolVersion versions<2..254>
    private fun supportedVersionsExt(vararg versions: Int): ByteArray {
        val body = versions.fold(ByteArray(0)) { acc, v -> acc + u16(v) }
        return ext(43, lp8(body))
    }

    // application_layer_protocol_negotiation (16): ProtocolNameList of opaque<1..>
    private fun alpnExt(vararg protocols: String): ByteArray {
        val list = protocols.fold(ByteArray(0)) { acc, p -> acc + lp8(p.toByteArray(Charsets.US_ASCII)) }
        return ext(16, lp16(list))
    }

    // signature_algorithms (13): SignatureScheme supported_signature_algorithms<2..>
    private fun sigAlgsExt(vararg schemes: Int): ByteArray {
        val body = schemes.fold(ByteArray(0)) { acc, s -> acc + u16(s) }
        return ext(13, lp16(body))
    }

    private fun defaultExtensions(): ByteArray =
        serverNameExt("example.com") +
            keyShareExt(0x001D, x25519Key) +
            supportedVersionsExt(0x0304, 0x0303) +
            alpnExt("h2", "http/1.1") +
            sigAlgsExt(0x0403, 0x0804)

    /**
     * A complete ClientHello handshake message (type + 24-bit length + body).
     * Every sub-field is length-prefixed from its own contents, so the outer
     * declared length always matches unless a caller deliberately truncates.
     */
    private fun clientHello(
        sessionIdField: ByteArray = lp8(sessionId),
        cipherSuitesField: ByteArray = lp16(u16(0x1301) + u16(0x1302) + u16(0x1303)),
        compression: ByteArray = lp8(byteArrayOf(0x00)),
        extensions: ByteArray? = defaultExtensions()
    ): ByteArray {
        var body = u16(0x0303) + random + sessionIdField + cipherSuitesField + compression
        if (extensions != null) body += lp16(extensions)
        return byteArrayOf(0x01) + lp24(body)
    }

    // --- the happy path, asserted field by field ---

    @Test
    fun `a well-formed ClientHello parses every field this server reads`() {
        val parsed = ClientHelloParser.parse(clientHello())
        assertNotNull(parsed)
        parsed!!
        assertArrayEquals(random, parsed.random)
        assertArrayEquals(sessionId, parsed.sessionId)
        assertEquals(listOf(0x1301, 0x1302, 0x1303), parsed.cipherSuites)
        assertEquals("example.com", parsed.serverName)
        assertArrayEquals(x25519Key, parsed.x25519KeyShare)
        assertEquals(listOf(0x0304, 0x0303), parsed.supportedVersions)
        assertEquals(listOf("h2", "http/1.1"), parsed.alpn)
        assertEquals(listOf(0x0403, 0x0804), parsed.signatureAlgorithms)
    }

    @Test
    fun `offersTls13 is true only when supported_versions carries 0x0304`() {
        assertTrue(ClientHelloParser.parse(clientHello())!!.offersTls13)

        val onlyTls12 = clientHello(extensions = serverNameExt("h") + supportedVersionsExt(0x0303))
        val parsed = ClientHelloParser.parse(onlyTls12)!!
        assertFalse(parsed.offersTls13)
        assertEquals(listOf(0x0303), parsed.supportedVersions)
    }

    @Test
    fun `a hello with no server_name parses with a null serverName`() {
        val noSni = clientHello(extensions = keyShareExt(0x001D, x25519Key) + supportedVersionsExt(0x0304))
        val parsed = ClientHelloParser.parse(noSni)
        assertNotNull(parsed)
        assertNull(parsed!!.serverName)
    }

    @Test
    fun `a key_share for a group other than x25519 leaves the x25519 share null`() {
        // secp256r1 (0x0017) with a 65-byte point: the parser skips it and
        // reports no x25519 share, but the hello is still valid.
        val p256 = ByteArray(65) { 0x04 }
        val hello = clientHello(extensions = serverNameExt("example.com") + keyShareExt(0x0017, p256))
        val parsed = ClientHelloParser.parse(hello)
        assertNotNull(parsed)
        assertNull(parsed!!.x25519KeyShare)
        assertEquals("example.com", parsed.serverName)
    }

    @Test
    fun `x25519 share of the wrong length is not accepted`() {
        val hello = clientHello(extensions = keyShareExt(0x001D, ByteArray(31)))
        assertNull(ClientHelloParser.parse(hello)!!.x25519KeyShare)
    }

    @Test
    fun `a hello with no extensions block still parses the core fields`() {
        val parsed = ClientHelloParser.parse(clientHello(extensions = null))
        assertNotNull(parsed)
        parsed!!
        assertEquals(listOf(0x1301, 0x1302, 0x1303), parsed.cipherSuites)
        assertNull(parsed.serverName)
        assertFalse(parsed.offersTls13)
        assertTrue(parsed.alpn.isEmpty())
    }

    // --- malformed input yields null, never an exception ---

    @Test
    fun `bytes too short to hold a header are null`() {
        assertNull(ClientHelloParser.parse(ByteArray(0)))
        assertNull(ClientHelloParser.parse(ByteArray(3)))
    }

    @Test
    fun `a message that is not a ClientHello is null`() {
        val notHello = clientHello().copyOf()
        notHello[0] = 0x02 // ServerHello, not ClientHello
        assertNull(ClientHelloParser.parse(notHello))
    }

    @Test
    fun `a declared length that disagrees with the message size is null`() {
        val valid = clientHello()
        // Drop the last byte: the 24-bit length now overstates the body.
        assertNull(ClientHelloParser.parse(valid.copyOf(valid.size - 1)))
        // Or overstate it directly in the low length byte.
        val overstated = valid.copyOf()
        overstated[3] = (overstated[3] + 1).toByte()
        assertNull(ClientHelloParser.parse(overstated))
    }

    @Test
    fun `a session id longer than 32 bytes is refused`() {
        // legacy_session_id is opaque<0..32>; 33 is out of range.
        val hello = clientHello(sessionIdField = lp8(ByteArray(33)))
        assertNull(ClientHelloParser.parse(hello))
    }

    @Test
    fun `an odd cipher-suites length is refused`() {
        // The list is 2 bytes per suite, so an odd byte count cannot be valid.
        val hello = clientHello(cipherSuitesField = u16(3) + byteArrayOf(0x13, 0x01, 0x13))
        assertNull(ClientHelloParser.parse(hello))
    }

    @Test
    fun `an empty cipher-suites list is refused`() {
        val hello = clientHello(cipherSuitesField = u16(0))
        assertNull(ClientHelloParser.parse(hello))
    }

    @Test
    fun `an extension whose length runs past the extensions block is null`() {
        // A single extension that claims 0xFFFF bytes of body but supplies
        // none: reading it would run off the end, so the parser must refuse.
        val badExtension = u16(0x0000) + byteArrayOf(0xFF.toByte(), 0xFF.toByte())
        assertNull(ClientHelloParser.parse(clientHello(extensions = badExtension)))
    }

    @Test
    fun `a compression-methods length of zero is refused`() {
        // legacy_compression_methods must be exactly { 0 } on a TLS 1.3 hello;
        // an empty list is malformed.
        val hello = clientHello(compression = byteArrayOf(0x00))
        assertNull(ClientHelloParser.parse(hello))
    }
}
