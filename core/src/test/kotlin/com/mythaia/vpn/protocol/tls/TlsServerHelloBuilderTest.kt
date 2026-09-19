package com.mythaia.vpn.protocol.tls

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the byte layout of every [TlsServerHelloBuilder] output against
 * hand-written RFC 8446 / RFC 7301 bytes.
 *
 * The expected arrays here are assembled by hand from the spec — literal
 * handshake-type prefixes, extension ids, and length fields counted out by
 * hand — never by calling the builder's own helpers. If the builder and these
 * expectations drift apart, one of them is wrong about the wire format, which
 * is exactly the bug these tests exist to catch (the client in `TlsClient.kt`
 * parses precisely these bytes).
 */
class TlsServerHelloBuilderTest {

    private fun bytes(vararg v: Int): ByteArray = ByteArray(v.size) { v[it].toByte() }
    private fun filled(n: Int, value: Int): ByteArray = ByteArray(n) { value.toByte() }

    // -- ServerHello --

    @Test
    fun `serverHello matches the hand-written RFC 8446 layout`() {
        val random = filled(32, 0x11)
        val sessionId = filled(32, 0x22)
        val serverPub = filled(32, 0x33)
        val cipherSuite = 0x1301 // TLS_AES_128_GCM_SHA256

        val msg = TlsServerHelloBuilder.buildServerHello(
            random = random,
            legacySessionId = sessionId,
            cipherSuite = cipherSuite,
            serverX25519Pub = serverPub
        )

        // Extensions, laid out by hand:
        //   supported_versions: 00 2b | 00 02 | 03 04
        //   key_share:          00 33 | 00 24 | 00 1d | 00 20 | <32-byte key>
        val extensions =
            bytes(0x00, 0x2B, 0x00, 0x02, 0x03, 0x04) +
            bytes(0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20) + serverPub
        assertEquals("extensions length sanity", 6 + 8 + 32, extensions.size) // 46

        val body =
            bytes(0x03, 0x03) +                                  // legacy_version
            random +                                             // random(32)
            bytes(0x20) + sessionId +                            // session id len(0x20) + id
            bytes(0x13, 0x01) +                                  // cipher suite
            bytes(0x00) +                                        // compression
            bytes((extensions.size shr 8) and 0xFF, extensions.size and 0xFF) +
            extensions

        val expected =
            bytes(0x02, (body.size shr 16) and 0xFF, (body.size shr 8) and 0xFF, body.size and 0xFF) +
            body

        assertArrayEquals(expected, msg)

        // Spot-check the load-bearing fields directly too.
        assertEquals("handshake type", 0x02.toByte(), msg[0])
        assertEquals("3-byte length", body.size, ((msg[1].toInt() and 0xFF) shl 16) or
                ((msg[2].toInt() and 0xFF) shl 8) or (msg[3].toInt() and 0xFF))
        assertEquals("legacy_version hi", 0x03.toByte(), msg[4])
        assertEquals("legacy_version lo", 0x03.toByte(), msg[5])
    }

    @Test
    fun `serverHello echoes an empty session id`() {
        val msg = TlsServerHelloBuilder.buildServerHello(
            random = filled(32, 0x00),
            legacySessionId = ByteArray(0),
            cipherSuite = 0x1303,
            serverX25519Pub = filled(32, 0x44)
        )
        // type(1)+len(3)+version(2)+random(32) = 38, then the session-id length byte.
        assertEquals("session id length byte", 0x00.toByte(), msg[38])
        // Followed immediately by the 2-byte cipher suite 0x1303.
        assertEquals(0x13.toByte(), msg[39])
        assertEquals(0x03.toByte(), msg[40])
        assertEquals("compression", 0x00.toByte(), msg[41])
    }

    // -- EncryptedExtensions --

    @Test
    fun `encryptedExtensions with no ALPN is an empty extension list`() {
        val msg = TlsServerHelloBuilder.buildEncryptedExtensions(null)
        // type 0x08, length 0x000002, body = extensions_length 0x0000.
        assertArrayEquals(bytes(0x08, 0x00, 0x00, 0x02, 0x00, 0x00), msg)
    }

    @Test
    fun `encryptedExtensions carries a single ALPN protocol`() {
        val msg = TlsServerHelloBuilder.buildEncryptedExtensions("h2")

        // ALPN extension (RFC 7301), hand-written:
        //   00 10            extension type
        //   00 05            ext_data length = 2 + 3
        //   00 03            ProtocolNameList length
        //   02 68 32         len(2) + "h2"
        val alpnExt = bytes(0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32)
        val body = bytes(0x00, alpnExt.size) + alpnExt // extensions_length(2) + extensions
        val expected = bytes(0x08, 0x00, 0x00, body.size) + body

        assertArrayEquals(expected, msg)
        assertEquals("handshake type", 0x08.toByte(), msg[0])
    }

    // -- Certificate --

    @Test
    fun `certificate wraps the leaf DER with empty context and extensions`() {
        val leaf = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE)

        val msg = TlsServerHelloBuilder.buildCertificate(leaf)

        // CertificateEntry: 3-byte cert len + DER + 2-byte (empty) extensions.
        val entry = bytes(0x00, 0x00, leaf.size) + leaf + bytes(0x00, 0x00)
        // body: 1-byte context(0x00) + 3-byte list length + entry.
        val body = bytes(0x00) + bytes(0x00, 0x00, entry.size) + entry
        val expected = bytes(0x0B, 0x00, 0x00, body.size) + body

        assertArrayEquals(expected, msg)
        assertEquals("handshake type", 0x0B.toByte(), msg[0])
        assertEquals("cert_request_context length", 0x00.toByte(), msg[4])
    }

    // -- CertificateVerify --

    @Test
    fun `certificateVerify prefixes scheme and signature length`() {
        val signature = filled(70, 0x5A) // a plausible ECDSA DER signature length

        val msg = TlsServerHelloBuilder.buildCertificateVerify(
            signatureScheme = 0x0403,
            signature = signature
        )

        // body: 04 03 (scheme) | 00 46 (len=70) | signature
        val body = bytes(0x04, 0x03, 0x00, 0x46) + signature
        val expected = bytes(0x0F, 0x00, 0x00, body.size) + body

        assertArrayEquals(expected, msg)
        assertEquals("handshake type", 0x0F.toByte(), msg[0])
    }

    @Test
    fun `certificateVerify defaults to ecdsa_secp256r1_sha256`() {
        val msg = TlsServerHelloBuilder.buildCertificateVerify(signature = filled(64, 0x01))
        // Scheme bytes sit right after the 4-byte handshake header.
        assertEquals(0x04.toByte(), msg[4])
        assertEquals(0x03.toByte(), msg[5])
    }

    // -- Finished --

    @Test
    fun `finished carries verify data verbatim`() {
        val verifyData = filled(32, 0x7E) // SHA-256 sized verify_data

        val msg = TlsServerHelloBuilder.buildFinished(verifyData)

        val expected = bytes(0x14, 0x00, 0x00, 0x20) + verifyData
        assertArrayEquals(expected, msg)
        assertEquals("handshake type", 0x14.toByte(), msg[0])
    }

    // -- CertificateVerify signing input --

    @Test
    fun `certificateVerifyContext emits 64 spaces, the exact label, a 0x00, then the hash`() {
        val transcriptHash = filled(32, 0x99)

        val context = TlsServerHelloBuilder.certificateVerifyContext(transcriptHash)

        // The 98-byte prefix, written out by hand.
        // 64 octets of 0x20:
        val spaces = filled(64, 0x20)
        // ASCII for "TLS 1.3, server CertificateVerify", one byte per character:
        val label = bytes(
            0x54, 0x4C, 0x53,             // T L S
            0x20,                         // (space)
            0x31, 0x2E, 0x33,             // 1 . 3
            0x2C,                         // ,
            0x20,                         // (space)
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, // s e r v e r
            0x20,                         // (space)
            0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, // C e r t i f i c a t e
            0x56, 0x65, 0x72, 0x69, 0x66, 0x79  // V e r i f y
        )
        assertEquals("label is 33 bytes", 33, label.size)

        val prefix = spaces + label + bytes(0x00)
        assertEquals("prefix is 98 bytes", 98, prefix.size)

        val expected = prefix + transcriptHash
        assertArrayEquals(expected, context)
        assertEquals(98 + 32, context.size)

        // Belt-and-suspenders: the first 64 bytes are all 0x20, and the
        // separator byte sits exactly at offset 97.
        for (i in 0 until 64) assertEquals("space at $i", 0x20.toByte(), context[i])
        assertEquals("separator", 0x00.toByte(), context[97])
    }
}
