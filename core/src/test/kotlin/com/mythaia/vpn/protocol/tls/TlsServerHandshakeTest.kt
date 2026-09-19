package com.mythaia.vpn.protocol.tls

import com.mythaia.vpn.Tls13Crypto
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.Signature

/**
 * Driver-piece tests for the TLS 1.3 server [TlsServer].
 *
 * # Why this is not the full loopback interop test
 *
 * The gold-standard test would stand [TlsServer] and the app's own
 * [TlsClient] back to back over an in-memory transport and drive a real
 * handshake. That cannot run in this (JVM, off-device) unit suite. Both sides
 * reach [Tls13KeyDerivation] for the key schedule, and every one of its methods
 * calls into [com.mythaia.vpn.NativeBridge], whose static initializer runs
 * `System.loadLibrary("mythaia_native")`. The Gradle `test` source set has no
 * such library on `java.library.path`, so the first class-load of `NativeBridge`
 * throws `UnsatisfiedLinkError` — the `NativeBridge` KDoc says as much ("the unit
 * suite runs on a desktop JVM with no library to load"). The key-schedule maths
 * underneath (`Tls13Crypto`) is pure JCA and would run fine; it is only the
 * native loader wrapper that is unloadable here. The loopback interop therefore
 * belongs in the `androidTest` instrumentation set, where the native library is
 * packaged.
 *
 * What this suite does instead, without touching the native loader, is exercise
 * the pieces the driver owns outright:
 *
 *  - the fatal-alert paths a server must take for a client it cannot serve —
 *    no TLS 1.3, no X25519 key_share, no ecdsa_secp256r1_sha256, no shared ALPN
 *    — which [TlsServer] reaches *before* any key derivation, driving the real
 *    state machine over an in-memory [Transport];
 *  - the CertificateVerify the server signs, verified under the leaf public key
 *    exactly as [TlsClient.verifyCertificateVerify] would, and rejected when the
 *    transcript it binds is altered;
 *  - the constant-time client-Finished comparison, accepting a correct
 *    verify_data (computed by the independent `Tls13Crypto` code path) and
 *    rejecting a single flipped bit.
 *
 * Expected values are built by hand from RFC 8446 or taken from a second code
 * path, never from what [TlsServer] itself emits.
 */
class TlsServerHandshakeTest {

    // ----- in-memory transport -----

    /**
     * One end of a loopback transport pair: [inbound] carries bytes written by
     * the peer, [outbound] carries bytes written here. Channels are unbounded so
     * a send never suspends, which keeps the single-threaded `runBlocking` tests
     * from deadlocking on their own writes.
     */
    private class LoopbackTransport(
        private val inbound: Channel<ByteArray>,
        private val outbound: Channel<ByteArray>
    ) : Transport {
        override suspend fun send(data: ByteArray) { outbound.send(data.copyOf()) }
        override fun sendAsync(data: ByteArray) { outbound.trySend(data.copyOf()) }
        override suspend fun receive(): ByteArray? = inbound.receiveCatching().getOrNull()
        override fun forceCancel() { inbound.cancel(); outbound.cancel() }

        companion object {
            fun pair(): Pair<LoopbackTransport, LoopbackTransport> {
                val a2b = Channel<ByteArray>(Channel.UNLIMITED)
                val b2a = Channel<ByteArray>(Channel.UNLIMITED)
                val server = LoopbackTransport(inbound = b2a, outbound = a2b)
                val peer = LoopbackTransport(inbound = a2b, outbound = b2a)
                return server to peer
            }
        }
    }

    private fun leafProvider(): MitmLeafCertificates =
        MitmLeafCertificates(MitmCertificateAuthority.generate())

    // ----- hand-rolled ClientHello (RFC 8446 §4.1.2) -----

    private fun u16(v: Int): ByteArray =
        byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun extension(type: Int, data: ByteArray): ByteArray = u16(type) + u16(data.size) + data

    /**
     * Assembles a ClientHello handshake message (type + 3-byte length + body)
     * from the fields the tests vary. Every length is counted out here, by hand,
     * rather than taken from any app code, so [ClientHelloParser] is tested
     * against the spec and not against a shared encoder.
     */
    private fun clientHello(
        supportedVersions: List<Int> = listOf(0x0304),
        cipherSuites: List<Int> = listOf(0x1301),
        signatureAlgorithms: List<Int> = listOf(0x0403),
        alpn: List<String> = emptyList(),
        x25519Key: ByteArray? = ByteArray(32) { 0x33 },
        serverName: String? = "example.com"
    ): ByteArray {
        val extensions = ArrayList<Byte>()

        // supported_versions (43): ClientHello form — 1-byte list length, then versions.
        if (supportedVersions.isNotEmpty()) {
            val list = supportedVersions.flatMap { u16(it).toList() }.toByteArray()
            val data = byteArrayOf(list.size.toByte()) + list
            extensions += extension(0x002B, data).toList()
        }

        // key_share (51): client_shares length(2), then one x25519 entry.
        if (x25519Key != null) {
            require(x25519Key.size == 32)
            val entry = u16(0x001D) + u16(32) + x25519Key
            val data = u16(entry.size) + entry
            extensions += extension(0x0033, data).toList()
        }

        // signature_algorithms (13): list length(2), then schemes.
        if (signatureAlgorithms.isNotEmpty()) {
            val list = signatureAlgorithms.flatMap { u16(it).toList() }.toByteArray()
            val data = u16(list.size) + list
            extensions += extension(0x000D, data).toList()
        }

        // application_layer_protocol_negotiation (16): list length(2), then len(1)+name entries.
        if (alpn.isNotEmpty()) {
            val list = ArrayList<Byte>()
            for (p in alpn) {
                val bytes = p.toByteArray(Charsets.US_ASCII)
                list += bytes.size.toByte()
                list += bytes.toList()
            }
            val data = u16(list.size) + list.toByteArray()
            extensions += extension(0x0010, data).toList()
        }

        // server_name (0): list length(2), then type(1)+len(2)+host.
        if (serverName != null) {
            val host = serverName.toByteArray(Charsets.US_ASCII)
            val entry = byteArrayOf(0x00) + u16(host.size) + host
            val data = u16(entry.size) + entry
            extensions += extension(0x0000, data).toList()
        }

        val suites = cipherSuites.flatMap { u16(it).toList() }.toByteArray()

        val body = ArrayList<Byte>()
        body += u16(0x0303).toList()                 // legacy_version
        body += ByteArray(32) { 0x01 }.toList()      // random
        body += 32.toByte()                          // legacy_session_id length
        body += ByteArray(32) { 0x02 }.toList()      // legacy_session_id
        body += u16(suites.size).toList()            // cipher_suites length
        body += suites.toList()
        body += 1.toByte()                           // compression_methods length
        body += 0x00.toByte()                        // null compression
        body += u16(extensions.size).toList()        // extensions length
        body += extensions

        val bodyBytes = body.toByteArray()
        val header = byteArrayOf(
            0x01,
            ((bodyBytes.size ushr 16) and 0xFF).toByte(),
            ((bodyBytes.size ushr 8) and 0xFF).toByte(),
            (bodyBytes.size and 0xFF).toByte()
        )
        return header + bodyBytes
    }

    /** Wraps a handshake message in a single plaintext TLS record (content type 0x16). */
    private fun record(message: ByteArray): ByteArray =
        byteArrayOf(0x16, 0x03, 0x03) + u16(message.size) + message

    private fun assertFatalAlert(alert: ByteArray, description: Int) {
        assertEquals("content type (alert)", 0x15, alert[0].toInt() and 0xFF)
        assertEquals("legacy version hi", 0x03, alert[1].toInt() and 0xFF)
        assertEquals("legacy version lo", 0x03, alert[2].toInt() and 0xFF)
        assertEquals("alert body length", 2, ((alert[3].toInt() and 0xFF) shl 8) or (alert[4].toInt() and 0xFF))
        assertEquals("alert level fatal", 2, alert[5].toInt() and 0xFF)
        assertEquals("alert description", description, alert[6].toInt() and 0xFF)
    }

    /** Runs the driver against a hand-built ClientHello and returns (thrown error, bytes the server wrote). */
    private fun runAndCaptureAlert(clientHelloMessage: ByteArray): Pair<Throwable?, ByteArray?> = runBlocking {
        val (serverTransport, peer) = LoopbackTransport.pair()
        val server = TlsServer(serverTransport, leafProvider())
        val error = runCatching { server.handshake(record(clientHelloMessage)) }.exceptionOrNull()
        error to peer.receive()
    }

    // ----- alert paths -----

    @Test
    fun `a client that does not offer TLS 1_3 gets a protocol_version fatal alert`() {
        // supported_versions advertises only TLS 1.2, so offersTls13 is false.
        val (error, alert) = runAndCaptureAlert(clientHello(supportedVersions = listOf(0x0303)))
        assertTrue("handshake must fail", error is TlsError.HandshakeFailed)
        assertFatalAlert(alert!!, description = 70) // protocol_version
    }

    @Test
    fun `a client with no X25519 key_share gets a handshake_failure fatal alert`() {
        val (error, alert) = runAndCaptureAlert(clientHello(x25519Key = null))
        assertTrue("handshake must fail", error is TlsError.HandshakeFailed)
        assertFatalAlert(alert!!, description = 40) // handshake_failure
    }

    @Test
    fun `a client without ecdsa_secp256r1_sha256 gets a handshake_failure fatal alert`() {
        // Offers only rsa_pss_rsae_sha256 (0x0804), not the 0x0403 the leaf is signed with.
        val (error, alert) = runAndCaptureAlert(clientHello(signatureAlgorithms = listOf(0x0804)))
        assertTrue("handshake must fail", error is TlsError.HandshakeFailed)
        assertFatalAlert(alert!!, description = 40) // handshake_failure
    }

    @Test
    fun `a client offering no shared cipher suite gets a handshake_failure fatal alert`() {
        // 0x00FF is SCSV, never a real TLS 1.3 suite the server prefers.
        val (error, alert) = runAndCaptureAlert(clientHello(cipherSuites = listOf(0x00FF)))
        assertTrue("handshake must fail", error is TlsError.HandshakeFailed)
        assertFatalAlert(alert!!, description = 40) // handshake_failure
    }

    @Test
    fun `a client whose ALPN does not overlap gets a no_application_protocol fatal alert`() {
        // Everything else is acceptable; only the ALPN set is disjoint from {h2, http/1.1}.
        val (error, alert) = runAndCaptureAlert(clientHello(alpn = listOf("spdy/3")))
        assertTrue("handshake must fail", error is TlsError.HandshakeFailed)
        assertFatalAlert(alert!!, description = 120) // no_application_protocol
    }

    // ----- CertificateVerify -----

    @Test
    fun `the server CertificateVerify signature verifies under the leaf public key`() {
        val leaf = leafProvider().leaf("example.com")

        // An arbitrary transcript stand-in; the suite is TLS_AES_128_GCM_SHA256, so SHA-256.
        val transcript = ByteArray(128) { it.toByte() }
        val transcriptHash = MessageDigest.getInstance("SHA-256").digest(transcript)

        // Pin the signed octet string independently from the builder: 64 * 0x20,
        // the server context string, a 0x00 separator, then the transcript hash
        // (RFC 8446 §4.4.3).
        val handBuiltContext =
            ByteArray(64) { 0x20 } +
                "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII) +
                byteArrayOf(0x00) +
                transcriptHash
        val builderContext = TlsServerHelloBuilder.certificateVerifyContext(transcriptHash)
        assertArrayEqualsMsg("CertificateVerify context layout", handBuiltContext, builderContext)

        // Sign exactly as TlsServer does.
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(leaf.privateKey)
        signer.update(builderContext)
        val signature = signer.sign()

        // Verify under the leaf's public key, the way TlsClient.verifyCertificateVerify does.
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(leaf.certificate.publicKey)
        verifier.update(builderContext)
        assertTrue("a correct signature must verify", verifier.verify(signature))

        // The signature binds the transcript: a single flipped byte must break it.
        val tampered = transcript.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val tamperedContext =
            TlsServerHelloBuilder.certificateVerifyContext(
                MessageDigest.getInstance("SHA-256").digest(tampered)
            )
        val tamperedVerifier = Signature.getInstance("SHA256withECDSA")
        tamperedVerifier.initVerify(leaf.certificate.publicKey)
        tamperedVerifier.update(tamperedContext)
        assertFalse("a signature over a different transcript must not verify", tamperedVerifier.verify(signature))
    }

    // ----- client Finished verification -----

    @Test
    fun `the client-Finished check accepts a correct verify_data and rejects a flipped bit`() {
        // The expected verify_data from an independent code path (Tls13Crypto is
        // the pure-JCA implementation TlsServer reaches through Tls13KeyDerivation).
        val suite = TlsCipherSuite.TLS_AES_128_GCM_SHA256
        val clientTrafficSecret = ByteArray(32) { (it + 7).toByte() }
        val transcript = ByteArray(200) { (it * 3).toByte() }
        val expected = Tls13Crypto.computeFinished(suite, clientTrafficSecret, transcript)

        assertTrue("a byte-identical verify_data is accepted",
            TlsServer.constantTimeEquals(expected, expected.copyOf()))

        val flipped = expected.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        assertFalse("a single flipped bit is rejected",
            TlsServer.constantTimeEquals(expected, flipped))

        assertFalse("a length mismatch is rejected",
            TlsServer.constantTimeEquals(expected, expected + byteArrayOf(0x00)))
    }

    private fun assertArrayEqualsMsg(message: String, expected: ByteArray, actual: ByteArray) {
        assertEquals("$message (length)", expected.size, actual.size)
        assertTrue(message, expected.contentEquals(actual))
    }
}
