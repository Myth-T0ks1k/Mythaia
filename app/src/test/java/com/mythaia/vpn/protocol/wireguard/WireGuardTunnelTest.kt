package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The parts of the tunnel that can be exercised without a socket: how a
 * received datagram is sorted, and how a packet's own length is read.
 */
class WireGuardTunnelTest {

    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    private fun tunnel(extraInterface: String = ""): WireGuardTunnel =
        WireGuardTunnel(
            WireGuardConfig.parse(
                """
                [Interface]
                PrivateKey = $privateKey
                Address = 10.0.0.2/32
                $extraInterface

                [Peer]
                PublicKey = $peerKey
                Endpoint = 192.0.2.1:51820
                AllowedIPs = 0.0.0.0/0
                """.trimIndent()
            )
        )

    private fun message(size: Int, typeAt: Int, type: Int): ByteArray =
        ByteArray(size) { 0xAB.toByte() }.also { WireGuardHandshake.writeLe32(it, typeAt, type) }

    // MARK: - Classification

    @Test
    fun `plain WireGuard reads the type at offset zero`() {
        val wg = tunnel()
        assertEquals(
            WireGuardTunnel.Kind.RESPONSE,
            wg.classify(message(WireGuardHandshake.RESPONSE_SIZE, 0, 2))
        )
        assertEquals(WireGuardTunnel.Kind.COOKIE, wg.classify(message(64, 0, 3)))
        assertEquals(WireGuardTunnel.Kind.TRANSPORT, wg.classify(message(128, 0, 4)))
        assertEquals(WireGuardTunnel.Kind.UNKNOWN, wg.classify(message(128, 0, 9)))
    }

    @Test
    fun `an S2-junked response is recognised past its junk`() {
        // The response is the only message AmneziaWG pads, and the padding is
        // random — so a dispatcher reading offset 0 sees noise and throws the
        // handshake away, leaving the tunnel retrying forever.
        val junk = 30
        val wg = tunnel("S2 = $junk\nH2 = 2")

        val response = message(WireGuardHandshake.RESPONSE_SIZE + junk, junk, 2)
        assertEquals(WireGuardTunnel.Kind.RESPONSE, wg.classify(response))
    }

    @Test
    fun `a junked response is recognised under a renumbered H2`() {
        val junk = 15
        val h2 = 0x2A3B4C5D
        val wg = tunnel("S2 = $junk\nH1 = 1234567\nH2 = $h2\nH3 = 3333333\nH4 = 4433221")

        val response = message(WireGuardHandshake.RESPONSE_SIZE + junk, junk, h2)
        assertEquals(WireGuardTunnel.Kind.RESPONSE, wg.classify(response))
    }

    @Test
    fun `a datagram of the junked length that is not a response is left alone`() {
        // Length alone must not be enough: a transport packet that happens to
        // be 92 + S2 bytes long would otherwise be handed to the handshake.
        val junk = 30
        val wg = tunnel("S2 = $junk\nH2 = 2")

        val transport = message(WireGuardHandshake.RESPONSE_SIZE + junk, 0, 4)
        assertEquals(WireGuardTunnel.Kind.TRANSPORT, wg.classify(transport))
    }

    @Test
    fun `a runt datagram is not classified`() {
        assertEquals(WireGuardTunnel.Kind.UNKNOWN, tunnel().classify(ByteArray(3)))
    }

    // MARK: - Packet length

    @Test
    fun `an IPv4 packet reports its own total length`() {
        val packet = ByteArray(64)
        packet[0] = 0x45
        packet[2] = 0x00
        packet[3] = 40
        assertEquals(40, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `an IPv6 packet reports the header plus its payload`() {
        val packet = ByteArray(128)
        packet[0] = 0x60
        packet[4] = 0x00
        packet[5] = 24
        assertEquals(64, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `padding past the declared length is not written to the TUN`() {
        // The plaintext is padded to a multiple of 16, so what comes out of the
        // AEAD is longer than the packet inside it.
        val packet = ByteArray(48)
        packet[0] = 0x45
        packet[3] = 37
        assertEquals(37, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `a truncated or unknown header has no length`() {
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(0)))
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(10) { 0x45 }))
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(64) { 0x25 }))
    }

    // MARK: - HChaCha20

    @Test
    fun `HChaCha20 matches the RFC draft test vector`() {
        // draft-irtf-cfrg-xchacha, section 2.2.1. Checked against the published
        // answer rather than our own round trip: a wrong core would still
        // decrypt whatever it had encrypted.
        val key = ByteArray(32) { it.toByte() }
        val nonce = byteArrayOf(
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27
        )
        val expected = intArrayOf(
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
            0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
            0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
            0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc
        ).map { it.toByte() }.toByteArray()

        assertArrayEquals(expected, WireGuardCrypto.hchacha20(key, nonce))
    }

    @Test
    fun `XChaCha20 rejects a tampered cookie and a wrong associated mac1`() {
        val key = WireGuardCrypto.randomBytes(32)
        val nonce = WireGuardCrypto.randomBytes(24)
        val mac1 = WireGuardCrypto.randomBytes(16)

        // Sealing goes through the same subkey derivation as opening.
        val subkey = WireGuardCrypto.hchacha20(key, nonce.copyOf(16))
        val inner = ByteArray(12).also { nonce.copyInto(it, 4, 16, 24) }
        val cookie = WireGuardCrypto.randomBytes(16)
        val sealed = sealWithNonce(subkey, inner, cookie, mac1)

        assertArrayEquals(cookie, WireGuardCrypto.xopen(key, nonce, sealed, mac1))
        assertNull(WireGuardCrypto.xopen(key, nonce, sealed, WireGuardCrypto.randomBytes(16)))
        assertNull(
            WireGuardCrypto.xopen(
                key, nonce, sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }, mac1
            )
        )
    }

    private fun sealWithNonce(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = org.bouncycastle.crypto.modes.ChaCha20Poly1305()
        cipher.init(
            true,
            org.bouncycastle.crypto.params.AEADParameters(
                org.bouncycastle.crypto.params.KeyParameter(key), 128, nonce, aad
            )
        )
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var written = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        written += cipher.doFinal(out, written)
        return if (written == out.size) out else out.copyOf(written)
    }
}
