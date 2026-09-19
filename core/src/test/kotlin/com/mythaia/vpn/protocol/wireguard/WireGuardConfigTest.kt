package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** The wg-quick INI a user pastes in, and the AmneziaWG fields on top of it. */
class WireGuardConfigTest {

    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    private fun config(
        extraInterface: String = "",
        extraPeer: String = ""
    ) = """
        [Interface]
        PrivateKey = $privateKey
        Address = 10.8.0.2/32, fd00::2/128
        DNS = 1.1.1.1, 1.0.0.1
        MTU = 1380
        $extraInterface

        [Peer]
        PublicKey = $peerKey
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        $extraPeer
    """.trimIndent()

    // MARK: - Basics

    @Test
    fun `parses an ordinary wg-quick config`() {
        val parsed = WireGuardConfig.parse(config())

        assertArrayEquals(ByteArray(32) { it.toByte() }, parsed.privateKey)
        assertEquals(listOf("10.8.0.2/32", "fd00::2/128"), parsed.addresses)
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), parsed.dnsServers)
        assertEquals(1380, parsed.mtu)

        assertArrayEquals(ByteArray(32) { (it * 7).toByte() }, parsed.peer.publicKey)
        assertEquals("vpn.example.com", parsed.peer.endpointHost)
        assertEquals(51820, parsed.peer.endpointPort)
        assertEquals(listOf("0.0.0.0/0", "::/0"), parsed.peer.allowedIps)
        assertEquals(25, parsed.peer.persistentKeepalive)
        assertNull(parsed.peer.presharedKey)

        // A plain config is not AmneziaWG.
        assertTrue(!parsed.amnezia.isEnabled)
    }

    @Test
    fun `the public key is derived, not stored`() {
        val parsed = WireGuardConfig.parse(config())
        assertArrayEquals(WireGuardCrypto.publicKey(parsed.privateKey), parsed.publicKey)
    }

    @Test
    fun `keys are matched case-insensitively, as wg-quick does`() {
        val parsed = WireGuardConfig.parse(
            """
            [Interface]
            privatekey = $privateKey
            ADDRESS = 10.8.0.2/32

            [PEER]
            PublicKey = $peerKey
            endpoint = example.com:1234
            """.trimIndent()
        )
        assertEquals("example.com", parsed.peer.endpointHost)
        assertEquals(listOf("10.8.0.2/32"), parsed.addresses)
    }

    @Test
    fun `comments and blank lines are ignored`() {
        val parsed = WireGuardConfig.parse(
            """
            # a comment
            [Interface]
            PrivateKey = $privateKey   # trailing comment
            ; another comment

            [Peer]
            PublicKey = $peerKey
            Endpoint = example.com:1234
            """.trimIndent()
        )
        assertArrayEquals(ByteArray(32) { it.toByte() }, parsed.privateKey)
        assertEquals(1234, parsed.peer.endpointPort)
    }

    @Test
    fun `an absent MTU falls back to what wg-quick uses`() {
        val parsed = WireGuardConfig.parse(
            """
            [Interface]
            PrivateKey = $privateKey

            [Peer]
            PublicKey = $peerKey
            Endpoint = example.com:1234
            """.trimIndent()
        )
        assertEquals(WireGuardConfig.DEFAULT_MTU, parsed.mtu)
        // An absent AllowedIPs routes everything, which is the common case.
        assertEquals(listOf("0.0.0.0/0", "::/0"), parsed.peer.allowedIps)
    }

    @Test
    fun `a pre-shared key is read when present`() {
        val psk = WireGuardCrypto.encodeKey(ByteArray(32) { 9 })
        val parsed = WireGuardConfig.parse(config(extraPeer = "PresharedKey = $psk"))
        assertArrayEquals(ByteArray(32) { 9 }, parsed.peer.presharedKey)
    }

    // MARK: - Endpoints

    @Test
    fun `a bracketed IPv6 endpoint is split correctly`() {
        val parsed = WireGuardConfig.parse(
            config().replace("Endpoint = vpn.example.com:51820", "Endpoint = [2001:db8::1]:51820")
        )
        assertEquals("2001:db8::1", parsed.peer.endpointHost)
        assertEquals(51820, parsed.peer.endpointPort)
    }

    @Test
    fun `an unbracketed IPv6 endpoint is refused rather than truncated`() {
        // Splitting on the last colon would give "2001:db8:" and port 1.
        expectError("2001:db8::1:51820") {
            WireGuardConfig.parse(
                config().replace("Endpoint = vpn.example.com:51820", "Endpoint = 2001:db8::1:51820")
            )
        }
    }

    @Test
    fun `an endpoint without a usable port is refused`() {
        for (endpoint in listOf("example.com", "example.com:", "example.com:abc",
                                "example.com:0", "example.com:70000", ":51820")) {
            expectError(endpoint) {
                WireGuardConfig.parse(
                    config().replace("Endpoint = vpn.example.com:51820", "Endpoint = $endpoint")
                )
            }
        }
    }

    // MARK: - Missing or bad fields

    @Test
    fun `a config missing what it needs says so`() {
        expectError("no private key") {
            WireGuardConfig.parse("[Interface]\n\n[Peer]\nPublicKey = $peerKey\nEndpoint = a.b:1")
        }
        expectError("no peer") {
            WireGuardConfig.parse("[Interface]\nPrivateKey = $privateKey")
        }
        expectError("no peer public key") {
            WireGuardConfig.parse("[Interface]\nPrivateKey = $privateKey\n\n[Peer]\nEndpoint = a.b:1")
        }
        expectError("no endpoint") {
            WireGuardConfig.parse("[Interface]\nPrivateKey = $privateKey\n\n[Peer]\nPublicKey = $peerKey")
        }
    }

    @Test
    fun `a key of the wrong length is refused, not silently truncated`() {
        val short = java.util.Base64.getEncoder().encodeToString(ByteArray(16))
        expectError("short private key") {
            WireGuardConfig.parse(config().replace(privateKey, short))
        }
        expectError("short peer key") {
            WireGuardConfig.parse(config().replace(peerKey, short))
        }
    }

    @Test
    fun `only the first peer is used`() {
        // Silently dialling a peer the user did not expect would be worse than
        // ignoring the extras.
        val otherKey = WireGuardCrypto.encodeKey(ByteArray(32) { 5 })
        val parsed = WireGuardConfig.parse(
            config() + "\n\n[Peer]\nPublicKey = $otherKey\nEndpoint = other.example:9999"
        )
        assertEquals("vpn.example.com", parsed.peer.endpointHost)
        assertArrayEquals(ByteArray(32) { (it * 7).toByte() }, parsed.peer.publicKey)
    }

    // MARK: - AmneziaWG

    @Test
    fun `AmneziaWG parameters are read from the interface section`() {
        val parsed = WireGuardConfig.parse(
            config(
                extraInterface = """
                    Jc = 4
                    Jmin = 40
                    Jmax = 70
                    S1 = 15
                    S2 = 30
                    H1 = 1234567
                    H2 = 7654321
                    H3 = 1122334
                    H4 = 4433221
                """.trimIndent()
            )
        )

        val a = parsed.amnezia
        assertTrue(a.isEnabled)
        assertEquals(4, a.junkPacketCount)
        assertEquals(40, a.junkPacketMinSize)
        assertEquals(70, a.junkPacketMaxSize)
        assertEquals(15, a.initPacketJunkSize)
        assertEquals(30, a.responsePacketJunkSize)
        assertEquals(1234567L, a.initPacketMagicHeader)
        assertEquals(4433221L, a.transportPacketMagicHeader)
        // The full 32-bit value reaches the wire, not just its low byte.
        assertEquals(4433221, a.transportType)
        assertEquals(1234567, a.initiationType)
    }

    @Test
    fun `a key written twice keeps both values`() {
        // wg-quick takes the union of repeated Address, DNS and AllowedIPs
        // lines. Dropping the first would send that whole family in the clear.
        val parsed = WireGuardConfig.parse(
            """
            [Interface]
            PrivateKey = $privateKey
            Address = 10.0.0.2/32
            Address = fd00::2/128
            DNS = 1.1.1.1
            DNS = 8.8.8.8

            [Peer]
            PublicKey = $peerKey
            Endpoint = example.com:51820
            AllowedIPs = 0.0.0.0/0
            AllowedIPs = ::/0
            """.trimIndent()
        )

        assertEquals(listOf("10.0.0.2/32", "fd00::2/128"), parsed.addresses)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), parsed.dnsServers)
        assertEquals(listOf("0.0.0.0/0", "::/0"), parsed.peer.allowedIps)
    }

    @Test
    fun `a repeated single-valued key takes the last one`() {
        val parsed = WireGuardConfig.parse(
            """
            [Interface]
            PrivateKey = $privateKey
            MTU = 1280
            MTU = 1420

            [Peer]
            PublicKey = $peerKey
            Endpoint = example.com:51820
            """.trimIndent()
        )
        assertEquals(1420, parsed.mtu)
    }

    @Test
    fun `the AmneziaWG defaults are plain WireGuard`() {
        val a = AmneziaSettings()
        assertTrue(!a.isEnabled)
        assertEquals(1L, a.initPacketMagicHeader)
        assertEquals(2L, a.responsePacketMagicHeader)
        assertEquals(3L, a.underloadPacketMagicHeader)
        assertEquals(4L, a.transportPacketMagicHeader)
        assertEquals(WireGuardHandshake.MESSAGE_TRANSPORT, a.transportType)
    }

    @Test
    fun `junk sizes stay inside the configured range`() {
        val random = java.security.SecureRandom()
        val settings = AmneziaSettings(junkPacketCount = 5, junkPacketMinSize = 40, junkPacketMaxSize = 70)
        repeat(200) {
            val size = settings.junkSize(random)
            assertTrue("size $size outside 40..70", size in 40..70)
        }

        // A single-value range does not need a random draw at all.
        val fixed = AmneziaSettings(junkPacketMinSize = 50, junkPacketMaxSize = 50)
        assertEquals(50, fixed.junkSize(random))

        // No junk configured means no junk packet.
        assertEquals(0, AmneziaSettings().junkSize(random))
    }

    @Test
    fun `a reversed junk range does not throw`() {
        // Typed the wrong way round in a config someone pasted; it must not
        // take the tunnel down.
        val random = java.security.SecureRandom()
        val settings = AmneziaSettings(junkPacketMinSize = 90, junkPacketMaxSize = 40)
        repeat(50) { assertTrue(settings.junkSize(random) >= 0) }
    }

    private inline fun expectError(label: String, body: () -> Unit) {
        try {
            body()
            fail("expected a WireGuardError for $label")
        } catch (_: WireGuardError) {
            // expected
        }
    }
}
