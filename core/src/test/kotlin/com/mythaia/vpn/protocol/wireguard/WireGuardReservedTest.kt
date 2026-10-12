package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Cloudflare WARP's `Reserved` bytes: how configs spell them, and where they
 * go on the wire.
 */
class WireGuardReservedTest {

    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    private fun config(extraInterface: String = "", extraPeer: String = "") = """
        [Interface]
        PrivateKey = $privateKey
        Address = 172.16.0.2/32
        $extraInterface

        [Peer]
        PublicKey = $peerKey
        Endpoint = engage.cloudflareclient.com:2408
        $extraPeer
    """.trimIndent()

    // MARK: - Parsing

    @Test
    fun `Reserved is read from the Interface as decimal bytes`() {
        val parsed = WireGuardConfig.parse(config(extraInterface = "Reserved = 12, 34, 56"))
        assertArrayEquals(byteArrayOf(12, 34, 56), parsed.reserved)
        assertArrayEquals(byteArrayOf(12, 34, 56), parsed.headerReserved)
    }

    @Test
    fun `Reserved is read from the Peer and as base64`() {
        // "AQID" is base64 of 01 02 03, the form WARP's API returns client_id in.
        val parsed = WireGuardConfig.parse(config(extraPeer = "Reserved = AQID"))
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.reserved)
    }

    @Test
    fun `the spellings configs use all parse`() {
        assertArrayEquals(byteArrayOf(1, 2, 3), WireGuardConfig.parseReserved("1,2,3"))
        assertArrayEquals(byteArrayOf(1, 2, 3), WireGuardConfig.parseReserved("[1, 2, 3]"))
        assertArrayEquals(byteArrayOf(-1, 0, 127), WireGuardConfig.parseReserved("255,0,127"))
        assertArrayEquals(byteArrayOf(1, 2, 3), WireGuardConfig.parseReserved("AQID"))
        assertNull(WireGuardConfig.parseReserved("1,2"))
        assertNull(WireGuardConfig.parseReserved("1,2,256"))
        assertNull(WireGuardConfig.parseReserved("AQIDBA=="))
        assertNull(WireGuardConfig.parseReserved(""))
    }

    @Test
    fun `an unusable Reserved is refused rather than dropped`() {
        try {
            WireGuardConfig.parse(config(extraInterface = "Reserved = 1,2"))
            fail("expected a refusal")
        } catch (e: WireGuardError) {
            assertTrue(e.message!!.contains("Reserved"))
        }
    }

    @Test
    fun `no Reserved, or all zeroes, leaves the wire alone`() {
        assertNull(WireGuardConfig.parse(config()).reserved)
        assertNull(WireGuardConfig.parse(config()).headerReserved)
        val zeroes = WireGuardConfig.parse(config(extraInterface = "Reserved = 0,0,0"))
        assertNotNull(zeroes.reserved)
        assertNull(zeroes.headerReserved)
    }

    @Test
    fun `AmneziaWG renumbering wins over Reserved`() {
        val parsed = WireGuardConfig.parse(
            config(extraInterface = "Reserved = 1,2,3\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890")
        )
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.reserved)
        assertNull(parsed.headerReserved)

        // Junk alone does not take the type word, so Reserved still applies.
        val junkOnly = WireGuardConfig.parse(config(extraInterface = "Reserved = 1,2,3\nJc = 3\nJmin = 10\nJmax = 20"))
        assertArrayEquals(byteArrayOf(1, 2, 3), junkOnly.headerReserved)
    }

    // MARK: - The wire

    private val reserved = byteArrayOf(0x0A, 0x0B, 0x0C)
    private val keyA = ByteArray(32) { it.toByte() }
    private val keyB = ByteArray(32) { (it * 3 + 1).toByte() }

    @Test
    fun `transport messages carry the reserved bytes after the type`() {
        val client = WireGuardTransport(keyA, keyB, peerIndex = 2, localIndex = 1, reserved = reserved)
        val message = client.encapsulate("packet".toByteArray())

        assertEquals(WireGuardHandshake.MESSAGE_TRANSPORT.toByte(), message[0])
        assertEquals(0x0A.toByte(), message[1])
        assertEquals(0x0B.toByte(), message[2])
        assertEquals(0x0C.toByte(), message[3])
        assertEquals(2, WireGuardHandshake.readLe32(message, 4))
    }

    @Test
    fun `with Reserved set, a received message is matched on its low octet`() {
        val server = WireGuardTransport(keyB, keyA, peerIndex = 1, localIndex = 2)
        val fromServer = server.encapsulate("reply".toByteArray())
        // WARP puts its own bytes into the reserved octets of what it sends.
        fromServer[1] = 0x55; fromServer[2] = 0x66; fromServer[3] = 0x77

        val client = WireGuardTransport(keyA, keyB, peerIndex = 2, localIndex = 1, reserved = reserved)
        assertArrayEquals("reply".toByteArray(), client.decapsulate(fromServer)?.copyOf(5))

        // Plain WireGuard keeps comparing the whole word.
        val plain = WireGuardTransport(keyA, keyB, peerIndex = 2, localIndex = 1)
        assertNull(plain.decapsulate(fromServer))
    }

    @Test
    fun `the type comparison only relaxes when Reserved is in use`() {
        assertTrue(WireGuardHandshake.isType(0x77665504, 4, reserved))
        assertTrue(!WireGuardHandshake.isType(0x77665503, 4, reserved))
        assertTrue(!WireGuardHandshake.isType(0x77665504, 4, null))
        assertTrue(WireGuardHandshake.isType(4, 4, null))
    }
}
