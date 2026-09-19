package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The data phase.
 *
 * The two sides are built with the keys crossed, the way a real pair is, so a
 * message one produces is read by the other rather than by itself.
 */
class WireGuardTransportTest {

    private val keyA = ByteArray(32) { it.toByte() }
    private val keyB = ByteArray(32) { (it * 3 + 1).toByte() }
    private val indexClient = 0x11111111
    private val indexServer = 0x22222222

    /** The client: sends with A, receives with B. */
    private fun client() = WireGuardTransport(
        sendKey = keyA, receiveKey = keyB,
        peerIndex = indexServer, localIndex = indexClient
    )

    /** The server: the mirror image. */
    private fun server() = WireGuardTransport(
        sendKey = keyB, receiveKey = keyA,
        peerIndex = indexClient, localIndex = indexServer
    )

    // MARK: - Framing

    @Test
    fun `a message carries the peer index and the counter little-endian`() {
        val message = client().encapsulate("packet".toByteArray())

        assertEquals(WireGuardHandshake.MESSAGE_TRANSPORT, WireGuardHandshake.readLe32(message, 0))
        assertEquals(0.toByte(), message[1])
        assertEquals(0.toByte(), message[2])
        assertEquals(0.toByte(), message[3])
        // Addressed to the peer's index, not our own.
        assertEquals(indexServer, WireGuardHandshake.readLe32(message, 4))
        assertEquals(0L, WireGuardHandshake.readLe64(message, 8))
    }

    @Test
    fun `the counter advances by one per packet`() {
        val transport = client()
        for (expected in 0L until 5L) {
            val message = transport.encapsulate("x".toByteArray())
            assertEquals(expected, WireGuardHandshake.readLe64(message, 8))
        }
        assertEquals(5L, transport.packetsSent)
    }

    @Test
    fun `the plaintext is padded to a multiple of sixteen`() {
        // Padding is what stops the ciphertext length being the packet length.
        for (size in listOf(1, 15, 16, 17, 31, 32, 100)) {
            val message = client().encapsulate(ByteArray(size))
            val ciphertext = message.size - WireGuardTransport.HEADER_SIZE - WireGuardCrypto.TAG_SIZE
            assertEquals("size $size", 0, ciphertext % 16)
            assertTrue("size $size", ciphertext >= size)
            assertTrue("size $size", ciphertext < size + 16)
        }
        // An empty packet — a keepalive — is not padded up to a full block.
        val keepalive = client().encapsulate(ByteArray(0))
        assertEquals(
            WireGuardTransport.HEADER_SIZE + WireGuardCrypto.TAG_SIZE,
            keepalive.size
        )
    }

    // MARK: - Round trip

    @Test
    fun `what the client sends the server reads`() {
        val client = client()
        val server = server()

        for (i in 0 until 10) {
            val packet = ByteArray(40) { (i + it).toByte() }
            val opened = server.decapsulate(client.encapsulate(packet))
            assertNotNull("packet $i", opened)
            // Padding rides along; the real length comes from the IP header.
            assertArrayEquals(packet, opened!!.copyOfRange(0, packet.size))
        }
    }

    @Test
    fun `a keepalive opens to nothing`() {
        val opened = server().decapsulate(client().encapsulate(ByteArray(0)))
        assertNotNull(opened)
        assertEquals(0, opened!!.size)
    }

    // MARK: - Rejection

    @Test
    fun `a message for another session is ignored`() {
        val message = client().encapsulate("x".toByteArray())

        // Addressed to somebody else's index.
        val misaddressed = message.copyOf()
        WireGuardHandshake.writeLe32(misaddressed, 4, 0x99999999.toInt())
        assertNull(server().decapsulate(misaddressed))

        // Not a transport message.
        val wrongType = message.copyOf()
            .also { WireGuardHandshake.writeLe32(it, 0, WireGuardHandshake.MESSAGE_INITIATION) }
        assertNull(server().decapsulate(wrongType))
    }

    @Test
    fun `a tampered or truncated message is ignored`() {
        val message = client().encapsulate(ByteArray(64))

        for (cut in 0 until WireGuardTransport.HEADER_SIZE + WireGuardCrypto.TAG_SIZE) {
            assertNull("cut=$cut", server().decapsulate(message.copyOfRange(0, cut)))
        }

        val tampered = message.copyOf().also {
            it[WireGuardTransport.HEADER_SIZE] = (it[WireGuardTransport.HEADER_SIZE].toInt() xor 1).toByte()
        }
        assertNull(server().decapsulate(tampered))
    }

    @Test
    fun `the wrong key does not open the message`() {
        val message = client().encapsulate("x".toByteArray())
        val stranger = WireGuardTransport(
            sendKey = ByteArray(32), receiveKey = ByteArray(32),
            peerIndex = indexClient, localIndex = indexServer
        )
        assertNull(stranger.decapsulate(message))
    }

    // MARK: - Replay window

    @Test
    fun `the same packet is not accepted twice`() {
        val client = client()
        val server = server()

        val message = client.encapsulate("x".toByteArray())
        assertNotNull(server.decapsulate(message))
        assertNull("a replay was accepted", server.decapsulate(message))
    }

    @Test
    fun `packets that arrive out of order are still accepted`() {
        // Reordering is normal on any real path; only a repeat is a replay.
        val client = client()
        val server = server()

        val messages = (0 until 10).map { client.encapsulate(byteArrayOf(it.toByte())) }
        for (message in messages.reversed()) {
            assertNotNull(server.decapsulate(message))
        }
        // And none of them a second time.
        for (message in messages) {
            assertNull(server.decapsulate(message))
        }
    }

    @Test
    fun `a packet older than the window is refused`() {
        val client = client()
        val server = server()

        val first = client.encapsulate("first".toByteArray())

        // Move the window well past it.
        val window = WireGuardTransport.WINDOW_SIZE.toInt()
        for (i in 0 until window + 10) {
            client.encapsulate(byteArrayOf(i.toByte()))
        }
        val recent = client.encapsulate("recent".toByteArray())
        assertNotNull(server.decapsulate(recent))

        // The first one is now too far behind to be distinguishable from a
        // replay, so it goes.
        assertNull(server.decapsulate(first))
    }

    @Test
    fun `a large jump forward does not leave stale bits behind`() {
        // After the window slides, the counters it moved over must read as
        // unseen — otherwise a later packet landing on a stale bit is dropped
        // as a replay it never was.
        val client = client()
        val server = server()

        client.encapsulate("x".toByteArray())                       // counter 0
        val zero = WireGuardHandshake.readLe64(
            client().encapsulate("x".toByteArray()), 8
        )
        assertEquals(0L, zero)

        // Skip most of a window, then come back to a counter inside it.
        val skipped = ArrayList<ByteArray>()
        for (i in 0 until 100) skipped.add(client.encapsulate(byteArrayOf(i.toByte())))

        // Deliver the last one first, then the earlier ones: all must be
        // accepted exactly once.
        assertNotNull(server.decapsulate(skipped.last()))
        for (message in skipped.dropLast(1)) {
            assertNotNull(server.decapsulate(message))
        }
        for (message in skipped) {
            assertNull(server.decapsulate(message))
        }
    }

    @Test
    fun `the send limits are positive and ordered`() {
        // A sign error here would make every session look exhausted at counter
        // zero and refuse to send anything at all.
        assertTrue(WireGuardTransport.REKEY_AFTER_MESSAGES > 0)
        assertTrue(WireGuardTransport.REJECT_AFTER_MESSAGES > WireGuardTransport.REKEY_AFTER_MESSAGES)

        val transport = client()
        assertTrue(!transport.needsRekey)
        assertTrue(!transport.isExhausted)
        transport.encapsulate("x".toByteArray())
    }

    // MARK: - AmneziaWG type renumbering

    @Test
    fun `a renumbered transport type is used on both sides`() {
        // AmneziaWG replaces the four message types so a filter matching on
        // WireGuard's constants sees nothing it recognises. H4 is required to
        // exceed 4 and is generated up to 2^31, so it does not fit in a byte.
        val type = 0x70609579
        val client = WireGuardTransport(keyA, keyB, indexServer, indexClient, transportType = type)
        val server = WireGuardTransport(keyB, keyA, indexClient, indexServer, transportType = type)

        val message = client.encapsulate("x".toByteArray())
        assertNotNull(server.decapsulate(message))

        // Asserted against the bytes a peer reads, not against our own writer:
        // a round trip alone passes just as happily when both sides truncate.
        assertEquals(0x79.toByte(), message[0])
        assertEquals(0x95.toByte(), message[1])
        assertEquals(0x60.toByte(), message[2])
        assertEquals(0x70.toByte(), message[3])

        // A peer still expecting the standard type does not read it.
        val standard = WireGuardTransport(keyB, keyA, indexClient, indexServer)
        assertNull(standard.decapsulate(message))
    }

    @Test
    fun `two headers sharing a low byte are told apart`() {
        // The whole 32-bit word is the type. Comparing only its low byte would
        // let one AmneziaWG peer's traffic be accepted as another's.
        val ours = 0x11223344
        val theirs = 0x55667744

        val client = WireGuardTransport(keyA, keyB, indexServer, indexClient, transportType = theirs)
        val server = WireGuardTransport(keyB, keyA, indexClient, indexServer, transportType = ours)

        assertNull(server.decapsulate(client.encapsulate("x".toByteArray())))
    }

    @Test
    fun `plain WireGuard still writes type 4 with three zero bytes`() {
        val message = client().encapsulate("x".toByteArray())
        assertEquals(4.toByte(), message[0])
        assertEquals(0.toByte(), message[1])
        assertEquals(0.toByte(), message[2])
        assertEquals(0.toByte(), message[3])
    }
}
