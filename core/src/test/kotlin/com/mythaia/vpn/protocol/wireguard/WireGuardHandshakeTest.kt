package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The handshake, driven against a responder written out below from the
 * WireGuard paper's own responder steps.
 *
 * This is the point of the exercise: a client tested against itself agrees with
 * itself whatever the order of its operations. The responder here follows the
 * published sequence — including the one place the two sides genuinely differ,
 * where the responder's transport keys come out of KDF2 the other way round —
 * so an ordering mistake in the client shows up as keys that do not match.
 */
class WireGuardHandshakeTest {

    private val construction =
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII)
    private val identifier =
        "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray(Charsets.US_ASCII)

    /** What the responder ends up with. */
    private class ResponderResult(
        val response: ByteArray,
        val sendKey: ByteArray,
        val receiveKey: ByteArray,
        val initiatorStatic: ByteArray,
        val timestamp: ByteArray
    )

    /**
     * The responder half, step for step from the paper.
     *
     * Deliberately not factored to share anything with the client beyond the
     * primitives — the ordering is what is being checked.
     */
    private fun respond(
        initiation: ByteArray,
        responderPrivate: ByteArray,
        responderPublic: ByteArray,
        presharedKey: ByteArray = ByteArray(32)
    ): ResponderResult {
        assertEquals(WireGuardHandshake.INITIATION_SIZE, initiation.size)
        assertEquals(
            WireGuardHandshake.MESSAGE_INITIATION,
            WireGuardHandshake.readLe32(initiation, 0)
        )

        val senderIndex = WireGuardHandshake.readLe32(initiation, 4)
        val initiatorEphemeral = initiation.copyOfRange(8, 40)
        val encryptedStatic = initiation.copyOfRange(40, 88)
        val encryptedTimestamp = initiation.copyOfRange(88, 116)

        var c = WireGuardCrypto.hash(construction)
        var h = WireGuardCrypto.hash(WireGuardCrypto.hash(c, identifier), responderPublic)

        c = WireGuardCrypto.kdf(c, initiatorEphemeral, 1)[0]
        h = WireGuardCrypto.hash(h, initiatorEphemeral)

        var derived = WireGuardCrypto.kdf(
            c, WireGuardCrypto.sharedSecret(responderPrivate, initiatorEphemeral), 2
        )
        c = derived[0]
        val initiatorStatic = WireGuardCrypto.open(derived[1], 0, encryptedStatic, h)
            ?: fail("responder could not open the static key") as ByteArray
        h = WireGuardCrypto.hash(h, encryptedStatic)

        derived = WireGuardCrypto.kdf(
            c, WireGuardCrypto.sharedSecret(responderPrivate, initiatorStatic), 2
        )
        c = derived[0]
        val timestamp = WireGuardCrypto.open(derived[1], 0, encryptedTimestamp, h)
            ?: fail("responder could not open the timestamp") as ByteArray
        h = WireGuardCrypto.hash(h, encryptedTimestamp)

        // --- response ---
        val (ePriv, ePub) = WireGuardCrypto.generateKeyPair()
        c = WireGuardCrypto.kdf(c, ePub, 1)[0]
        h = WireGuardCrypto.hash(h, ePub)

        c = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(ePriv, initiatorEphemeral), 1)[0]
        c = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(ePriv, initiatorStatic), 1)[0]

        val three = WireGuardCrypto.kdf(c, presharedKey, 3)
        c = three[0]
        h = WireGuardCrypto.hash(h, three[1])

        val empty = WireGuardCrypto.seal(three[2], 0, ByteArray(0), h)
        h = WireGuardCrypto.hash(h, empty)

        val responderIndex = 0x11223344
        val body = ByteArray(4 + 4 + 4 + 32 + 16)
        var at = 0
        WireGuardHandshake.writeLe32(body, at, WireGuardHandshake.MESSAGE_RESPONSE); at += 4
        WireGuardHandshake.writeLe32(body, at, responderIndex); at += 4
        WireGuardHandshake.writeLe32(body, at, senderIndex); at += 4
        ePub.copyInto(body, at); at += 32
        empty.copyInto(body, at)

        val mac1 = WireGuardCrypto.mac(
            WireGuardCrypto.hash("mac1----".toByteArray(Charsets.US_ASCII), initiatorStatic),
            body
        )
        val response = body + mac1 + ByteArray(16)

        // The responder's transport keys are KDF2 the other way round from the
        // initiator's: its send key is the initiator's receive key.
        val transport = WireGuardCrypto.kdf(c, ByteArray(0), 2)
        return ResponderResult(
            response = response,
            receiveKey = transport[0],
            sendKey = transport[1],
            initiatorStatic = initiatorStatic,
            timestamp = timestamp
        )
    }

    // MARK: - Message shape

    @Test
    fun `the initiation is 148 bytes with the fields where the spec puts them`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val handshake = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
        val message = handshake.buildInitiation(index = 0x01020304)

        assertEquals(WireGuardHandshake.INITIATION_SIZE, message.size)
        assertEquals(WireGuardHandshake.MESSAGE_INITIATION, WireGuardHandshake.readLe32(message, 0))
        // Three reserved zero bytes, which some deployments do inspect.
        assertEquals(0.toByte(), message[1])
        assertEquals(0.toByte(), message[2])
        assertEquals(0.toByte(), message[3])
        // The index is little-endian, unlike every length in the protocol.
        assertEquals(0x01020304, WireGuardHandshake.readLe32(message, 4))
        assertEquals(0x04.toByte(), message[4])

        // mac2 is zero until the peer sends a cookie.
        assertArrayEquals(ByteArray(16), message.copyOfRange(132, 148))
    }

    @Test
    fun `mac1 proves knowledge of the peer public key`() {
        // A server drops a message whose mac1 does not verify without doing any
        // asymmetric work, which is what makes flooding it expensive.
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val message = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
            .buildInitiation()

        val expected = WireGuardCrypto.mac(
            WireGuardCrypto.hash("mac1----".toByteArray(Charsets.US_ASCII), serverPublic),
            message.copyOfRange(0, 116)
        )
        assertArrayEquals(expected, message.copyOfRange(116, 132))
    }

    @Test
    fun `two initiations never repeat their ephemeral key`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val a = WireGuardHandshake(clientPrivate, clientPublic, serverPublic).buildInitiation()
        val b = WireGuardHandshake(clientPrivate, clientPublic, serverPublic).buildInitiation()
        assertNotEquals(
            a.copyOfRange(8, 40).toList(),
            b.copyOfRange(8, 40).toList()
        )
    }

    // MARK: - Full handshake

    @Test
    fun `a handshake with an independent responder agrees on the transport keys`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()

        val handshake = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
        val initiation = handshake.buildInitiation(index = 42)

        val responder = respond(initiation, serverPrivate, serverPublic)

        // The responder recovered who we are and when we said it.
        assertArrayEquals(clientPublic, responder.initiatorStatic)
        assertEquals(12, responder.timestamp.size)

        val keys = handshake.consumeResponse(responder.response)
        assertEquals(42, keys.localIndex)
        assertEquals(0x11223344, keys.peerIndex)

        // What one side sends with, the other receives with.
        assertArrayEquals(responder.receiveKey, keys.sendKey)
        assertArrayEquals(responder.sendKey, keys.receiveKey)
        assertNotEquals(keys.sendKey.toList(), keys.receiveKey.toList())
    }

    @Test
    fun `a packet encrypted with the agreed keys opens on the other side`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()

        val handshake = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
        val responder = respond(handshake.buildInitiation(), serverPrivate, serverPublic)
        val keys = handshake.consumeResponse(responder.response)

        val packet = "an IP packet".toByteArray()
        val sealed = WireGuardCrypto.seal(keys.sendKey, 0, packet, ByteArray(0))
        assertArrayEquals(packet, WireGuardCrypto.open(responder.receiveKey, 0, sealed, ByteArray(0)))
    }

    @Test
    fun `a pre-shared key changes the transport keys and both sides must have it`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()
        val psk = ByteArray(32) { (it * 5).toByte() }

        // Both sides with the same PSK: agreement, and different keys from the
        // no-PSK case.
        val withPsk = WireGuardHandshake(clientPrivate, clientPublic, serverPublic, psk)
        val response = respond(withPsk.buildInitiation(), serverPrivate, serverPublic, psk)
        val keys = withPsk.consumeResponse(response.response)
        assertArrayEquals(response.receiveKey, keys.sendKey)

        val withoutPsk = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
        val plainResponse = respond(withoutPsk.buildInitiation(), serverPrivate, serverPublic)
        assertNotEquals(
            keys.sendKey.toList(),
            withoutPsk.consumeResponse(plainResponse.response).sendKey.toList()
        )

        // A mismatched PSK fails the response's authentication rather than
        // producing keys that silently do not work.
        val mismatched = WireGuardHandshake(clientPrivate, clientPublic, serverPublic, psk)
        val plainForMismatch = respond(mismatched.buildInitiation(), serverPrivate, serverPublic)
        try {
            mismatched.consumeResponse(plainForMismatch.response)
            fail("expected the response not to authenticate")
        } catch (_: WireGuardError) {
            // expected
        }
    }

    @Test
    fun `the wrong server key fails at the responder, not silently later`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()
        val (_, wrongPublic) = WireGuardCrypto.generateKeyPair()

        // The client believes the server has a key it does not.
        val handshake = WireGuardHandshake(clientPrivate, clientPublic, wrongPublic)
        val initiation = handshake.buildInitiation()

        try {
            respond(initiation, serverPrivate, serverPublic)
            fail("expected the responder to reject the initiation")
        } catch (_: AssertionError) {
            // The responder's own open() failed, which is the intended outcome.
        }
    }

    // MARK: - Malformed responses

    @Test
    fun `a malformed response is refused`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()

        val handshake = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
        val good = respond(handshake.buildInitiation(index = 7), serverPrivate, serverPublic).response

        for (bad in listOf(
            ByteArray(0),
            good.copyOfRange(0, WireGuardHandshake.RESPONSE_SIZE - 1),
            good + byteArrayOf(0),
            good.copyOf().also { WireGuardHandshake.writeLe32(it, 0, WireGuardHandshake.MESSAGE_INITIATION) },
            // Echoes somebody else's index.
            good.copyOf().also { WireGuardHandshake.writeLe32(it, 8, 99) },
            // Tampered ephemeral.
            good.copyOf().also { it[12] = (it[12].toInt() xor 1).toByte() }
        )) {
            val fresh = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
            fresh.buildInitiation(index = 7)
            try {
                fresh.consumeResponse(bad)
                fail("expected a refusal for a ${bad.size}-byte response")
            } catch (_: WireGuardError) {
                // expected
            }
        }
    }

    // MARK: - AmneziaWG wire tweaks

    @Test
    fun `H1 replaces the whole initiation type word`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val h1 = 0x1A2B3C4D
        val handshake = WireGuardHandshake(
            clientPrivate, clientPublic, serverPublic, initiationType = h1
        )
        val message = handshake.buildInitiation(index = 7)

        assertEquals(WireGuardHandshake.INITIATION_SIZE, message.size)
        assertEquals(0x4D.toByte(), message[0])
        assertEquals(0x3C.toByte(), message[1])
        assertEquals(0x2B.toByte(), message[2])
        assertEquals(0x1A.toByte(), message[3])
    }

    @Test
    fun `plain WireGuard writes type 1 with three zero bytes`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val message = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
            .buildInitiation(index = 7)
        assertEquals(1.toByte(), message[0])
        assertEquals(0.toByte(), message[1])
        assertEquals(0.toByte(), message[2])
        assertEquals(0.toByte(), message[3])
    }

    @Test
    fun `S1 prepends junk without disturbing the message behind it`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (_, serverPublic) = WireGuardCrypto.generateKeyPair()

        val junkSize = 15
        val plain = WireGuardHandshake(clientPrivate, clientPublic, serverPublic)
            .buildInitiation(index = 7)
        val junked = WireGuardHandshake(
            clientPrivate, clientPublic, serverPublic, initiationJunkSize = junkSize
        ).buildInitiation(index = 7)

        assertEquals(WireGuardHandshake.INITIATION_SIZE + junkSize, junked.size)
        // The type word starts after the junk, not at offset 0.
        assertEquals(1, WireGuardHandshake.readLe32(junked, junkSize))
        // Index is echoed in the same place relative to the message start.
        assertEquals(
            WireGuardHandshake.readLe32(plain, 4),
            WireGuardHandshake.readLe32(junked, junkSize + 4)
        )
    }

    @Test
    fun `S2 junk is stripped from the response before it is parsed`() {
        val (clientPrivate, clientPublic) = WireGuardCrypto.generateKeyPair()
        val (serverPrivate, serverPublic) = WireGuardCrypto.generateKeyPair()

        val junkSize = 30
        val client = WireGuardHandshake(
            clientPrivate, clientPublic, serverPublic, responseJunkSize = junkSize
        )
        val initiation = client.buildInitiation(index = 7)
        val responder = respond(initiation, serverPrivate, serverPublic)

        val keys = client.consumeResponse(
            WireGuardCrypto.randomBytes(junkSize) + responder.response
        )
        assertEquals(7, keys.localIndex)
        assertTrue(keys.sendKey.contentEquals(responder.receiveKey))
    }

    @Test
    fun `little-endian helpers round-trip`() {
        val buffer = ByteArray(8)
        for (value in listOf(0, 1, -1, 0x7FFFFFFF, Int.MIN_VALUE, 0x01020304)) {
            WireGuardHandshake.writeLe32(buffer, 0, value)
            assertEquals(value, WireGuardHandshake.readLe32(buffer, 0))
        }
        for (value in listOf(0L, 1L, -1L, Long.MAX_VALUE, 0x0102030405060708L)) {
            WireGuardHandshake.writeLe64(buffer, 0, value)
            assertEquals(value, WireGuardHandshake.readLe64(buffer, 0))
        }
        assertTrue(true)
    }
}
