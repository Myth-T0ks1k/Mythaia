package com.mythaia.vpn.protocol.shadowsocks

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * The first write of a Shadowsocks connection, decoded the way a server
 * would decode it.
 *
 * The address header rides the first write, so the client flushes it at
 * connect time even when the app has nothing to send yet. For AEAD that is a
 * chunk holding only the header; for 2022 it is a request whose initial
 * payload is empty and whose padding is therefore mandatory. And a first
 * write may be everything the app queued during the dial — hundreds of KB —
 * which the 2022 variable-length header cannot hold on its own.
 */
class ShadowsocksConnectionTest {

    private class RecordingTransport : Transport {
        private val out = ByteArrayOutputStream()
        var writes = 0
            private set

        override suspend fun send(data: ByteArray) { out.write(data); writes++ }
        override fun sendAsync(data: ByteArray) { out.write(data); writes++ }
        override suspend fun receive(): ByteArray? = null
        override fun forceCancel() = Unit

        fun sent(): ByteArray = out.toByteArray()
    }

    private val random = SecureRandom()
    private val addressHeader = ShadowsocksProtocol.buildAddressHeader("example.com", 443)

    // MARK: - AEAD

    @Test
    fun `an empty first write is one chunk carrying only the address header`() = runBlocking {
        val cipher = ShadowsocksCipher.AES_128_GCM
        val masterKey = ShadowsocksKeyDerivation.deriveKey("pw", cipher.keySize)
        val transport = RecordingTransport()
        val connection = ShadowsocksConnection(transport, cipher, masterKey, addressHeader)

        connection.send(ByteArray(0))

        assertEquals(1, transport.writes)
        // salt + sealed length + sealed header: nothing more.
        assertEquals(cipher.saltSize + (2 + 16) + (addressHeader.size + 16), transport.sent().size)
        assertArrayEquals(addressHeader, ShadowsocksAEADReader(cipher, masterKey).open(transport.sent()))
    }

    // MARK: - 2022

    /** What a server reads back from a client request, chunk by chunk. */
    private class DecodedRequest(
        val variableHeaderLength: Int,
        val paddingLength: Int,
        val initialPayload: ByteArray,
        val chunkLengths: List<Int>,
        val payload: ByteArray
    )

    /**
     * Decodes [wire] as the server would: salt, the sealed fixed header, the
     * sealed variable header, then ordinary length/payload chunk pairs until
     * the bytes run out. Throws if anything is left over or short.
     */
    private fun decode(wire: ByteArray, cipher: ShadowsocksCipher, psk: ByteArray): DecodedRequest {
        val keySize = cipher.keySize
        var at = 0
        val salt = wire.copyOfRange(at, at + keySize); at += keySize
        val key = ShadowsocksKeyDerivation.deriveSessionKey(psk, salt, keySize)
        val nonce = ShadowsocksNonce(cipher.nonceSize)

        fun open(length: Int): ByteArray {
            val sealed = wire.copyOfRange(at, at + length + 16); at += length + 16
            return ShadowsocksAEADCrypto.open(cipher, key, nonce.next(), sealed)
        }

        val fixed = open(11)
        assertEquals(0.toByte(), fixed[0])
        val variableLength = ((fixed[9].toInt() and 0xFF) shl 8) or (fixed[10].toInt() and 0xFF)

        val variable = open(variableLength)
        assertArrayEquals(addressHeader, variable.copyOfRange(0, addressHeader.size))
        var v = addressHeader.size
        val paddingLength = ((variable[v].toInt() and 0xFF) shl 8) or (variable[v + 1].toInt() and 0xFF)
        v += 2 + paddingLength
        val initialPayload = variable.copyOfRange(v, variable.size)

        val chunkLengths = ArrayList<Int>()
        val payload = ByteArrayOutputStream()
        payload.write(initialPayload)
        while (at < wire.size) {
            val lengthBytes = open(2)
            val length = ((lengthBytes[0].toInt() and 0xFF) shl 8) or (lengthBytes[1].toInt() and 0xFF)
            chunkLengths.add(length)
            payload.write(open(length))
        }
        assertEquals("every byte of the write is accounted for", wire.size, at)

        return DecodedRequest(variableLength, paddingLength, initialPayload, chunkLengths, payload.toByteArray())
    }

    @Test
    fun `a 2022 request with no payload still carries padding`() = runBlocking {
        val cipher = ShadowsocksCipher.BLAKE3_AES_128_GCM
        val psk = ByteArray(cipher.keySize).also { random.nextBytes(it) }
        val transport = RecordingTransport()
        val connection = Shadowsocks2022Connection(transport, cipher, listOf(psk), addressHeader)

        connection.send(ByteArray(0))

        val decoded = decode(transport.sent(), cipher, psk)
        assertTrue("padding ${decoded.paddingLength}", decoded.paddingLength in 1..900)
        assertEquals(0, decoded.initialPayload.size)
        assertEquals(addressHeader.size + 2 + decoded.paddingLength, decoded.variableHeaderLength)
        assertEquals(emptyList<Int>(), decoded.chunkLengths)
    }

    @Test
    fun `a large 2022 first write spills from the header into chunks`() = runBlocking {
        val cipher = ShadowsocksCipher.BLAKE3_AES_128_GCM
        val psk = ByteArray(cipher.keySize).also { random.nextBytes(it) }
        val transport = RecordingTransport()
        val connection = Shadowsocks2022Connection(transport, cipher, listOf(psk), addressHeader)

        val payload = ByteArray(100 * 1024) { (it % 251).toByte() }
        connection.send(payload)

        assertEquals("one write", 1, transport.writes)
        val decoded = decode(transport.sent(), cipher, psk)
        assertTrue(
            "variable header ${decoded.variableHeaderLength} exceeds a chunk",
            decoded.variableHeaderLength <= ShadowsocksAEADWriter.MAX_PAYLOAD_SIZE
        )
        assertEquals("a payload this large is not padded", 0, decoded.paddingLength)
        for (length in decoded.chunkLengths) {
            assertTrue("chunk $length exceeds the limit", length in 1..ShadowsocksAEADWriter.MAX_PAYLOAD_SIZE)
        }
        assertTrue("the remainder went out as chunks", decoded.chunkLengths.isNotEmpty())
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun `a small 2022 first write fits the header and is padded`() = runBlocking {
        val cipher = ShadowsocksCipher.BLAKE3_CHACHA20_POLY1305
        val psk = ByteArray(cipher.keySize).also { random.nextBytes(it) }
        val transport = RecordingTransport()
        val connection = Shadowsocks2022Connection(transport, cipher, listOf(psk), addressHeader)

        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        connection.send(payload)

        val decoded = decode(transport.sent(), cipher, psk)
        assertTrue(decoded.paddingLength in 1..900)
        assertArrayEquals(payload, decoded.initialPayload)
        assertEquals(emptyList<Int>(), decoded.chunkLengths)
    }
}
