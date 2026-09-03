package com.mythaia.vpn.protocol.vmess

import com.mythaia.data.model.ProxyError
import org.bouncycastle.crypto.digests.SHAKEDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * VMess body framing: a two-byte length, then one AEAD-sealed chunk, repeated.
 *
 * With ChunkMasking the length is XORed with a SHAKE128 stream seeded by the
 * body IV, so an observer sees no plaintext sizes; with GlobalPadding the same
 * stream also decides how many random bytes follow each chunk, so the sizes it
 * does see mean nothing either. Both sides advance the stream in lockstep, one
 * draw per chunk — which is why a mask must never be taken speculatively.
 */
class VmessChunkStream(
    private val key: ByteArray,
    private val iv: ByteArray,
    private val security: VmessSecurity,
    private val masking: Boolean,
    private val globalPadding: Boolean
) {

    /** The largest value the two-byte length field can hold. */
    private val maxChunk = 16 * 1024 - 1

    private companion object {
        /** GlobalPadding draws its length from the mask modulo this. */
        const val MAX_PADDING = 64
    }

    private val shake: SHAKEDigest? = if (masking || globalPadding) {
        SHAKEDigest(128).apply { update(iv, 0, iv.size) }
    } else {
        null
    }

    private var count = 0
    private val shakeBuffer = ByteArray(2)

    /** The next two bytes of the mask stream, as an unsigned 16-bit value. */
    private fun nextMask(): Int {
        val digest = shake ?: return 0
        digest.doOutput(shakeBuffer, 0, 2)
        return ((shakeBuffer[0].toInt() and 0xFF) shl 8) or (shakeBuffer[1].toInt() and 0xFF)
    }

    /**
     * The AEAD nonce for chunk [index]: a big-endian counter followed by ten
     * bytes of the body IV.
     */
    private fun nonce(index: Int): ByteArray {
        val out = ByteArray(12)
        out[0] = ((index shr 8) and 0xFF).toByte()
        out[1] = (index and 0xFF).toByte()
        iv.copyInto(out, 2, 2, 12)
        return out
    }

    private fun seal(plaintext: ByteArray, index: Int): ByteArray = when (security) {
        VmessSecurity.AES_128_GCM -> {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, nonce(index))
            )
            cipher.doFinal(plaintext)
        }
        VmessSecurity.CHACHA20_POLY1305 -> {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(chachaKey(), "ChaCha20"),
                IvParameterSpec(nonce(index))
            )
            cipher.doFinal(plaintext)
        }
        VmessSecurity.NONE, VmessSecurity.ZERO -> plaintext
    }

    private fun open(ciphertext: ByteArray, index: Int): ByteArray? = try {
        when (security) {
            VmessSecurity.AES_128_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, nonce(index))
                )
                cipher.doFinal(ciphertext)
            }
            VmessSecurity.CHACHA20_POLY1305 -> {
                val cipher = Cipher.getInstance("ChaCha20-Poly1305")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(chachaKey(), "ChaCha20"),
                    IvParameterSpec(nonce(index))
                )
                cipher.doFinal(ciphertext)
            }
            VmessSecurity.NONE, VmessSecurity.ZERO -> ciphertext
        }
    } catch (_: Exception) {
        null
    }

    /**
     * ChaCha20-Poly1305 wants 32 bytes; VMess supplies 16, and the protocol
     * stretches them as MD5(key) ‖ MD5(MD5(key)).
     */
    private fun chachaKey(): ByteArray {
        val md5 = java.security.MessageDigest.getInstance("MD5")
        val first = md5.digest(key)
        md5.reset()
        val second = md5.digest(first)
        return first + second
    }

    private val tagSize: Int
        get() = when (security) {
            VmessSecurity.AES_128_GCM, VmessSecurity.CHACHA20_POLY1305 -> 16
            VmessSecurity.NONE, VmessSecurity.ZERO -> 0
        }

    /**
     * [plaintext] as one or more framed chunks, ready for the wire.
     *
     * Nothing in means nothing out: an empty chunk is the end-of-stream marker,
     * so writing one here would close the stream by accident. Use
     * [encodeTerminator] when that is what is meant.
     */
    fun encode(plaintext: ByteArray): ByteArray {
        if (plaintext.isEmpty()) return ByteArray(0)

        val out = java.io.ByteArrayOutputStream(plaintext.size + 64)
        var offset = 0
        while (offset < plaintext.size) {
            val take = minOf(payloadPerChunk, plaintext.size - offset)
            writeChunk(out, plaintext.copyOfRange(offset, offset + take))
            offset += take
        }
        return out.toByteArray()
    }

    /**
     * The most plaintext one chunk carries, leaving room for the tag and for
     * the largest padding the mask stream can ask for.
     */
    private val payloadPerChunk: Int
        get() = maxChunk - tagSize - MAX_PADDING

    /** The empty chunk that tells the peer the stream is finished. */
    fun encodeTerminator(): ByteArray {
        val out = java.io.ByteArrayOutputStream(4)
        writeChunk(out, ByteArray(0))
        return out.toByteArray()
    }

    private fun writeChunk(out: java.io.ByteArrayOutputStream, plaintext: ByteArray) {
        // The mask and the padding length come from one draw each, in this
        // order, and the peer draws them the same way.
        val mask = nextMask()
        val paddingLength = if (globalPadding) mask % MAX_PADDING else 0

        val sealed = seal(plaintext, count)
        val onWire = sealed.size + paddingLength
        val length = if (masking) onWire xor mask else onWire

        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(sealed)
        if (paddingLength > 0) {
            val padding = ByteArray(paddingLength)
            java.security.SecureRandom().nextBytes(padding)
            out.write(padding)
        }
        count++
    }

    /** How a decode attempt ended. */
    sealed class Decoded {
        /** Not enough bytes yet; call again once more have arrived. */
        object NeedMore : Decoded()

        /** The peer sent its terminating empty chunk. */
        object EndOfStream : Decoded()

        class Chunk(val payload: ByteArray, val consumed: Int) : Decoded()
    }

    /**
     * Reads one chunk from the front of [input].
     *
     * The chunk counter and the mask stream only advance on a complete chunk,
     * so a partial read can be retried with more bytes and lands in the same
     * place.
     */
    fun decode(input: ByteArray, from: Int): Decoded {
        if (input.size - from < 2) return Decoded.NeedMore

        // Peek the mask without consuming it: the stream must not advance
        // unless the whole chunk is here.
        val digest = shake?.let { SHAKEDigest(it) }
        val mask = if (digest != null) {
            val buffer = ByteArray(2)
            digest.doOutput(buffer, 0, 2)
            ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
        } else {
            0
        }

        val raw = ((input[from].toInt() and 0xFF) shl 8) or (input[from + 1].toInt() and 0xFF)
        val onWire = if (masking) raw xor mask else raw
        val paddingLength = if (globalPadding) mask % MAX_PADDING else 0

        if (onWire < paddingLength || onWire > maxChunk) {
            throw ProxyError.ProtocolError("VMess: chunk length $onWire is not plausible")
        }
        if (input.size - from - 2 < onWire) return Decoded.NeedMore

        val sealedLength = onWire - paddingLength
        // An empty payload seals to exactly the tag, or to nothing at all when
        // the body is unencrypted.
        if ((tagSize > 0 && sealedLength == tagSize) || sealedLength == 0) {
            // An empty payload is the end-of-stream marker.
            advanceMask()
            return Decoded.EndOfStream
        }

        val sealed = input.copyOfRange(from + 2, from + 2 + sealedLength)
        val payload = open(sealed, count)
            ?: throw ProxyError.ProtocolError("VMess: chunk failed authentication")

        advanceMask()
        count++
        return Decoded.Chunk(payload, 2 + onWire)
    }

    /** Consumes the mask draw that [decode] peeked. */
    private fun advanceMask() {
        if (shake != null) nextMask()
    }
}
