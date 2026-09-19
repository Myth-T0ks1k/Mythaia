package com.mythaia.vpn.protocol.tls.ech

import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation

/**
 * The HPKE half of ECH (RFC 9180 base mode, RFC 9460 §6.1 usage).
 *
 * One context is one ClientHelloOuter: the encapsulated key goes in the
 * extension and the sealing key encrypts exactly one inner hello.
 *
 * Ports the iOS `ECHClientContext` onto BouncyCastle's HPKE, which is already a
 * dependency — the platform has no HPKE below API 35.
 */
class EchClientContext private constructor(
    val config: EchConfig,
    val cipherSuite: EchCipherSuite,
    /** The encapsulated key the server needs to derive the same secret. */
    val enc: ByteArray,
    private val context: HPKEContextWithEncapsulation
) {

    /**
     * Seals the encoded inner ClientHello.
     *
     * [aad] is the serialised ClientHelloOuter without its four-byte handshake
     * header, carrying a payload field of the right length filled with zeroes —
     * the server rebuilds exactly that to verify the tag, so a byte out of
     * place there fails the handshake rather than degrading it.
     */
    fun seal(plaintext: ByteArray, aad: ByteArray): ByteArray = context.seal(aad, plaintext)

    companion object {
        /** Every AEAD ECH uses has a 16-byte tag. */
        const val AEAD_TAG_LENGTH = 16

        /**
         * Sets up a sender against [config].
         *
         * @throws EchError when the config asks for something this build has no
         *         implementation of, which is a reason to fall back to a normal
         *         hello rather than to fail the connection.
         */
        fun create(config: EchConfig, cipherSuite: EchCipherSuite): EchClientContext {
            if (config.kemId != EchKem.DHKEM_X25519_HKDF_SHA256) {
                throw EchError("ECH: unsupported KEM 0x${config.kemId.toString(16)}")
            }
            val kdf = hpkeKdf(cipherSuite.kdfId)
                ?: throw EchError("ECH: unsupported KDF 0x${cipherSuite.kdfId.toString(16)}")
            val aead = hpkeAead(cipherSuite.aeadId)
                ?: throw EchError("ECH: unsupported AEAD 0x${cipherSuite.aeadId.toString(16)}")

            val hpke = HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, kdf, aead)

            val recipient = try {
                hpke.deserializePublicKey(config.publicKey)
            } catch (e: Exception) {
                throw EchError("ECH: config public key is not a valid X25519 point")
            }

            val context = try {
                hpke.setupBaseS(recipient, info(config))
            } catch (e: Exception) {
                throw EchError("ECH: HPKE setup failed: ${e.message ?: e}")
            }

            return EchClientContext(config, cipherSuite, context.encapsulation, context)
        }

        /**
         * The HPKE info string: `"tls ech" ‖ 0x00 ‖ ECHConfig`.
         *
         * The config bytes are the record as received, version and length
         * header included — which is why [EchConfig.raw] is kept verbatim.
         */
        internal fun info(config: EchConfig): ByteArray =
            "tls ech".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + config.raw

        private fun hpkeKdf(id: Int): Short? = when (id) {
            EchKdf.HKDF_SHA256 -> HPKE.kdf_HKDF_SHA256
            EchKdf.HKDF_SHA384 -> HPKE.kdf_HKDF_SHA384
            EchKdf.HKDF_SHA512 -> HPKE.kdf_HKDF_SHA512
            else -> null
        }

        private fun hpkeAead(id: Int): Short? = when (id) {
            EchAead.AES_GCM_128 -> HPKE.aead_AES_GCM128
            EchAead.AES_GCM_256 -> HPKE.aead_AES_GCM256
            EchAead.CHACHA20_POLY1305 -> HPKE.aead_CHACHA20_POLY1305
            else -> null
        }
    }
}

/** Building the two byte strings ECH puts on the wire. */
object EchEncryption {

    /**
     * EncodedClientHelloInner: the inner ClientHello body, padded.
     *
     * [innerMessage] is a full handshake message (type, three-byte length,
     * body); the four-byte header comes off because the server reconstructs it.
     *
     * The padding hides how long the real server name is: a hello for a short
     * name and one for a long name have to come out the same length, or the
     * ciphertext length leaks what the encryption is hiding.
     */
    fun encodeInnerClientHello(
        innerMessage: ByteArray,
        serverName: String,
        maxNameLength: Int
    ): ByteArray {
        if (innerMessage.size < 4) throw EchError("ECH: inner hello is not a handshake message")

        val body = innerMessage.copyOfRange(4, innerMessage.size)

        // draft-ietf-tls-esni §6.1.3: add D bytes, THEN round the total up to a
        // multiple of 32. Both steps matter. Rounding alone leaves the length
        // varying with the name, which is the thing the padding exists to hide:
        // in a real hello the body grows with the name, so only the added D —
        // which shrinks by the same amount — holds the total steady.
        val difference = if (serverName.isNotEmpty()) {
            maxOf(0, maxNameLength - serverName.toByteArray(Charsets.UTF_8).size)
        } else {
            // No name to hide, so pad as if for the longest one plus the bytes
            // an SNI extension would have cost.
            maxNameLength + 9
        }

        val padded = body.size + difference
        val roundUp = (32 - (padded % 32)) % 32
        val paddingLength = difference + roundUp
        return if (paddingLength > 0) body + ByteArray(paddingLength) else body
    }

    /**
     * The body of the outer `encrypted_client_hello` extension.
     *
     * The caller wraps it with the 0xFE0D type and a length.
     */
    fun outerExtensionData(
        configId: Int,
        kdfId: Int,
        aeadId: Int,
        enc: ByteArray,
        payload: ByteArray
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream(9 + enc.size + payload.size)
        out.write(0x00)                              // ECHClientHelloType: outer
        out.write((kdfId shr 8) and 0xFF); out.write(kdfId and 0xFF)
        out.write((aeadId shr 8) and 0xFF); out.write(aeadId and 0xFF)
        out.write(configId and 0xFF)
        out.write((enc.size shr 8) and 0xFF); out.write(enc.size and 0xFF)
        out.write(enc)
        out.write((payload.size shr 8) and 0xFF); out.write(payload.size and 0xFF)
        out.write(payload)
        return out.toByteArray()
    }
}
