package com.mythaia.vpn.protocol.hysteria

import org.bouncycastle.crypto.digests.Blake2bDigest
import java.security.SecureRandom

/**
 * Hysteria's Salamander obfuscation.
 *
 * Every datagram becomes `salt(8) ‖ (packet XOR keystream)`, where the
 * keystream is BLAKE2b-256 over `password ‖ salt`, cycled to the packet's
 * length. There is no authentication here and none is wanted: QUIC underneath
 * already authenticates everything, and the point of this layer is only that a
 * censor cannot recognise a QUIC Initial packet by its plaintext header.
 *
 * A fresh salt per datagram is what stops the keystream repeating — the same
 * password with the same salt produces the same key, so a fixed salt would
 * turn this into a single reused one-time pad.
 *
 * BLAKE2b comes from BouncyCastle, which the app already uses for BLAKE2s in
 * WireGuard. A C implementation was considered and is not needed: this runs
 * once per datagram over a 32-byte digest, not per byte.
 */
class SalamanderObfuscator(password: String) {

    private val psk = password.toByteArray(Charsets.UTF_8)
    private val random = SecureRandom()

    init {
        // The reference refuses a shorter key outright rather than obfuscate
        // weakly, and a server built on it would reject this client anyway.
        require(psk.size >= MIN_PSK_LENGTH) {
            "Salamander needs a password of at least $MIN_PSK_LENGTH bytes"
        }
    }

    /** `salt ‖ ciphertext`. */
    fun seal(packet: ByteArray): ByteArray {
        val salt = ByteArray(SALT_LENGTH)
        random.nextBytes(salt)
        val key = keystream(salt)

        val out = ByteArray(SALT_LENGTH + packet.size)
        salt.copyInto(out)
        for (i in packet.indices) {
            out[SALT_LENGTH + i] = (packet[i].toInt() xor key[i % KEY_LENGTH].toInt()).toByte()
        }
        return out
    }

    /**
     * Reverses [seal], or null when the datagram is not one.
     *
     * Anything at or below the salt length is dropped rather than handed back:
     * it cannot have come from this layer, and passing the raw bytes through
     * would deliver un-deobfuscated data to QUIC, which is a worse failure than
     * losing a packet that was never ours.
     */
    fun open(datagram: ByteArray): ByteArray? {
        if (datagram.size <= SALT_LENGTH) return null

        val key = keystream(datagram.copyOfRange(0, SALT_LENGTH))
        val out = ByteArray(datagram.size - SALT_LENGTH)
        for (i in out.indices) {
            out[i] = (datagram[SALT_LENGTH + i].toInt() xor key[i % KEY_LENGTH].toInt()).toByte()
        }
        return out
    }

    private fun keystream(salt: ByteArray): ByteArray {
        val digest = Blake2bDigest(KEY_LENGTH * 8)
        digest.update(psk, 0, psk.size)
        digest.update(salt, 0, salt.size)
        val out = ByteArray(KEY_LENGTH)
        digest.doFinal(out, 0)
        return out
    }

    companion object {
        const val SALT_LENGTH = 8

        /** The reference rejects a shorter pre-shared key. */
        const val MIN_PSK_LENGTH = 4

        /** A BLAKE2b-256 digest, which is the whole keystream period. */
        const val KEY_LENGTH = 32
    }
}
