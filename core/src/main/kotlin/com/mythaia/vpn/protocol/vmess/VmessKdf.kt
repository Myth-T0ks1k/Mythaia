package com.mythaia.vpn.protocol.vmess

import java.security.MessageDigest
import java.util.UUID

/**
 * VMessAEAD's key-derivation function.
 *
 * It is HMAC-SHA256 where the *hash* is itself an HMAC — each path element
 * keys another layer, innermost first. `javax.crypto.Mac` cannot express that
 * (it takes a named algorithm, not a hash function), so HMAC is written out
 * here over a small hash abstraction.
 *
 * RFC 2104 with a 64-byte block throughout: SHA-256's block is 64, and an
 * HMAC-SHA256 used as a hash reports its underlying block size, so every layer
 * pads to 64 regardless of depth.
 */
object VmessKdf {

    private const val BLOCK_SIZE = 64

    /** The salt every derivation starts from. */
    private const val ROOT_SALT = "VMess AEAD KDF"

    const val SALT_AUTH_ID_ENCRYPTION = "AES Auth ID Encryption"
    const val SALT_HEADER_PAYLOAD_KEY = "VMess Header AEAD Key"
    const val SALT_HEADER_PAYLOAD_IV = "VMess Header AEAD Nonce"
    const val SALT_HEADER_LENGTH_KEY = "VMess Header AEAD Key_Length"
    const val SALT_HEADER_LENGTH_IV = "VMess Header AEAD Nonce_Length"
    const val SALT_RESP_HEADER_LEN_KEY = "AEAD Resp Header Len Key"
    const val SALT_RESP_HEADER_LEN_IV = "AEAD Resp Header Len IV"
    const val SALT_RESP_HEADER_PAYLOAD_KEY = "AEAD Resp Header Key"
    const val SALT_RESP_HEADER_PAYLOAD_IV = "AEAD Resp Header IV"

    /** A hash that can stand in for SHA-256 inside an outer HMAC. */
    private interface Hasher {
        fun update(data: ByteArray)
        fun digest(): ByteArray
    }

    private class Sha256Hasher : Hasher {
        private val digest = MessageDigest.getInstance("SHA-256")
        override fun update(data: ByteArray) = digest.update(data)
        override fun digest(): ByteArray = digest.digest()
    }

    /** HMAC over [inner], keyed by [key]. Itself usable as the hash of another. */
    private class HmacHasher(private val key: ByteArray, private val inner: () -> Hasher) : Hasher {
        private val ipadHasher: Hasher
        private val paddedKey: ByteArray

        init {
            // A key longer than the block is hashed down first; then padded
            // with zeros to the full block.
            val normalised = if (key.size > BLOCK_SIZE) {
                inner().apply { update(key) }.digest()
            } else {
                key
            }
            paddedKey = ByteArray(BLOCK_SIZE)
            normalised.copyInto(paddedKey)

            val ipad = ByteArray(BLOCK_SIZE) { (paddedKey[it].toInt() xor 0x36).toByte() }
            ipadHasher = inner().apply { update(ipad) }
        }

        override fun update(data: ByteArray) = ipadHasher.update(data)

        override fun digest(): ByteArray {
            val innerDigest = ipadHasher.digest()
            val opad = ByteArray(BLOCK_SIZE) { (paddedKey[it].toInt() xor 0x5C).toByte() }
            return inner().apply {
                update(opad)
                update(innerDigest)
            }.digest()
        }
    }

    /**
     * 32 bytes derived from [key] under [path].
     *
     * The layers nest outward: the root salt keys the innermost HMAC, each path
     * element keys one around it, and [key] is the message fed to the outermost.
     *
     * Path elements are raw bytes, not text. Some of them — the auth ID, the
     * connection nonce — are arbitrary binary, and putting them through a
     * character encoding on the way in would change them.
     */
    fun kdf(key: ByteArray, vararg path: ByteArray): ByteArray {
        var creator: () -> Hasher = { HmacHasher(ROOT_SALT.toByteArray(Charsets.UTF_8)) { Sha256Hasher() } }
        for (element in path) {
            val parent = creator
            creator = { HmacHasher(element, parent) }
        }
        return creator().apply { update(key) }.digest()
    }

    /** The first 16 bytes of [kdf] — an AES-128 key. */
    fun kdf16(key: ByteArray, vararg path: ByteArray): ByteArray = kdf(key, *path).copyOfRange(0, 16)

    /** The first 12 bytes of [kdf] — a GCM nonce. */
    fun kdf12(key: ByteArray, vararg path: ByteArray): ByteArray = kdf(key, *path).copyOfRange(0, 12)

    /** A constant salt as the bytes the KDF wants. */
    fun salt(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

    /**
     * The command key: MD5 of the user ID followed by VMess's fixed salt.
     *
     * MD5 is not a choice here; it is what the protocol specifies, and this
     * value is a key derivation input rather than a security claim of its own.
     */
    fun commandKey(id: UUID): ByteArray {
        val digest = MessageDigest.getInstance("MD5")
        digest.update(uuidBytes(id))
        digest.update("c48619fe-8f02-49e0-b9e9-edf763e17e21".toByteArray(Charsets.UTF_8))
        return digest.digest()
    }

    /** A UUID as its 16 big-endian bytes. */
    fun uuidBytes(id: UUID): ByteArray {
        val out = ByteArray(16)
        var high = id.mostSignificantBits
        var low = id.leastSignificantBits
        for (i in 7 downTo 0) {
            out[i] = (high and 0xFF).toByte()
            high = high ushr 8
        }
        for (i in 15 downTo 8) {
            out[i] = (low and 0xFF).toByte()
            low = low ushr 8
        }
        return out
    }

    /**
     * FNV-1a, 32-bit — the checksum VMess puts at the end of its request
     * header. Not a MAC; it catches a corrupted header, nothing more.
     */
    fun fnv1a32(data: ByteArray): Int {
        var hash = -0x7ee3623b   // 2166136261
        for (b in data) {
            hash = hash xor (b.toInt() and 0xFF)
            hash *= 16777619
        }
        return hash
    }
}
