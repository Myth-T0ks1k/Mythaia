package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.vpn.X25519Crypto
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

/**
 * A relay's public key, tagged by which primitive it is so the encapsulation
 * step knows whether to run an X25519 agreement or an ML-KEM encapsulation.
 * The length is the tag: 32 bytes is X25519, 1184 is ML-KEM-768.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal sealed class NfsPublicKey {
    abstract val raw: ByteArray

    class X25519(override val raw: ByteArray) : NfsPublicKey()
    class Mlkem768(override val raw: ByteArray) : NfsPublicKey()

    companion object {
        fun parse(raw: ByteArray): NfsPublicKey = when (raw.size) {
            VlessEncryptionConfig.X25519_KEY_LENGTH -> X25519(raw)
            VlessEncryptionConfig.MLKEM768_KEY_LENGTH -> Mlkem768(raw)
            else -> throw VlessEncryptionError.HandshakeFailed("invalid public key")
        }
    }
}

/**
 * The result of offering key material to one relay: the 32-byte shared secret
 * both ends now hold, and the [publicOrCiphertext] bytes the relay needs to
 * derive it — an ephemeral X25519 public key, or an ML-KEM ciphertext.
 */
internal class RelaySecret(val sharedSecret: ByteArray, val publicOrCiphertext: ByteArray)

/**
 * The client's own ephemeral hybrid key pair for a 1-RTT handshake.
 *
 * [publicBytes] is `mlkemPublic(1184) || x25519Public(32)`, the block the server
 * seals its own PFS hello in reply to. The private halves are kept so the
 * server's ciphertext and public key can be turned back into the same two shared
 * secrets.
 */
internal class PfsKeyPair(
    val publicBytes: ByteArray,
    val mlkemPrivate: MLKEMPrivateKeyParameters,
    val x25519Private: ByteArray
)

/**
 * The hybrid post-quantum key operations, in the one place a test can pin them.
 *
 * Every secret here is 32 bytes and every ML-KEM object is FIPS 203 ML-KEM-768
 * as BouncyCastle implements it; X25519 reuses the app's constant-time helper
 * rather than a second curve implementation. Encapsulation and decapsulation are
 * kept as plain functions so the round trip — and the fact that a flipped
 * ciphertext yields a different secret rather than the same one — can be checked
 * directly.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object VlessHybridCrypto {

    private val random = SecureRandom()

    /**
     * Offers key material to [key]: for X25519, a fresh ephemeral agreement; for
     * ML-KEM, an encapsulation. Returns the shared secret and the bytes the
     * relay reads to reach it.
     */
    fun encapsulateToRelay(key: NfsPublicKey): RelaySecret = when (key) {
        is NfsPublicKey.X25519 -> {
            val keyPair = X25519Crypto.generateKeyPair() // priv(32) || pub(32)
            val priv = keyPair.copyOfRange(0, 32)
            val pub = keyPair.copyOfRange(32, 64)
            val shared = X25519Crypto.keyAgreement(priv, key.raw)
            RelaySecret(sharedSecret = shared, publicOrCiphertext = pub)
        }
        is NfsPublicKey.Mlkem768 -> {
            val (secret, ciphertext) = mlkemEncapsulate(key.raw)
            RelaySecret(sharedSecret = secret, publicOrCiphertext = ciphertext)
        }
    }

    /** ML-KEM-768 encapsulation to [publicKeyBytes] (1184). Returns (secret 32, ciphertext 1088). */
    fun mlkemEncapsulate(publicKeyBytes: ByteArray): Pair<ByteArray, ByteArray> {
        val publicKey = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, publicKeyBytes)
        val encapsulated = MLKEMGenerator(random).generateEncapsulated(publicKey)
        return encapsulated.secret to encapsulated.encapsulation
    }

    /** ML-KEM-768 decapsulation; [ciphertext] is 1088 bytes, the secret 32. */
    fun mlkemDecapsulate(privateKey: MLKEMPrivateKeyParameters, ciphertext: ByteArray): ByteArray =
        MLKEMExtractor(privateKey).extractSecret(ciphertext)

    /** X25519 agreement, delegating to the app's constant-time helper. */
    fun x25519Agreement(privateKey: ByteArray, peerPublic: ByteArray): ByteArray =
        X25519Crypto.keyAgreement(privateKey, peerPublic)

    /** A fresh ML-KEM-768 + X25519 key pair for the client's PFS offer. */
    fun generatePfsKeyPair(): PfsKeyPair {
        val generator = MLKEMKeyPairGenerator()
        generator.init(MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768))
        val pair = generator.generateKeyPair()
        val mlkemPublic = (pair.getPublic() as MLKEMPublicKeyParameters).encoded // 1184
        val mlkemPrivate = pair.getPrivate() as MLKEMPrivateKeyParameters

        val x25519 = X25519Crypto.generateKeyPair() // priv(32) || pub(32)
        val x25519Private = x25519.copyOfRange(0, 32)
        val x25519Public = x25519.copyOfRange(32, 64)

        return PfsKeyPair(
            publicBytes = mlkemPublic + x25519Public,
            mlkemPrivate = mlkemPrivate,
            x25519Private = x25519Private
        )
    }
}

/**
 * Assembles the client-hello relay block: for each relay in chain order, the
 * bytes that carry key material to it, masked and chain-bound exactly as the
 * server will unwind them.
 *
 * The encapsulation step is injected so the block layout — the per-relay CTR
 * mask keyed on that relay's public key, and the chain-hash binding that XORs
 * one relay's leading bytes with a CTR keyed on the previous relay's secret —
 * can be tested against a fixed set of secrets, independently of the randomness
 * a live ML-KEM or X25519 would draw.
 *
 * The last relay's shared secret is the `nfsKey` that keys the record layer; the
 * earlier relays only bind the chain so the server can verify its order.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class RelayBlockBuilder(
    private val publicKeys: List<ByteArray>,
    private val xorMode: VlessEncryptionConfig.XorMode,
    private val encapsulate: (NfsPublicKey) -> RelaySecret = VlessHybridCrypto::encapsulateToRelay
) {

    private val parsedKeys: List<NfsPublicKey> = publicKeys.map { NfsPublicKey.parse(it) }

    /** BLAKE3-256 of each raw relay key, used to bind the chain order. */
    private val keyHashes: List<ByteArray> = publicKeys.map { Blake3Kdf.hash(it) }

    /** The relay block bytes, and the final relay's shared secret. */
    class RelayBlock(val bytes: ByteArray, val nfsKey: ByteArray)

    fun build(iv: ByteArray): RelayBlock {
        var relayBlock = ByteArray(0)
        var nfsKey = ByteArray(0)
        var lastCtr: VlessEncryptionCtr? = null

        for (j in parsedKeys.indices) {
            val relaySecret = encapsulate(parsedKeys[j])
            nfsKey = relaySecret.sharedSecret
            var block = relaySecret.publicOrCiphertext

            if (xorMode != VlessEncryptionConfig.XorMode.NATIVE) {
                block = VlessEncryptionCtr(publicKeys[j], iv).process(block)
            }

            val previous = lastCtr
            if (previous != null) {
                // Only the leading 32 bytes ride the previous relay's keystream;
                // the chain-hash XOR above continued that same stream, so this
                // picks up exactly where it left off.
                val head = previous.process(block.copyOfRange(0, 32))
                block = head + block.copyOfRange(32, block.size)
            }

            relayBlock += block

            if (j < parsedKeys.size - 1) {
                // The next relay's key hash, masked with a CTR keyed on this
                // relay's secret: this is what lets the server confirm the chain
                // order it was handed.
                val chainCtr = VlessEncryptionCtr(nfsKey, iv)
                relayBlock += chainCtr.process(keyHashes[j + 1])
                lastCtr = chainCtr
            }
        }

        return RelayBlock(relayBlock, nfsKey)
    }
}

/**
 * The record-layer key: `mlkemSecret(32) || x25519Secret(32) || nfsKey(32)`.
 *
 * The forward-secret PFS half (the first 64 bytes) is what a 0-RTT ticket
 * resumes; the nfsKey tail ties the key to the relay chain of this exact dial.
 */
internal fun deriveUnitedKey(
    mlkemSecret: ByteArray,
    x25519Secret: ByteArray,
    nfsKey: ByteArray
): ByteArray = mlkemSecret + x25519Secret + nfsKey
