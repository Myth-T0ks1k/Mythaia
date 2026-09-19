package com.mythaia.vpn.protocol.vmess

import com.mythaia.data.model.ProxyError
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.SecureRandom
import java.util.UUID
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** How the VMess body is encrypted. */
enum class VmessSecurity(val raw: String, val id: Int) {
    AES_128_GCM("aes-128-gcm", 0x03),
    CHACHA20_POLY1305("chacha20-poly1305", 0x04),
    NONE("none", 0x05),
    ZERO("zero", 0x06);

    val displayName: String
        get() = when (this) {
            AES_128_GCM -> "AES-128-GCM"
            CHACHA20_POLY1305 -> "ChaCha20-Poly1305"
            NONE -> "None"
            ZERO -> "Zero"
        }

    companion object {
        /**
         * `auto` is what most links and panels write; on any device this app
         * runs on AES has hardware backing, so it resolves to AES-128-GCM.
         */
        fun fromRaw(value: String?): VmessSecurity = when (value?.lowercase()) {
            null, "", "auto", "aes-128-gcm" -> AES_128_GCM
            "chacha20-poly1305", "chacha20-ietf-poly1305" -> CHACHA20_POLY1305
            "none" -> NONE
            "zero" -> ZERO
            else -> AES_128_GCM
        }
    }
}

/**
 * The VMessAEAD request header and its sealing.
 *
 * Only the AEAD form is implemented — `alterId` 0. The legacy MD5-authenticated
 * header with a non-zero alterId was deprecated by v2ray in 2022 and is refused
 * rather than half-supported.
 */
object VmessProtocol {

    const val VERSION: Byte = 1

    /** Request options. */
    const val OPTION_CHUNK_STREAM = 0x01
    const val OPTION_CHUNK_MASKING = 0x04
    const val OPTION_GLOBAL_PADDING = 0x08

    const val COMMAND_TCP: Byte = 1
    const val COMMAND_UDP: Byte = 2

    private const val ADDRESS_IPV4: Byte = 1
    private const val ADDRESS_DOMAIN: Byte = 2
    private const val ADDRESS_IPV6: Byte = 3

    private val random = SecureRandom()

    /** Everything the client must remember to read the reply. */
    class Session(
        val requestBodyKey: ByteArray,
        val requestBodyIv: ByteArray,
        val responseHeader: Byte,
        val security: VmessSecurity,
        val option: Int
    ) {
        /** The reply is keyed by the hash of the request's key and IV. */
        val responseBodyKey: ByteArray =
            java.security.MessageDigest.getInstance("SHA-256").digest(requestBodyKey).copyOfRange(0, 16)
        val responseBodyIv: ByteArray =
            java.security.MessageDigest.getInstance("SHA-256").digest(requestBodyIv).copyOfRange(0, 16)
    }

    class SealedRequest(val bytes: ByteArray, val session: Session)

    /**
     * Builds and seals a request header for [host]:[port].
     *
     * The result is `authID ‖ encrypted length ‖ nonce ‖ encrypted header`,
     * which is everything that goes on the wire before the first body chunk.
     */
    fun sealRequest(
        id: UUID,
        host: String,
        port: Int,
        command: Byte,
        security: VmessSecurity
    ): SealedRequest {
        val cmdKey = VmessKdf.commandKey(id)

        val bodyKey = ByteArray(16).also { random.nextBytes(it) }
        val bodyIv = ByteArray(16).also { random.nextBytes(it) }
        val responseHeader = ByteArray(1).also { random.nextBytes(it) }[0]

        val option = optionsFor(security)

        val header = buildHeader(bodyKey, bodyIv, responseHeader, option, security, command, host, port)
        val authId = generateAuthId(cmdKey)
        val nonce = ByteArray(8).also { random.nextBytes(it) }

        val lengthKey = VmessKdf.kdf16(cmdKey, salt(VmessKdf.SALT_HEADER_LENGTH_KEY), authId, nonce)
        val lengthNonce = VmessKdf.kdf12(cmdKey, salt(VmessKdf.SALT_HEADER_LENGTH_IV), authId, nonce)
        val lengthPlain = byteArrayOf(
            ((header.size shr 8) and 0xFF).toByte(),
            (header.size and 0xFF).toByte()
        )
        val sealedLength = aesGcmSeal(lengthKey, lengthNonce, lengthPlain, authId)

        val payloadKey = VmessKdf.kdf16(cmdKey, salt(VmessKdf.SALT_HEADER_PAYLOAD_KEY), authId, nonce)
        val payloadNonce = VmessKdf.kdf12(cmdKey, salt(VmessKdf.SALT_HEADER_PAYLOAD_IV), authId, nonce)
        val sealedHeader = aesGcmSeal(payloadKey, payloadNonce, header, authId)

        val out = ByteArray(authId.size + sealedLength.size + nonce.size + sealedHeader.size)
        var at = 0
        authId.copyInto(out, at); at += authId.size
        sealedLength.copyInto(out, at); at += sealedLength.size
        nonce.copyInto(out, at); at += nonce.size
        sealedHeader.copyInto(out, at)

        return SealedRequest(out, Session(bodyKey, bodyIv, responseHeader, security, option))
    }

    /**
     * The request options that go with [security].
     *
     * Masking and global padding only make sense over an AEAD body: they act on
     * the length prefix and the trailing bytes of a sealed chunk. With `none`
     * the chunk carries the payload verbatim, so padding would be delivered to
     * the destination as part of the stream — the first HTTP request the tunnel
     * carried would arrive with random bytes glued to the end of it.
     */
    private fun optionsFor(security: VmessSecurity): Int = when (security) {
        VmessSecurity.AES_128_GCM, VmessSecurity.CHACHA20_POLY1305 ->
            OPTION_CHUNK_STREAM or OPTION_CHUNK_MASKING or OPTION_GLOBAL_PADDING
        // Chunked, so lengths still frame the stream, but nothing is added to
        // the payload that the far side would have to strip.
        VmessSecurity.NONE, VmessSecurity.ZERO -> OPTION_CHUNK_STREAM
    }

    /**
     * The 16-byte authentication ID: a timestamp and some randomness under a
     * CRC32, encrypted with AES-128 in ECB.
     *
     * ECB is correct here and only here — the plaintext is exactly one block,
     * so there is no pattern across blocks for it to leak.
     */
    private fun generateAuthId(cmdKey: ByteArray): ByteArray {
        val plain = ByteArray(16)
        var time = System.currentTimeMillis() / 1000
        for (i in 7 downTo 0) {
            plain[i] = (time and 0xFF).toByte()
            time = time ushr 8
        }
        // SecureRandom fills a whole array; the four random bytes sit at 8..12.
        ByteArray(4).also { random.nextBytes(it) }.copyInto(plain, 8)

        val crc = CRC32().apply { update(plain, 0, 12) }.value
        plain[12] = ((crc shr 24) and 0xFF).toByte()
        plain[13] = ((crc shr 16) and 0xFF).toByte()
        plain[14] = ((crc shr 8) and 0xFF).toByte()
        plain[15] = (crc and 0xFF).toByte()

        val key = VmessKdf.kdf16(cmdKey, salt(VmessKdf.SALT_AUTH_ID_ENCRYPTION))
        // One block, as the VMess AEAD header specifies. A chaining mode
        // would change the bytes on the wire.
        @Suppress("GetInstance")
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return cipher.doFinal(plain)
    }

    /** The plaintext header, FNV-1a checksum included. */
    private fun buildHeader(
        bodyKey: ByteArray,
        bodyIv: ByteArray,
        responseHeader: Byte,
        option: Int,
        security: VmessSecurity,
        command: Byte,
        host: String,
        port: Int
    ): ByteArray {
        val out = ArrayList<Byte>(64)
        out.add(VERSION)
        for (b in bodyIv) out.add(b)
        for (b in bodyKey) out.add(b)
        out.add(responseHeader)
        out.add(option.toByte())

        // High nibble is the padding length, low nibble the cipher.
        val paddingLength = random.nextInt(16)
        out.add(((paddingLength shl 4) or security.id).toByte())
        out.add(0)                                   // reserved
        out.add(command)
        out.add(((port shr 8) and 0xFF).toByte())
        out.add((port and 0xFF).toByte())

        appendAddress(out, host)

        if (paddingLength > 0) {
            val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
            for (b in padding) out.add(b)
        }

        val body = out.toByteArray()
        val checksum = VmessKdf.fnv1a32(body)
        return body + byteArrayOf(
            ((checksum shr 24) and 0xFF).toByte(),
            ((checksum shr 16) and 0xFF).toByte(),
            ((checksum shr 8) and 0xFF).toByte(),
            (checksum and 0xFF).toByte()
        )
    }

    /**
     * The destination, as a literal address when it is one and as a name
     * otherwise.
     *
     * A name is never resolved here: the point of sending it is to let the
     * server resolve it on its own side.
     */
    private fun appendAddress(out: ArrayList<Byte>, host: String) {
        val literal = parseLiteral(host)
        when {
            literal is Inet4Address -> {
                out.add(ADDRESS_IPV4)
                for (b in literal.address) out.add(b)
            }
            literal is Inet6Address -> {
                out.add(ADDRESS_IPV6)
                for (b in literal.address) out.add(b)
            }
            else -> {
                val name = host.toByteArray(Charsets.UTF_8)
                if (name.isEmpty() || name.size > 255) {
                    throw ProxyError.ProtocolError("VMess: destination name is not addressable")
                }
                out.add(ADDRESS_DOMAIN)
                out.add(name.size.toByte())
                for (b in name) out.add(b)
            }
        }
    }

    /** [host] as an address, or null when it is a name. Never resolves. */
    private fun parseLiteral(host: String): InetAddress? {
        val bare = host.removePrefix("[").removeSuffix("]")
        val looksNumeric = bare.all { it.isDigit() || it == '.' } ||
            (bare.contains(':') && bare.all { it.isDigit() || it in "abcdefABCDEF:." })
        if (!looksNumeric) return null
        return runCatching { InetAddress.getByName(bare) }.getOrNull()
    }

    /**
     * Reads the sealed reply header and checks it answers our request.
     *
     * @return the number of bytes consumed, or -1 when more input is needed.
     */
    fun openResponseHeader(session: Session, input: ByteArray): Int {
        val lengthKey = VmessKdf.kdf16(session.responseBodyKey, salt(VmessKdf.SALT_RESP_HEADER_LEN_KEY))
        val lengthNonce = VmessKdf.kdf12(session.responseBodyIv, salt(VmessKdf.SALT_RESP_HEADER_LEN_IV))

        // 2 bytes of length plus the GCM tag.
        if (input.size < 18) return -1
        val lengthPlain = aesGcmOpen(lengthKey, lengthNonce, input.copyOfRange(0, 18), null)
            ?: throw ProxyError.ProtocolError("VMess: response length failed authentication")
        val headerLength = ((lengthPlain[0].toInt() and 0xFF) shl 8) or (lengthPlain[1].toInt() and 0xFF)

        val total = 18 + headerLength + 16
        if (input.size < total) return -1

        val payloadKey = VmessKdf.kdf16(session.responseBodyKey, salt(VmessKdf.SALT_RESP_HEADER_PAYLOAD_KEY))
        val payloadNonce = VmessKdf.kdf12(session.responseBodyIv, salt(VmessKdf.SALT_RESP_HEADER_PAYLOAD_IV))
        val header = aesGcmOpen(payloadKey, payloadNonce, input.copyOfRange(18, total), null)
            ?: throw ProxyError.ProtocolError("VMess: response header failed authentication")

        if (header.isEmpty() || header[0] != session.responseHeader) {
            throw ProxyError.ProtocolError("VMess: response header does not match the request")
        }
        // header[1] is an option byte and header[2..] a dynamic-port command we
        // do not act on; the server is free to send it and we skip it whole.
        return total
    }

    // MARK: - AEAD helpers

    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /** Null when the tag does not verify — a wrong key, or a tampered message. */
    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray?): ByteArray? = try {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad != null) cipher.updateAAD(aad)
        cipher.doFinal(ciphertext)
    } catch (_: Exception) {
        null
    }

    private fun salt(text: String): ByteArray = VmessKdf.salt(text)
}
