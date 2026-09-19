package com.mythaia.vpn.protocol.tls.ech

import java.io.IOException

/** HPKE identifiers (RFC 9180) as ECH uses them. */
object EchKem {
    const val DHKEM_X25519_HKDF_SHA256 = 0x0020
}

object EchKdf {
    const val HKDF_SHA256 = 0x0001
    const val HKDF_SHA384 = 0x0002
    const val HKDF_SHA512 = 0x0003
}

object EchAead {
    const val AES_GCM_128 = 0x0001
    const val AES_GCM_256 = 0x0002
    const val CHACHA20_POLY1305 = 0x0003
}

/** The ECH extension codepoint, which is also the ECHConfig version understood here. */
const val ECH_EXTENSION_CODEPOINT = 0xFE0D

/** How a config list failed to be one. */
class EchError(message: String) : IOException(message)

data class EchCipherSuite(val kdfId: Int, val aeadId: Int)

data class EchConfigExtension(val type: Int, val data: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is EchConfigExtension && type == other.type && data.contentEquals(other.data)

    override fun hashCode(): Int = 31 * type + data.contentHashCode()
}

/**
 * One ECHConfig from an ECHConfigList.
 *
 * Ports the iOS `ECHConfig`.
 */
class EchConfig(
    /**
     * The whole record including its two-byte version and two-byte length.
     *
     * Kept byte-exact because it feeds the HPKE info string
     * (`"tls ech" ‖ 0x00 ‖ raw`) — a re-serialised copy that differed anywhere
     * would derive a different key and the server would reject the hello.
     */
    val raw: ByteArray,
    val version: Int,
    val configId: Int,
    val kemId: Int,
    val publicKey: ByteArray,
    val cipherSuites: List<EchCipherSuite>,
    val maxNameLength: Int,
    val publicName: String,
    val extensions: List<EchConfigExtension>
) {

    /** The first cipher suite this build can actually use, or null. */
    fun pickCipherSuite(): EchCipherSuite? = cipherSuites.firstOrNull {
        it.aeadId in SUPPORTED_AEADS && it.kdfId in SUPPORTED_KDFS
    }

    companion object {
        val SUPPORTED_KEMS = setOf(EchKem.DHKEM_X25519_HKDF_SHA256)
        val SUPPORTED_KDFS = setOf(EchKdf.HKDF_SHA256, EchKdf.HKDF_SHA384, EchKdf.HKDF_SHA512)
        val SUPPORTED_AEADS =
            setOf(EchAead.AES_GCM_128, EchAead.AES_GCM_256, EchAead.CHACHA20_POLY1305)

        /**
         * The first usable config: a supported KEM, at least one supported
         * cipher suite, a DNS-shaped public name, and no mandatory extension
         * this build does not understand.
         *
         * A mandatory extension is one with the high bit of its type set. The
         * spec says a client that cannot honour it must not use the config, so
         * it is skipped rather than ignored.
         */
        fun pick(list: List<EchConfig>): EchConfig? = list.firstOrNull { config ->
            config.kemId in SUPPORTED_KEMS &&
                config.pickCipherSuite() != null &&
                isValidDnsName(config.publicName) &&
                config.extensions.none { it.type and 0x8000 != 0 }
        }

        /**
         * Whether [name] is shaped like a hostname.
         *
         * The public name goes out as the SNI of the outer hello, in the clear.
         * Anything that is not a plausible hostname would stand out, which is
         * the opposite of the point.
         */
        fun isValidDnsName(name: String): Boolean {
            if (name.isEmpty() || name.length > 253) return false
            val labels = name.split(".")
            if (labels.size < 2) return false
            for (label in labels) {
                if (label.isEmpty()) return false
                for ((i, c) in label.withIndex()) {
                    if (c == '-' && (i == 0 || i == label.length - 1)) return false
                    val ok = c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z' || c == '-'
                    if (!ok) return false
                }
            }
            return true
        }

        /**
         * Parses an ECHConfigList: a two-byte total length, then records of
         * version, length and body.
         *
         * A record whose version is not the one understood here is skipped
         * rather than rejected, so a list carrying a future version alongside a
         * usable one still works.
         */
        fun parseList(data: ByteArray): List<EchConfig> {
            if (data.size < 2) throw EchError("ECHConfigList shorter than its own length field")
            val listLength = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
            if (listLength != data.size - 2) {
                throw EchError("ECHConfigList declares $listLength bytes but carries ${data.size - 2}")
            }

            val configs = ArrayList<EchConfig>()
            var at = 2
            while (at < data.size) {
                if (at + 4 > data.size) throw EchError("truncated ECHConfig record header")
                val version = ((data[at].toInt() and 0xFF) shl 8) or (data[at + 1].toInt() and 0xFF)
                val bodyLength =
                    ((data[at + 2].toInt() and 0xFF) shl 8) or (data[at + 3].toInt() and 0xFF)
                val end = at + 4 + bodyLength
                if (end > data.size) throw EchError("ECHConfig record runs past the list")

                if (version == ECH_EXTENSION_CODEPOINT) {
                    configs.add(
                        parseBody(
                            body = data.copyOfRange(at + 4, end),
                            version = version,
                            raw = data.copyOfRange(at, end)
                        )
                    )
                }
                at = end
            }
            return configs
        }

        private fun parseBody(body: ByteArray, version: Int, raw: ByteArray): EchConfig {
            val reader = Reader(body)

            val configId = reader.u8() ?: throw EchError("ECHConfig: missing config_id")
            val kemId = reader.u16() ?: throw EchError("ECHConfig: missing kem_id")
            val publicKey = reader.u16Prefixed() ?: throw EchError("ECHConfig: missing public_key")
            val suiteBytes = reader.u16Prefixed() ?: throw EchError("ECHConfig: missing cipher_suites")

            val suites = ArrayList<EchCipherSuite>()
            val suiteReader = Reader(suiteBytes)
            while (!suiteReader.isEmpty) {
                val kdf = suiteReader.u16() ?: throw EchError("ECHConfig: truncated cipher suite")
                val aead = suiteReader.u16() ?: throw EchError("ECHConfig: truncated cipher suite")
                suites.add(EchCipherSuite(kdf, aead))
            }

            val maxNameLength = reader.u8() ?: throw EchError("ECHConfig: missing maximum_name_length")
            val publicNameRaw = reader.u8Prefixed() ?: throw EchError("ECHConfig: missing public_name")
            val extensionBytes = reader.u16Prefixed() ?: throw EchError("ECHConfig: missing extensions")

            val extensions = ArrayList<EchConfigExtension>()
            val extReader = Reader(extensionBytes)
            while (!extReader.isEmpty) {
                val type = extReader.u16() ?: throw EchError("ECHConfig: truncated extension")
                val data = extReader.u16Prefixed() ?: throw EchError("ECHConfig: truncated extension")
                extensions.add(EchConfigExtension(type, data))
            }

            // Anything past the declared fields means the record is not what it
            // says it is, which is worth refusing rather than guessing at.
            if (!reader.isEmpty) throw EchError("ECHConfig: trailing bytes")

            return EchConfig(
                raw = raw,
                version = version,
                configId = configId,
                kemId = kemId,
                publicKey = publicKey,
                cipherSuites = suites,
                maxNameLength = maxNameLength,
                publicName = String(publicNameRaw, Charsets.UTF_8),
                extensions = extensions
            )
        }

        /**
         * Base64 that may be URL-safe or unpadded.
         *
         * Configs are pasted out of share links and QR codes, so all three
         * spellings turn up.
         */
        fun decodeBase64(text: String): ByteArray? {
            val normalised = text.trim().replace('-', '+').replace('_', '/')
            if (normalised.isEmpty()) return null
            val padded = when (normalised.length % 4) {
                2 -> "$normalised=="
                3 -> "$normalised="
                0 -> normalised
                else -> return null
            }
            return runCatching { java.util.Base64.getDecoder().decode(padded) }.getOrNull()
        }
    }

    /** A cursor that returns null rather than throwing at the end of the buffer. */
    private class Reader(private val bytes: ByteArray) {
        private var offset = 0

        val isEmpty: Boolean get() = offset >= bytes.size

        fun u8(): Int? {
            if (offset + 1 > bytes.size) return null
            return (bytes[offset++].toInt() and 0xFF)
        }

        fun u16(): Int? {
            if (offset + 2 > bytes.size) return null
            val value = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
            offset += 2
            return value
        }

        fun take(count: Int): ByteArray? {
            if (count < 0 || offset + count > bytes.size) return null
            val out = bytes.copyOfRange(offset, offset + count)
            offset += count
            return out
        }

        fun u8Prefixed(): ByteArray? = u8()?.let { take(it) }

        fun u16Prefixed(): ByteArray? = u16()?.let { take(it) }
    }
}
