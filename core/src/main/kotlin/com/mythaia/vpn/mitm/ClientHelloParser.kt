package com.mythaia.vpn.mitm

/**
 * Reads a ClientHello (RFC 8446 §4.1.2), as a server must.
 *
 * Nothing else in this app parses one: every other component is a client, and
 * a client only ever reads ServerHellos. A server reads exactly the fields it
 * needs to answer — which name was asked for, which suites and groups the
 * client can do, which protocols it wants — and ignores the rest, since a
 * ClientHello from a browser carries a dozen extensions that have no bearing
 * on the answer.
 *
 * Every accessor is a plain field so the tests can assert offsets against a
 * hello written out by hand from the RFC, not against this parser's own idea
 * of the layout.
 */
class ClientHelloParser private constructor(
    val random: ByteArray,
    val sessionId: ByteArray,
    val cipherSuites: List<Int>,
    /** `server_name`, or null when the client sent none. */
    val serverName: String?,
    /** The client's X25519 public key from `key_share`, or null if it offered none. */
    val x25519KeyShare: ByteArray?,
    val supportedVersions: List<Int>,
    val alpn: List<String>,
    val signatureAlgorithms: List<Int>
) {

    /** Whether the client can speak TLS 1.3 at all. */
    val offersTls13: Boolean get() = supportedVersions.contains(0x0304)

    companion object {
        private const val EXT_SERVER_NAME = 0
        private const val EXT_SIGNATURE_ALGORITHMS = 13
        private const val EXT_ALPN = 16
        private const val EXT_SUPPORTED_VERSIONS = 43
        private const val EXT_KEY_SHARE = 51
        private const val GROUP_X25519 = 0x001D

        /**
         * Parses a ClientHello handshake message (type byte and length included).
         *
         * Null for anything malformed. A server that threw here would be
         * handing every client the power to raise an exception in it; a null is
         * a connection to close and nothing more.
         */
        fun parse(message: ByteArray): ClientHelloParser? {
            if (message.size < 4 || message[0] != 0x01.toByte()) return null
            val declared = ((message[1].toInt() and 0xFF) shl 16) or
                ((message[2].toInt() and 0xFF) shl 8) or (message[3].toInt() and 0xFF)
            if (declared != message.size - 4) return null

            var at = 4
            // legacy_version(2)
            at += 2
            if (at + 32 > message.size) return null
            val random = message.copyOfRange(at, at + 32); at += 32

            if (at >= message.size) return null
            val sessionIdLength = message[at].toInt() and 0xFF; at += 1
            if (sessionIdLength > 32 || at + sessionIdLength > message.size) return null
            val sessionId = message.copyOfRange(at, at + sessionIdLength); at += sessionIdLength

            if (at + 2 > message.size) return null
            val suitesLength = u16(message, at); at += 2
            if (suitesLength < 2 || suitesLength % 2 != 0 || at + suitesLength > message.size) return null
            val suites = ArrayList<Int>(suitesLength / 2)
            for (i in 0 until suitesLength step 2) suites.add(u16(message, at + i))
            at += suitesLength

            if (at >= message.size) return null
            val compressionLength = message[at].toInt() and 0xFF; at += 1
            if (compressionLength < 1 || at + compressionLength > message.size) return null
            at += compressionLength

            var serverName: String? = null
            var keyShare: ByteArray? = null
            var versions: List<Int> = emptyList()
            var alpn: List<String> = emptyList()
            var signatureAlgorithms: List<Int> = emptyList()

            if (at + 2 <= message.size) {
                val extensionsLength = u16(message, at); at += 2
                val end = at + extensionsLength
                if (end > message.size) return null

                while (at + 4 <= end) {
                    val type = u16(message, at)
                    val length = u16(message, at + 2)
                    at += 4
                    if (at + length > end) return null
                    val body = message.copyOfRange(at, at + length)
                    at += length

                    when (type) {
                        EXT_SERVER_NAME -> serverName = parseServerName(body) ?: serverName
                        EXT_KEY_SHARE -> keyShare = parseKeyShare(body) ?: keyShare
                        EXT_SUPPORTED_VERSIONS -> versions = parseSupportedVersions(body)
                        EXT_ALPN -> alpn = parseAlpn(body)
                        EXT_SIGNATURE_ALGORITHMS -> signatureAlgorithms = parseU16List(body)
                    }
                }
            }

            return ClientHelloParser(
                random, sessionId, suites, serverName, keyShare, versions, alpn, signatureAlgorithms
            )
        }

        /** server_name: list length(2), then entries of type(1) length(2) name. */
        private fun parseServerName(body: ByteArray): String? {
            if (body.size < 5) return null
            var at = 2
            while (at + 3 <= body.size) {
                val nameType = body[at].toInt() and 0xFF
                val length = u16(body, at + 1)
                at += 3
                if (at + length > body.size) return null
                if (nameType == 0) return String(body, at, length, Charsets.US_ASCII)
                at += length
            }
            return null
        }

        /** key_share: client_shares length(2), then entries of group(2) length(2) key. */
        private fun parseKeyShare(body: ByteArray): ByteArray? {
            if (body.size < 2) return null
            var at = 2
            while (at + 4 <= body.size) {
                val group = u16(body, at)
                val length = u16(body, at + 2)
                at += 4
                if (at + length > body.size) return null
                if (group == GROUP_X25519 && length == 32) return body.copyOfRange(at, at + 32)
                at += length
            }
            return null
        }

        /** supported_versions on a ClientHello: length(1), then versions(2 each). */
        private fun parseSupportedVersions(body: ByteArray): List<Int> {
            if (body.isEmpty()) return emptyList()
            val length = body[0].toInt() and 0xFF
            if (1 + length > body.size || length % 2 != 0) return emptyList()
            return (0 until length step 2).map { u16(body, 1 + it) }
        }

        /** ALPN: list length(2), then entries of length(1) name. */
        private fun parseAlpn(body: ByteArray): List<String> {
            if (body.size < 2) return emptyList()
            val out = ArrayList<String>()
            var at = 2
            while (at < body.size) {
                val length = body[at].toInt() and 0xFF; at += 1
                if (length == 0 || at + length > body.size) break
                out.add(String(body, at, length, Charsets.US_ASCII))
                at += length
            }
            return out
        }

        private fun parseU16List(body: ByteArray): List<Int> {
            if (body.size < 2) return emptyList()
            val length = u16(body, 0)
            if (2 + length > body.size || length % 2 != 0) return emptyList()
            return (0 until length step 2).map { u16(body, 2 + it) }
        }

        private fun u16(bytes: ByteArray, at: Int): Int =
            ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
    }
}
