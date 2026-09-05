package com.mythaia.vpn.protocol.anytls

import java.security.MessageDigest

/**
 * The AnyTLS wire format.
 *
 * AnyTLS is a session layer on top of an ordinary TLS connection: after the
 * handshake the client authenticates with a hash of the password, then both
 * sides speak framed, multiplexed streams. What makes it interesting is the
 * padding scheme — the server tells the client how to chop its first few
 * writes into TLS records, so the size pattern a censor sees is not fixed and
 * can be changed server-side without shipping a new client.
 *
 * Everything here is a pure function of bytes, which is what lets it be tested
 * against the reference implementation's own default scheme rather than only
 * against itself.
 */
object AnyTlsProtocol {

    // Commands. 0-6 are protocol version 1; 7-10 arrived with version 2.
    const val CMD_WASTE: Byte = 0
    const val CMD_SYN: Byte = 1
    const val CMD_PSH: Byte = 2
    const val CMD_FIN: Byte = 3
    const val CMD_SETTINGS: Byte = 4
    const val CMD_ALERT: Byte = 5
    const val CMD_UPDATE_PADDING_SCHEME: Byte = 6
    const val CMD_SYNACK: Byte = 7
    const val CMD_HEART_REQUEST: Byte = 8
    const val CMD_HEART_RESPONSE: Byte = 9
    const val CMD_SERVER_SETTINGS: Byte = 10

    /** command(1) + streamId(4) + length(2). */
    const val HEADER_SIZE = 7

    /** The protocol version this client implements. */
    const val VERSION = "2"

    /** UDP is carried as a TCP stream to this name, per sing-box's udp-over-tcp v2. */
    const val UDP_OVER_TCP_HOST = "sp.v2.udp-over-tcp.arpa"

    private const val ATYP_IPV4: Byte = 0x01
    private const val ATYP_DOMAIN: Byte = 0x03
    private const val ATYP_IPV6: Byte = 0x04

    /** A parsed frame header. */
    data class Header(val command: Byte, val streamId: Int, val length: Int)

    fun readHeader(bytes: ByteArray, offset: Int = 0): Header = Header(
        command = bytes[offset],
        streamId = ((bytes[offset + 1].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 8) or
            (bytes[offset + 4].toInt() and 0xFF),
        length = ((bytes[offset + 5].toInt() and 0xFF) shl 8) or
            (bytes[offset + 6].toInt() and 0xFF)
    )

    /** One frame: header then payload. Big-endian throughout. */
    fun frame(command: Byte, streamId: Int, data: ByteArray = ByteArray(0)): ByteArray {
        val out = ByteArray(HEADER_SIZE + data.size)
        out[0] = command
        out[1] = (streamId ushr 24).toByte()
        out[2] = (streamId ushr 16).toByte()
        out[3] = (streamId ushr 8).toByte()
        out[4] = streamId.toByte()
        out[5] = (data.size ushr 8).toByte()
        out[6] = data.size.toByte()
        data.copyInto(out, HEADER_SIZE)
        return out
    }

    /**
     * The first thing a client sends: sha256(password), then the length of the
     * zero padding the scheme asks for, then that padding.
     *
     * The padding is part of packet 0, which is the only one that cannot be
     * split across records — it shares a write with the authentication.
     */
    fun authentication(password: String, paddingLength: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray(Charsets.UTF_8))
        val out = ByteArray(digest.size + 2 + paddingLength.coerceAtLeast(0))
        digest.copyInto(out)
        out[digest.size] = (paddingLength ushr 8).toByte()
        out[digest.size + 1] = paddingLength.toByte()
        // The rest stays zero, which is what the reference client sends.
        return out
    }

    /**
     * The `cmdSettings` body: newline-separated `key=value`, UTF-8.
     *
     * `padding-md5` is how the server decides whether to push a new scheme, so
     * it has to be the digest of the exact bytes the client is using.
     */
    fun settings(clientName: String, paddingMd5: String): ByteArray =
        ("v=$VERSION\nclient=$clientName\npadding-md5=$paddingMd5")
            .toByteArray(Charsets.UTF_8)

    /** Parses the same shape coming back, e.g. `cmdServerSettings`. */
    fun parseSettings(data: ByteArray): Map<String, String> =
        String(data, Charsets.UTF_8)
            .split('\n')
            .mapNotNull { line ->
                val at = line.indexOf('=')
                if (at <= 0) null else line.substring(0, at).trim() to line.substring(at + 1).trim()
            }
            .toMap()

    /**
     * A destination in SOCKS5 address form, which is what a stream carries
     * first (RFC 1928 §5).
     */
    fun encodeAddress(host: String, port: Int): ByteArray {
        val ipv4 = parseIpv4(host)
        val ipv6 = if (ipv4 == null) parseIpv6(host) else null

        val prefix: ByteArray = when {
            ipv4 != null -> byteArrayOf(ATYP_IPV4) + ipv4
            ipv6 != null -> byteArrayOf(ATYP_IPV6) + ipv6
            else -> {
                val name = host.toByteArray(Charsets.UTF_8)
                val trimmed = if (name.size > 255) name.copyOf(255) else name
                byteArrayOf(ATYP_DOMAIN, trimmed.size.toByte()) + trimmed
            }
        }
        return prefix + byteArrayOf((port ushr 8).toByte(), port.toByte())
    }

    /**
     * Splits one payload into the TLS writes a padding scheme asks for.
     *
     * Each returned element is one call into the TLS layer, because the scheme
     * is defined in terms of record sizes. Where a record is bigger than what
     * is left of the payload, the slack is filled with a `cmdWaste` frame the
     * peer reads and drops; where the payload runs out entirely, a record of
     * pure waste is emitted. A `c` mark ends the sequence early once the
     * payload is spent, so a short request is not followed by padding that
     * would itself be a signature.
     *
     * Anything still unsent after the sizes run out goes as one final write.
     */
    fun shapeWrites(payload: ByteArray, sizes: List<Int>): List<ByteArray> {
        val writes = ArrayList<ByteArray>()
        var rest = payload

        for (size in sizes) {
            if (size == CHECK_MARK) {
                if (rest.isEmpty()) return writes else continue
            }
            when {
                rest.size > size -> {
                    writes.add(rest.copyOfRange(0, size))
                    rest = rest.copyOfRange(size, rest.size)
                }
                rest.isNotEmpty() -> {
                    val padLength = size - rest.size - HEADER_SIZE
                    writes.add(
                        if (padLength > 0) rest + frame(CMD_WASTE, 0, ByteArray(padLength))
                        else rest
                    )
                    rest = ByteArray(0)
                }
                else -> writes.add(frame(CMD_WASTE, 0, ByteArray(size)))
            }
        }

        if (rest.isNotEmpty()) writes.add(rest)
        return writes
    }

    /** Mirrors [AnyTlsPaddingScheme.CHECK] without depending on it. */
    const val CHECK_MARK = -1

    private fun parseIpv4(host: String): ByteArray? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            out[i] = v.toByte()
        }
        return out
    }

    private fun parseIpv6(host: String): ByteArray? {
        if (!host.contains(':')) return null
        return try {
            val address = java.net.InetAddress.getByName(host)
            address.address.takeIf { it.size == 16 }
        } catch (_: Exception) {
            null
        }
    }
}
