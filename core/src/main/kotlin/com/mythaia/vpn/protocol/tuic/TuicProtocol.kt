package com.mythaia.vpn.protocol.tuic

import java.net.InetAddress
import java.util.UUID

/**
 * The TUIC v5 wire format.
 *
 * Every message is a command: a version byte, a type byte, then whatever that
 * type carries. Big-endian throughout. The whole protocol is five commands, and
 * the notable thing about it is what is missing — there are no responses. A
 * client sends `Connect` and starts relaying immediately without waiting, which
 * is where the round trip it saves comes from, and a server that objects says
 * so by closing the stream rather than by answering.
 *
 * Written from the TUIC specification (SPEC.md, protocol version 0x05), not
 * ported: no reference implementation of it exists in the Anywhere tree.
 */
object TuicProtocol {

    const val VERSION: Byte = 0x05

    // Command types.
    const val CMD_AUTHENTICATE: Byte = 0x00
    const val CMD_CONNECT: Byte = 0x01
    const val CMD_PACKET: Byte = 0x02
    const val CMD_DISSOCIATE: Byte = 0x03
    const val CMD_HEARTBEAT: Byte = 0x04

    // Address types.
    const val ADDR_NONE: Byte = 0xFF.toByte()
    const val ADDR_DOMAIN: Byte = 0x00
    const val ADDR_IPV4: Byte = 0x01
    const val ADDR_IPV6: Byte = 0x02

    /** The exporter output length, and so the token length. */
    const val TOKEN_LENGTH = 32

    /** `VER` and `TYPE`. */
    const val HEADER_SIZE = 2

    /** assoc(2) + pkt(2) + fragTotal(1) + fragId(1) + size(2). */
    const val PACKET_HEADER_SIZE = 8

    /** A domain name cannot be longer than one length byte can describe. */
    const val MAX_DOMAIN_LENGTH = 255

    /**
     * The label the exporter is called with is the client's UUID as text, and
     * the context is the raw password. That binding is what makes a token
     * worthless off the connection it was made on.
     */
    fun authenticate(uuid: UUID, token: ByteArray): ByteArray {
        require(token.size == TOKEN_LENGTH) { "TUIC token must be $TOKEN_LENGTH bytes" }
        val out = ByteArray(HEADER_SIZE + 16 + TOKEN_LENGTH)
        out[0] = VERSION
        out[1] = CMD_AUTHENTICATE
        writeUuid(out, HEADER_SIZE, uuid)
        token.copyInto(out, HEADER_SIZE + 16)
        return out
    }

    /** Opens a TCP relay. The stream carries payload straight after this. */
    fun connect(host: String, port: Int): ByteArray {
        val address = encodeAddress(host, port)
        val out = ByteArray(HEADER_SIZE + address.size)
        out[0] = VERSION
        out[1] = CMD_CONNECT
        address.copyInto(out, HEADER_SIZE)
        return out
    }

    /** Ends a UDP session, releasing the socket the server bound for it. */
    fun dissociate(associationId: Int): ByteArray = byteArrayOf(
        VERSION, CMD_DISSOCIATE,
        (associationId ushr 8).toByte(), associationId.toByte()
    )

    /** Keeps the connection alive while a relay is in progress. */
    fun heartbeat(): ByteArray = byteArrayOf(VERSION, CMD_HEARTBEAT)

    /** One UDP datagram, or one fragment of one. */
    data class Packet(
        val associationId: Int,
        val packetId: Int,
        val fragmentTotal: Int,
        val fragmentId: Int,
        val host: String?,
        val port: Int,
        val payload: ByteArray
    ) {
        override fun equals(other: Any?): Boolean =
            other is Packet &&
                associationId == other.associationId &&
                packetId == other.packetId &&
                fragmentTotal == other.fragmentTotal &&
                fragmentId == other.fragmentId &&
                host == other.host &&
                port == other.port &&
                payload.contentEquals(other.payload)

        override fun hashCode(): Int {
            var result = associationId
            result = 31 * result + packetId
            result = 31 * result + fragmentTotal
            result = 31 * result + fragmentId
            result = 31 * result + (host?.hashCode() ?: 0)
            result = 31 * result + port
            result = 31 * result + payload.contentHashCode()
            return result
        }
    }

    /**
     * Encodes a packet command.
     *
     * Only the first fragment carries an address; the rest use the `None` type,
     * because repeating it would waste room in every fragment of a datagram
     * that was split precisely because room was short.
     */
    fun packet(packet: Packet): ByteArray {
        val address = if (packet.fragmentId == 0 && packet.host != null) {
            encodeAddress(packet.host, packet.port)
        } else {
            byteArrayOf(ADDR_NONE)
        }

        val out = ByteArray(HEADER_SIZE + PACKET_HEADER_SIZE + address.size + packet.payload.size)
        var at = 0
        out[at++] = VERSION
        out[at++] = CMD_PACKET
        out[at++] = (packet.associationId ushr 8).toByte()
        out[at++] = packet.associationId.toByte()
        out[at++] = (packet.packetId ushr 8).toByte()
        out[at++] = packet.packetId.toByte()
        out[at++] = packet.fragmentTotal.toByte()
        out[at++] = packet.fragmentId.toByte()
        out[at++] = (packet.payload.size ushr 8).toByte()
        out[at++] = packet.payload.size.toByte()
        address.copyInto(out, at); at += address.size
        packet.payload.copyInto(out, at)
        return out
    }

    /**
     * Decodes a packet command, or null when the bytes do not hold a whole one.
     *
     * Null rather than an exception: these arrive in unreliable datagrams, so a
     * short or malformed one is something to drop, not something exceptional.
     */
    fun parsePacket(bytes: ByteArray): Packet? {
        if (bytes.size < HEADER_SIZE + PACKET_HEADER_SIZE) return null
        if (bytes[0] != VERSION || bytes[1] != CMD_PACKET) return null

        var at = HEADER_SIZE
        val association = readUShort(bytes, at); at += 2
        val packetId = readUShort(bytes, at); at += 2
        val fragmentTotal = bytes[at++].toInt() and 0xFF
        val fragmentId = bytes[at++].toInt() and 0xFF
        val size = readUShort(bytes, at); at += 2

        val address = parseAddress(bytes, at) ?: return null
        at += address.size

        if (at + size > bytes.size) return null
        return Packet(
            associationId = association,
            packetId = packetId,
            fragmentTotal = fragmentTotal,
            fragmentId = fragmentId,
            host = address.host,
            port = address.port,
            payload = bytes.copyOfRange(at, at + size)
        )
    }

    // MARK: - Address

    /** A decoded address and how many bytes it took. */
    data class Address(val host: String?, val port: Int, val size: Int)

    fun encodeAddress(host: String, port: Int): ByteArray {
        val literal = runCatching {
            if (isLiteral(host)) InetAddress.getByName(host).address else null
        }.getOrNull()

        val body: ByteArray = when {
            literal != null && literal.size == 4 -> byteArrayOf(ADDR_IPV4) + literal
            literal != null && literal.size == 16 -> byteArrayOf(ADDR_IPV6) + literal
            else -> {
                val name = host.toByteArray(Charsets.UTF_8)
                val trimmed = if (name.size > MAX_DOMAIN_LENGTH) {
                    name.copyOf(MAX_DOMAIN_LENGTH)
                } else {
                    name
                }
                byteArrayOf(ADDR_DOMAIN, trimmed.size.toByte()) + trimmed
            }
        }
        return body + byteArrayOf((port ushr 8).toByte(), port.toByte())
    }

    /** Reads an address at [offset], or null when it runs past the buffer. */
    fun parseAddress(bytes: ByteArray, offset: Int): Address? {
        if (offset >= bytes.size) return null

        return when (bytes[offset]) {
            ADDR_NONE -> Address(null, 0, 1)

            ADDR_IPV4 -> {
                if (offset + 1 + 4 + 2 > bytes.size) return null
                val host = InetAddress.getByAddress(
                    bytes.copyOfRange(offset + 1, offset + 5)
                ).hostAddress
                Address(host, readUShort(bytes, offset + 5), 1 + 4 + 2)
            }

            ADDR_IPV6 -> {
                if (offset + 1 + 16 + 2 > bytes.size) return null
                val host = InetAddress.getByAddress(
                    bytes.copyOfRange(offset + 1, offset + 17)
                ).hostAddress
                Address(host, readUShort(bytes, offset + 17), 1 + 16 + 2)
            }

            ADDR_DOMAIN -> {
                if (offset + 2 > bytes.size) return null
                val length = bytes[offset + 1].toInt() and 0xFF
                if (offset + 2 + length + 2 > bytes.size) return null
                val host = String(bytes, offset + 2, length, Charsets.UTF_8)
                Address(host, readUShort(bytes, offset + 2 + length), 1 + 1 + length + 2)
            }

            else -> null
        }
    }

    // MARK: - Internal

    /**
     * Whether this is an address rather than a name.
     *
     * Checked by shape first: `InetAddress.getByName` on a name performs a DNS
     * lookup, and doing that here would resolve on whichever thread happened to
     * be encoding a packet.
     */
    private fun isLiteral(host: String): Boolean {
        if (host.contains(':')) return host.all { it.isDigit() || it in "abcdefABCDEF:." }
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it.isDigit() }
        }
    }

    private fun readUShort(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)

    private fun writeUuid(out: ByteArray, at: Int, uuid: UUID) {
        var high = uuid.mostSignificantBits
        var low = uuid.leastSignificantBits
        for (i in 7 downTo 0) {
            out[at + i] = high.toByte()
            high = high ushr 8
        }
        for (i in 15 downTo 8) {
            out[at + i] = low.toByte()
            low = low ushr 8
        }
    }
}
