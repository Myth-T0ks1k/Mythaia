package com.mythaia.vpn.util

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * The DNS wire format (RFC 1035), as much of it as a client needs: a query
 * going out, and the addresses in the answer coming back — read through the
 * name compression every real resolver uses.
 *
 * [PacketUtil.parseDnsQueryExt] is the other half: the query an *app* sent,
 * parsed and answered in place. This one is for questions we ask.
 *
 * Ports the iOS `DNSMessage`.
 */
object DnsMessage {

    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val TYPE_HTTPS = 65

    private const val TYPE_OPT = 41
    private const val CLASS_IN = 1
    private const val HEADER_LENGTH = 12

    /** How a response failed to be the answer we asked for. */
    sealed class ParseFailure(message: String) : Exception(message) {
        object Malformed : ParseFailure("malformed DNS message")

        /**
         * Somebody else's answer — a late reply to an earlier query on the same
         * socket. Keep waiting.
         */
        object IdentifierMismatch : ParseFailure("DNS identifier mismatch")

        class ServerFailure(val rcode: Int) : ParseFailure("DNS RCODE $rcode")
    }

    // MARK: - Query

    /**
     * One question, recursion desired. With [udpPayloadSize] an EDNS OPT record
     * is added so the server may answer past 512 bytes.
     *
     * Null when the name cannot be put on the wire: empty, a label over 63
     * bytes, or one that is not ASCII — IDNs are punycoded before they get
     * here, or not at all.
     */
    fun makeQuery(domain: String, type: Int, id: Int, udpPayloadSize: Int? = null): ByteArray? {
        val out = ArrayList<Byte>(32 + domain.length)

        out.add(((id shr 8) and 0xFF).toByte())
        out.add((id and 0xFF).toByte())
        out.add(0x01); out.add(0x00)                    // RD=1, everything else clear
        out.add(0x00); out.add(0x01)                    // QDCOUNT = 1
        out.add(0x00); out.add(0x00)                    // ANCOUNT
        out.add(0x00); out.add(0x00)                    // NSCOUNT
        out.add(0x00); out.add(if (udpPayloadSize == null) 0x00 else 0x01)   // ARCOUNT

        var labelCount = 0
        for (label in domain.split(".")) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            if (bytes.isEmpty() || bytes.size > 63) return null
            // toByteArray(US_ASCII) turns anything non-ASCII into '?', so check
            // the source characters rather than the encoded bytes.
            if (label.any { it.code >= 0x80 }) return null
            out.add(bytes.size.toByte())
            for (b in bytes) out.add(b)
            labelCount++
        }
        if (labelCount == 0) return null
        out.add(0)                                      // root label

        out.add(((type shr 8) and 0xFF).toByte())
        out.add((type and 0xFF).toByte())
        out.add(((CLASS_IN shr 8) and 0xFF).toByte())
        out.add((CLASS_IN and 0xFF).toByte())

        if (udpPayloadSize != null) {
            out.add(0)                                  // root owner name
            out.add(((TYPE_OPT shr 8) and 0xFF).toByte())
            out.add((TYPE_OPT and 0xFF).toByte())
            out.add(((udpPayloadSize shr 8) and 0xFF).toByte())
            out.add((udpPayloadSize and 0xFF).toByte())
            out.add(0); out.add(0); out.add(0); out.add(0)   // extended RCODE/flags clear
            out.add(0); out.add(0)                           // RDLENGTH = 0
        }

        if (out.size > 512) return null
        return out.toByteArray()
    }

    // MARK: - Response

    /** Every A and AAAA record in the answer section, IPv4 first. */
    @Throws(ParseFailure::class)
    fun parseAddresses(response: ByteArray, expectedId: Int): List<String> {
        val ipv4 = ArrayList<String>()
        val ipv6 = ArrayList<String>()
        walkAnswers(response, expectedId) { type, _, rdata ->
            if (type == TYPE_A && rdata.size == 4) {
                formatAddress(rdata)?.let { ipv4.add(it) }
            } else if (type == TYPE_AAAA && rdata.size == 16) {
                formatAddress(rdata)?.let { ipv6.add(it) }
            }
        }
        return ipv4 + ipv6
    }

    /** One record type, with the TTL the server put on each. */
    @Throws(ParseFailure::class)
    fun parseRecords(response: ByteArray, expectedId: Int, wantedType: Int): List<Pair<ByteArray, Long>> {
        val records = ArrayList<Pair<ByteArray, Long>>()
        walkAnswers(response, expectedId) { type, ttl, rdata ->
            if (type == wantedType) records.add(rdata to ttl)
        }
        return records
    }

    // MARK: - Internal

    @Throws(ParseFailure::class)
    private inline fun walkAnswers(
        response: ByteArray,
        expectedId: Int,
        onRecord: (type: Int, ttl: Long, rdata: ByteArray) -> Unit
    ) {
        if (response.size < HEADER_LENGTH) throw ParseFailure.Malformed

        val id = ((response[0].toInt() and 0xFF) shl 8) or (response[1].toInt() and 0xFF)
        if (id != expectedId) throw ParseFailure.IdentifierMismatch
        if (response[2].toInt() and 0x80 == 0) throw ParseFailure.Malformed   // QR must be set

        val rcode = response[3].toInt() and 0x0F
        if (rcode != 0) throw ParseFailure.ServerFailure(rcode)

        val questionCount = ((response[4].toInt() and 0xFF) shl 8) or (response[5].toInt() and 0xFF)
        val answerCount = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)

        var offset = HEADER_LENGTH
        repeat(questionCount) {
            offset = skipName(response, offset) ?: throw ParseFailure.Malformed
            offset += 4                                                       // QTYPE + QCLASS
            if (offset > response.size) throw ParseFailure.Malformed
        }

        repeat(answerCount) {
            offset = skipName(response, offset) ?: throw ParseFailure.Malformed
            if (offset + 10 > response.size) throw ParseFailure.Malformed

            val type = ((response[offset].toInt() and 0xFF) shl 8) or
                (response[offset + 1].toInt() and 0xFF)
            val recordClass = ((response[offset + 2].toInt() and 0xFF) shl 8) or
                (response[offset + 3].toInt() and 0xFF)
            val ttl = ((response[offset + 4].toLong() and 0xFF) shl 24) or
                ((response[offset + 5].toLong() and 0xFF) shl 16) or
                ((response[offset + 6].toLong() and 0xFF) shl 8) or
                (response[offset + 7].toLong() and 0xFF)
            val rdLength = ((response[offset + 8].toInt() and 0xFF) shl 8) or
                (response[offset + 9].toInt() and 0xFF)
            offset += 10
            if (offset + rdLength > response.size) throw ParseFailure.Malformed

            if (recordClass == CLASS_IN) {
                onRecord(type, ttl, response.copyOfRange(offset, offset + rdLength))
            }
            offset += rdLength
        }
    }

    /**
     * The offset just past a name, whether spelled out, compressed, or both.
     *
     * A pointer ends the name; it may only point backwards, which is what keeps
     * a hostile message from sending the parser in circles.
     */
    private fun skipName(bytes: ByteArray, from: Int): Int? {
        var cursor = from

        while (cursor < bytes.size) {
            val length = bytes[cursor].toInt() and 0xFF

            if (length and 0xC0 == 0xC0) {
                if (cursor + 2 > bytes.size) return null
                val target = ((length and 0x3F) shl 8) or (bytes[cursor + 1].toInt() and 0xFF)
                if (target >= cursor || target < HEADER_LENGTH) return null
                return cursor + 2
            }
            if (length and 0xC0 != 0) return null            // reserved label type

            cursor += 1
            if (length == 0) return cursor                   // root label ends the name
            cursor += length
            if (cursor > bytes.size) return null
        }
        return null
    }

    /** Presentation form of 4 or 16 raw address bytes. */
    private fun formatAddress(rdata: ByteArray): String? = try {
        when (val address = InetAddress.getByAddress(rdata)) {
            is Inet4Address -> address.hostAddress
            is Inet6Address -> address.hostAddress
            else -> null
        }
    } catch (_: Exception) {
        null
    }
}
