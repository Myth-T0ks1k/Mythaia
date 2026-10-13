package com.mythaia.vpn.util

/**
 * Pure-Kotlin packet utilities.
 */
object PacketUtil {

    /**
     * Returns a new 12-byte nonce formed by XORing the last 8 bytes of [iv]
     * with the big-endian encoding of [seqNum]. Used for TLS 1.3 AEAD.
     */
    fun xorNonce(iv: ByteArray, seqNum: Long): ByteArray {
        require(iv.size == 12) { "nonce must be 12 bytes" }
        val out = iv.copyOf()
        out[4]  = (out[4].toInt()  xor ((seqNum ushr 56).toInt() and 0xFF)).toByte()
        out[5]  = (out[5].toInt()  xor ((seqNum ushr 48).toInt() and 0xFF)).toByte()
        out[6]  = (out[6].toInt()  xor ((seqNum ushr 40).toInt() and 0xFF)).toByte()
        out[7]  = (out[7].toInt()  xor ((seqNum ushr 32).toInt() and 0xFF)).toByte()
        out[8]  = (out[8].toInt()  xor ((seqNum ushr 24).toInt() and 0xFF)).toByte()
        out[9]  = (out[9].toInt()  xor ((seqNum ushr 16).toInt() and 0xFF)).toByte()
        out[10] = (out[10].toInt() xor ((seqNum ushr 8).toInt()  and 0xFF)).toByte()
        out[11] = (out[11].toInt() xor (seqNum.toInt()            and 0xFF)).toByte()
        return out
    }

    /**
     * Strips TLS 1.3 zero padding and splits out the inner content type.
     * Returns a byte array whose first byte is the inner content type and
     * whose tail is the plaintext, or null on invalid input.
     */
    fun tls13UnwrapContent(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null

        // Scan backwards to find the last non-zero byte (content type).
        var i = data.size - 1
        while (i >= 0 && data[i].toInt() == 0) i--
        if (i < 0) return null

        val result = ByteArray(1 + i)
        result[0] = data[i]
        if (i > 0) System.arraycopy(data, 0, result, 1, i)
        return result
    }

    fun frameUdpPayload(payload: ByteArray): ByteArray {
        val out = ByteArray(2 + payload.size)
        out[0] = ((payload.size ushr 8) and 0xFF).toByte()
        out[1] = (payload.size and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 2, payload.size)
        return out
    }

    data class DnsQuery(val domain: String, val qtype: Int)

    /**
     * Parses a DNS query packet. Returns the domain (preserving its on-wire
     * case) and QTYPE, or null on malformed input. Compressed pointers in
     * QNAME are rejected (they're not expected in queries). Callers that
     * match the domain against a case-insensitive table must lowercase it
     * themselves; both LwipStack DNS interception and DomainRouter do.
     */
    fun parseDnsQueryExt(data: ByteArray): DnsQuery? {
        if (data.size < 12) return null

        val qdcount = ((data[4].toInt() and 0xFF) shl 8) or (data[5].toInt() and 0xFF)
        if (qdcount == 0) return null

        var offset = 12
        val sb = StringBuilder()

        while (offset < data.size) {
            val labelLen = data[offset].toInt() and 0xFF
            offset++
            if (labelLen == 0) break
            if ((labelLen and 0xC0) != 0) return null
            if (offset + labelLen > data.size) return null

            if (sb.isNotEmpty()) sb.append('.')
            for (k in 0 until labelLen) {
                sb.append((data[offset + k].toInt() and 0xFF).toChar())
            }
            offset += labelLen
        }

        if (sb.isEmpty()) return null

        if (offset + 2 > data.size) return null
        val qtype = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

        return DnsQuery(sb.toString(), qtype)
    }

    /**
     * Builds a DNS response for [query] that either resolves to [fakeIp]
     * (when non-null and [qtype] is A/AAAA) or a NODATA reply otherwise.
     */
    fun generateDnsResponse(query: ByteArray, fakeIp: ByteArray?, qtype: Int): ByteArray? {
        if (query.size < 12) return null

        // QNAME terminator + QTYPE(2) + QCLASS(2)
        var offset = 12
        while (offset < query.size) {
            val labelLen = query[offset].toInt() and 0xFF
            offset++
            if (labelLen == 0) break
            if ((labelLen and 0xC0) != 0) break
            offset += labelLen
        }
        offset += 4
        if (offset > query.size) return null
        val questionEnd = offset

        var rdLength = 0
        var ansType = 0
        if (fakeIp != null) {
            if (qtype == 1) {
                rdLength = 4
                ansType = 1
            } else if (qtype == 28) {
                rdLength = 16
                ansType = 28
            }
        }

        fun writeHeader(buf: ByteArray, ancount: Int) {
            buf[2] = 0x85.toByte()       // QR=1, AA=1, RD=1
            buf[3] = 0x80.toByte()       // RA=1
            buf[6] = ((ancount ushr 8) and 0xFF).toByte()
            buf[7] = (ancount and 0xFF).toByte()
            buf[8] = 0; buf[9] = 0       // NSCOUNT = 0
            buf[10] = 0; buf[11] = 0     // ARCOUNT = 0
        }

        if (rdLength > 0 && fakeIp != null && fakeIp.size >= rdLength) {
            // name(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata
            val answerLen = 12 + rdLength
            val out = ByteArray(questionEnd + answerLen)
            System.arraycopy(query, 0, out, 0, questionEnd)
            writeHeader(out, 1)

            val ans = questionEnd
            out[ans]     = 0xC0.toByte()
            out[ans + 1] = 0x0C.toByte()                         // pointer to QNAME
            out[ans + 2] = ((ansType ushr 8) and 0xFF).toByte()
            out[ans + 3] = (ansType and 0xFF).toByte()
            out[ans + 4] = 0x00; out[ans + 5] = 0x01             // CLASS = IN
            out[ans + 6] = 0x00; out[ans + 7] = 0x00
            out[ans + 8] = 0x00; out[ans + 9] = 0x01             // TTL = 1s
            out[ans + 10] = ((rdLength ushr 8) and 0xFF).toByte()
            out[ans + 11] = (rdLength and 0xFF).toByte()
            System.arraycopy(fakeIp, 0, out, ans + 12, rdLength)
            return out
        }

        val out = ByteArray(questionEnd)
        System.arraycopy(query, 0, out, 0, questionEnd)
        writeHeader(out, 0)
        return out
    }

    /**
     * Parses a TLS ServerHello record batch and extracts the X25519 key-share
     * (group 0x001d) plus the negotiated cipher suite. Returns a 34-byte
     * array: [32-byte key share][cipher BE], or null if no matching
     * ServerHello / X25519 key share is found.
     */
    fun parseServerHello(data: ByteArray): ByteArray? {
        var offset = 0
        while (offset + 5 < data.size) {
            val contentType = data[offset].toInt() and 0xFF
            if (contentType != 0x16) return null

            val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or
                    (data[offset + 4].toInt() and 0xFF)
            offset += 5
            if (offset + recordLen > data.size) return null
            if ((data[offset].toInt() and 0xFF) != 0x02) {
                offset += recordLen
                continue
            }

            // type(1) + length(3) + version(2) + random(32)
            var sh = offset + 1 + 3 + 2 + 32
            if (sh >= data.size) return null

            val sessionIdLen = data[sh].toInt() and 0xFF
            sh += 1 + sessionIdLen

            if (sh + 2 > data.size) return null
            val cipherSuite = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
            sh += 3  // cipher(2) + compression(1)

            if (sh + 2 > data.size) return null
            val extLen = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
            sh += 2
            val extEnd = sh + extLen
            if (extEnd > data.size) return null

            while (sh + 4 <= extEnd) {
                val extType = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
                val extDataLen = ((data[sh + 2].toInt() and 0xFF) shl 8) or (data[sh + 3].toInt() and 0xFF)
                sh += 4

                val extDataStart = sh

                if (extType == 0x0033) {
                    if (sh + 4 > data.size) return null
                    val group = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
                    val keyLen = ((data[sh + 2].toInt() and 0xFF) shl 8) or (data[sh + 3].toInt() and 0xFF)
                    sh += 4

                    if (group == 0x001d && keyLen == 32) {
                        if (sh + 32 > data.size) return null
                        val result = ByteArray(34)
                        System.arraycopy(data, sh, result, 0, 32)
                        result[32] = ((cipherSuite ushr 8) and 0xFF).toByte()
                        result[33] = (cipherSuite and 0xFF).toByte()
                        return result
                    }
                }

                // From the extension's start, not from wherever the key_share
                // branch stopped reading: a share for another group (or the
                // group-only share of a HelloRetryRequest) left the walk four
                // bytes adrift and every extension after it misread.
                sh = extDataStart + extDataLen
            }

            return null
        }
        return null
    }

    /**
     * Whether the ServerHello in [data] (TLS records) selects TLS 1.3 through
     * supported_versions, whatever key share it carries.
     */
    fun serverHelloSelectsTls13(data: ByteArray): Boolean {
        var offset = 0
        while (offset + 5 <= data.size) {
            if ((data[offset].toInt() and 0xFF) != 0x16) return false
            val recordLen = ((data[offset + 3].toInt() and 0xFF) shl 8) or (data[offset + 4].toInt() and 0xFF)
            offset += 5
            if (offset + recordLen > data.size) return false
            if ((data[offset].toInt() and 0xFF) != 0x02) {
                offset += recordLen
                continue
            }
            var sh = offset + 1 + 3 + 2 + 32
            if (sh >= data.size) return false
            sh += 1 + (data[sh].toInt() and 0xFF)
            sh += 3 // cipher(2) + compression(1)
            if (sh + 2 > data.size) return false
            val extEnd = sh + 2 + (((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF))
            sh += 2
            if (extEnd > data.size) return false
            while (sh + 4 <= extEnd) {
                val extType = ((data[sh].toInt() and 0xFF) shl 8) or (data[sh + 1].toInt() and 0xFF)
                val extDataLen = ((data[sh + 2].toInt() and 0xFF) shl 8) or (data[sh + 3].toInt() and 0xFF)
                sh += 4
                if (extType == 0x002B && extDataLen == 2 && sh + 2 <= extEnd) {
                    return data[sh].toInt() == 0x03 && data[sh + 1].toInt() == 0x04
                }
                sh += extDataLen
            }
            return false
        }
        return false
    }

    /**
     * The body of extension [type] in [clientHello] (a handshake message, no
     * record header), or null when the hello does not carry it.
     */
    fun clientHelloExtension(clientHello: ByteArray, type: Int): ByteArray? {
        // type(1) length(3) version(2) random(32) session_id cipher_suites compression extensions
        var i = 1 + 3 + 2 + 32
        if (i >= clientHello.size) return null
        i += 1 + (clientHello[i].toInt() and 0xFF)
        if (i + 2 > clientHello.size) return null
        i += 2 + (((clientHello[i].toInt() and 0xFF) shl 8) or (clientHello[i + 1].toInt() and 0xFF))
        if (i >= clientHello.size) return null
        i += 1 + (clientHello[i].toInt() and 0xFF)
        if (i + 2 > clientHello.size) return null
        val extEnd = i + 2 + (((clientHello[i].toInt() and 0xFF) shl 8) or (clientHello[i + 1].toInt() and 0xFF))
        if (extEnd > clientHello.size) return null
        i += 2
        while (i + 4 <= extEnd) {
            val extType = ((clientHello[i].toInt() and 0xFF) shl 8) or (clientHello[i + 1].toInt() and 0xFF)
            val extLen = ((clientHello[i + 2].toInt() and 0xFF) shl 8) or (clientHello[i + 3].toInt() and 0xFF)
            val dataStart = i + 4
            if (dataStart + extLen > extEnd) return null
            if (extType == type) return clientHello.copyOfRange(dataStart, dataStart + extLen)
            i = dataStart + extLen
        }
        return null
    }

    /** Whether [clientHello] (a handshake message) lists TLS 1.3 in supported_versions. */
    fun clientHelloOffersTls13(clientHello: ByteArray): Boolean {
        val versions = clientHelloExtension(clientHello, 0x002B) ?: return false
        var v = 1
        while (v + 2 <= versions.size) {
            if (versions[v].toInt() == 0x03 && versions[v + 1].toInt() == 0x04) return true
            v += 2
        }
        return false
    }
}
