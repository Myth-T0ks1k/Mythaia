package com.mythaia.vpn.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Ports `Mythaia Tests/DNSMessageTests.swift`.
 *
 * The parser reads messages a resolver sends us, so it has to survive a hostile
 * one: a compression pointer that loops, a length that runs past the buffer, a
 * label type nobody defined.
 */
class DnsMessageTest {

    // MARK: - makeQuery

    @Test
    fun `builds a well-formed A query`() {
        val query = DnsMessage.makeQuery("example.com", DnsMessage.TYPE_A, id = 0x1234)!!

        assertEquals(0x12.toByte(), query[0])
        assertEquals(0x34.toByte(), query[1])
        assertEquals(0x01.toByte(), query[2])   // RD set
        assertEquals(0x00.toByte(), query[3])
        assertEquals(1, be16(query, 4))         // QDCOUNT
        assertEquals(0, be16(query, 6))         // ANCOUNT
        assertEquals(0, be16(query, 10))        // ARCOUNT — no EDNS asked for

        // 7 "example" 3 "com" 0
        val expectedName = byteArrayOf(7) + "example".toByteArray() +
            byteArrayOf(3) + "com".toByteArray() + byteArrayOf(0)
        assertTrue(query.copyOfRange(12, 12 + expectedName.size).contentEquals(expectedName))

        val afterName = 12 + expectedName.size
        assertEquals(DnsMessage.TYPE_A, be16(query, afterName))
        assertEquals(1, be16(query, afterName + 2))    // class IN
        assertEquals(afterName + 4, query.size)
    }

    @Test
    fun `an EDNS payload size appends one OPT record`() {
        val plain = DnsMessage.makeQuery("example.com", DnsMessage.TYPE_A, id = 1)!!
        val edns = DnsMessage.makeQuery("example.com", DnsMessage.TYPE_A, id = 1, udpPayloadSize = 1232)!!

        assertEquals(0, be16(plain, 10))
        assertEquals(1, be16(edns, 10))
        // Root owner name, type OPT (41), class = the payload size.
        assertEquals(plain.size + 11, edns.size)
        assertEquals(0, edns[plain.size].toInt())
        assertEquals(41, be16(edns, plain.size + 1))
        assertEquals(1232, be16(edns, plain.size + 3))
    }

    @Test
    fun `names that cannot go on the wire are refused`() {
        assertNull(DnsMessage.makeQuery("", DnsMessage.TYPE_A, 1))
        assertNull(DnsMessage.makeQuery(".", DnsMessage.TYPE_A, 1))
        assertNull(DnsMessage.makeQuery("a..b", DnsMessage.TYPE_A, 1))
        // A label over 63 bytes has no length byte that can hold it.
        assertNull(DnsMessage.makeQuery("${"a".repeat(64)}.com", DnsMessage.TYPE_A, 1))
        assertNotNull(DnsMessage.makeQuery("${"a".repeat(63)}.com", DnsMessage.TYPE_A, 1))
        // Non-ASCII must be punycoded before it gets here, not silently mangled.
        assertNull(DnsMessage.makeQuery("пример.com", DnsMessage.TYPE_A, 1))
        // The whole message still has to fit a datagram.
        assertNull(DnsMessage.makeQuery(List(9) { "a".repeat(60) }.joinToString("."), DnsMessage.TYPE_A, 1))
    }

    // MARK: - parseAddresses

    @Test
    fun `reads A and AAAA records, IPv4 first`() {
        val response = response(
            id = 0x1234,
            question = "example.com",
            answers = listOf(
                answer(DnsMessage.TYPE_AAAA, byteArrayOf(
                    0x20, 0x01, 0x0d, 0x0b.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
                )),
                answer(DnsMessage.TYPE_A, byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34))
            )
        )

        val addresses = DnsMessage.parseAddresses(response, expectedId = 0x1234)
        assertEquals(2, addresses.size)
        assertEquals("93.184.216.34", addresses[0])
        assertTrue(addresses[1].startsWith("2001:"))
    }

    @Test
    fun `a compressed answer name is read through`() {
        // The answer's owner name is a pointer back to the question's, which is
        // what every real resolver sends.
        val response = response(
            id = 7,
            question = "example.com",
            answers = listOf(answer(DnsMessage.TYPE_A, byteArrayOf(1, 2, 3, 4), compressed = true))
        )
        assertEquals(listOf("1.2.3.4"), DnsMessage.parseAddresses(response, expectedId = 7))
    }

    @Test
    fun `records of another class are ignored`() {
        val response = response(
            id = 3,
            question = "example.com",
            answers = listOf(answer(DnsMessage.TYPE_A, byteArrayOf(1, 2, 3, 4), recordClass = 3))
        )
        assertTrue(DnsMessage.parseAddresses(response, expectedId = 3).isEmpty())
    }

    @Test
    fun `an answer for another query is reported as a mismatch`() {
        val response = response(id = 1, question = "example.com",
            answers = listOf(answer(DnsMessage.TYPE_A, byteArrayOf(1, 2, 3, 4))))
        try {
            DnsMessage.parseAddresses(response, expectedId = 2)
            fail("expected IdentifierMismatch")
        } catch (e: DnsMessage.ParseFailure) {
            assertTrue(e is DnsMessage.ParseFailure.IdentifierMismatch)
        }
    }

    @Test
    fun `a non-zero RCODE is surfaced, not silently empty`() {
        val response = response(id = 1, question = "example.com", answers = emptyList(), rcode = 3)
        try {
            DnsMessage.parseAddresses(response, expectedId = 1)
            fail("expected ServerFailure")
        } catch (e: DnsMessage.ParseFailure) {
            assertTrue(e is DnsMessage.ParseFailure.ServerFailure)
            assertEquals(3, (e as DnsMessage.ParseFailure.ServerFailure).rcode)
        }
    }

    @Test
    fun `a hostile message cannot hang or overrun the parser`() {
        val good = response(id = 5, question = "example.com",
            answers = listOf(answer(DnsMessage.TYPE_A, byteArrayOf(1, 2, 3, 4))))

        // Truncated header.
        expectFailure(byteArrayOf(0, 5, 0x81.toByte(), 0), 5)

        // QR clear: a query, not an answer.
        val notAnAnswer = good.copyOf().also { it[2] = 0x01 }
        expectFailure(notAnAnswer, 5)

        // A pointer to itself would loop forever if it were followed; the
        // parser only accepts a strictly backwards target.
        val selfPointer = good.copyOf()
        val nameStart = 12
        selfPointer[nameStart] = 0xC0.toByte()
        selfPointer[nameStart + 1] = nameStart.toByte()
        expectFailure(selfPointer, 5)

        // A forward pointer is the same trap in the other direction.
        val forwardPointer = good.copyOf()
        forwardPointer[nameStart] = 0xC0.toByte()
        forwardPointer[nameStart + 1] = (good.size - 1).toByte()
        expectFailure(forwardPointer, 5)

        // A pointer into the header is not a name.
        val headerPointer = good.copyOf()
        headerPointer[nameStart] = 0xC0.toByte()
        headerPointer[nameStart + 1] = 0
        expectFailure(headerPointer, 5)

        // RDLENGTH claiming more than is there.
        val overrun = good.copyOf()
        overrun[overrun.size - 5] = 0xFF.toByte()
        expectFailure(overrun, 5)

        // Every truncation of a valid message either parses or fails cleanly —
        // what it must never do is throw something other than ParseFailure.
        for (cut in 0 until good.size) {
            try {
                DnsMessage.parseAddresses(good.copyOfRange(0, cut), expectedId = 5)
            } catch (_: DnsMessage.ParseFailure) {
                // expected
            }
        }
    }

    private fun expectFailure(message: ByteArray, id: Int) {
        try {
            DnsMessage.parseAddresses(message, expectedId = id)
            fail("expected ParseFailure for ${message.size} bytes")
        } catch (_: DnsMessage.ParseFailure) {
            // expected
        }
    }

    // MARK: - Builders

    private fun be16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)

    private class Answer(
        val type: Int,
        val rdata: ByteArray,
        val recordClass: Int,
        val compressed: Boolean
    )

    private fun answer(
        type: Int,
        rdata: ByteArray,
        recordClass: Int = 1,
        compressed: Boolean = false
    ) = Answer(type, rdata, recordClass, compressed)

    private fun encodeName(domain: String): ByteArray {
        val out = ArrayList<Byte>()
        for (label in domain.split(".")) {
            out.add(label.length.toByte())
            for (b in label.toByteArray()) out.add(b)
        }
        out.add(0)
        return out.toByteArray()
    }

    private fun response(
        id: Int,
        question: String,
        answers: List<Answer>,
        rcode: Int = 0
    ): ByteArray {
        val out = ArrayList<Byte>()
        out.add(((id shr 8) and 0xFF).toByte()); out.add((id and 0xFF).toByte())
        out.add(0x81.toByte())                                   // QR + RD
        out.add((0x80 or rcode).toByte())                        // RA + RCODE
        out.add(0); out.add(1)                                   // QDCOUNT
        out.add(((answers.size shr 8) and 0xFF).toByte())
        out.add((answers.size and 0xFF).toByte())                // ANCOUNT
        out.add(0); out.add(0)                                   // NSCOUNT
        out.add(0); out.add(0)                                   // ARCOUNT

        val name = encodeName(question)
        for (b in name) out.add(b)
        out.add(0); out.add(DnsMessage.TYPE_A.toByte())          // QTYPE
        out.add(0); out.add(1)                                   // QCLASS

        for (a in answers) {
            if (a.compressed) {
                out.add(0xC0.toByte()); out.add(12)              // pointer to the question name
            } else {
                for (b in name) out.add(b)
            }
            out.add(((a.type shr 8) and 0xFF).toByte()); out.add((a.type and 0xFF).toByte())
            out.add(((a.recordClass shr 8) and 0xFF).toByte()); out.add((a.recordClass and 0xFF).toByte())
            out.add(0); out.add(0); out.add(0); out.add(60)      // TTL
            out.add(((a.rdata.size shr 8) and 0xFF).toByte()); out.add((a.rdata.size and 0xFF).toByte())
            for (b in a.rdata) out.add(b)
        }
        return out.toByteArray()
    }
}
