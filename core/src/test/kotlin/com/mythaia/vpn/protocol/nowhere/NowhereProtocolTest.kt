package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.IDN
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The expectations here are written out from the Nowhere wire format itself —
 * its named constants, its bit layout and its stated field widths — byte by
 * byte, rather than captured from this encoder. A codec compared only against
 * itself agrees with its own mistakes, and the framing is the whole contract
 * with the portal.
 *
 * The two mechanisms that get the hardest treatment are the ones with the most
 * room to be subtly wrong: the portal hop counter, which shares a byte with
 * four other fields, and UDP fragmentation, where a header eight bytes larger
 * than the unfragmented one makes every size boundary its own special case.
 */
class NowhereProtocolTest {

    /** Builds a buffer from literal bytes, ASCII/UTF-8 text and other buffers. */
    private fun wire(vararg parts: Any): ByteArray {
        val out = ByteArrayOutputStream()
        for (part in parts) when (part) {
            is Int -> out.write(part)
            is String -> out.write(part.toByteArray(Charsets.UTF_8))
            is ByteArray -> out.write(part)
            else -> throw IllegalArgumentException("unsupported part: $part")
        }
        return out.toByteArray()
    }

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    private fun duplexHeader(
        flowId: Long = 1,
        kind: NowhereProtocol.FlowKind = NowhereProtocol.FlowKind.TCP,
        carrier: NowhereNetwork = NowhereNetwork.TCP,
        hops: Int = 0
    ) = NowhereProtocol.FlowHeader(
        role = NowhereProtocol.FlowRole.DUPLEX,
        flowId = flowId,
        kind = kind,
        uplink = carrier,
        downlink = carrier,
        hops = hops
    )

    // Constants.

    @Test
    fun `every named constant holds the value the format specifies`() {
        assertEquals(0x100L, NowhereProtocol.CLOSE_ERR_CODE_OK)
        assertEquals("now/1", NowhereProtocol.DEFAULT_ALPN)
        assertEquals(32, NowhereProtocol.AUTH_FRAME_SIZE)
        assertEquals(5, NowhereProtocol.FLOW_HEADER_SIZE)
        assertEquals(1, NowhereProtocol.FLOW_RESULT_SIZE)
        assertEquals(5, NowhereProtocol.UDP_HEADER_SIZE)
        assertEquals(13, NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE)
        assertEquals(65535, NowhereProtocol.MAX_UDP_PACKET_SIZE)
        assertEquals(253, NowhereProtocol.MAX_DOMAIN_LENGTH)
        assertEquals(7, NowhereProtocol.MAX_PORTAL_HOPS)

        assertEquals(16, NowhereProtocol.SESSION_ID_SIZE)
        assertEquals(32, NowhereProtocol.AUTH_KEY_SIZE)
        assertEquals("nowhere/now/1/auth-root", NowhereProtocol.AUTH_ROOT_LABEL)
        assertEquals("authentication", NowhereProtocol.AUTH_INFO_LABEL)
        assertEquals("EXPORTER-Nowhere-Auth", NowhereProtocol.EXPORTER_LABEL)
        assertEquals(32, NowhereProtocol.EXPORTER_LENGTH)
    }

    @Test
    fun `the enumerations use the wire numbers, not their declaration order`() {
        assertEquals(0x01, NowhereProtocol.AuthTransport.TLS_TCP.value)
        assertEquals(0x02, NowhereProtocol.AuthTransport.QUIC.value)

        assertEquals(0, NowhereProtocol.FlowRole.DUPLEX.value)
        assertEquals(1, NowhereProtocol.FlowRole.OPEN.value)
        assertEquals(2, NowhereProtocol.FlowRole.ATTACH.value)

        assertEquals(0, NowhereProtocol.FlowKind.TCP.value)
        assertEquals(1, NowhereProtocol.FlowKind.UDP.value)

        assertEquals(0, NowhereProtocol.UdpType.DATA.value)
        assertEquals(1, NowhereProtocol.UdpType.FRAGMENT.value)
        assertEquals(2, NowhereProtocol.UdpType.CLOSE.value)

        assertEquals(1, NowhereProtocol.FlowRejectCode.INVALID_REQUEST.value)
        assertEquals(2, NowhereProtocol.FlowRejectCode.METADATA_CONFLICT.value)
        assertEquals(3, NowhereProtocol.FlowRejectCode.PAIR_TIMEOUT.value)
        assertEquals(4, NowhereProtocol.FlowRejectCode.FLOW_LIMIT.value)
        assertEquals(5, NowhereProtocol.FlowRejectCode.DIAL_FAILED.value)
        assertEquals(6, NowhereProtocol.FlowRejectCode.SESSION_REPLACED.value)
        assertEquals(7, NowhereProtocol.FlowRejectCode.INTERNAL_ERROR.value)

        assertEquals("invalid request", NowhereProtocol.FlowRejectCode.INVALID_REQUEST.description)
        assertEquals("metadata conflict", NowhereProtocol.FlowRejectCode.METADATA_CONFLICT.description)
        assertEquals("pair timeout", NowhereProtocol.FlowRejectCode.PAIR_TIMEOUT.description)
        assertEquals("flow limit", NowhereProtocol.FlowRejectCode.FLOW_LIMIT.description)
        assertEquals("dial failed", NowhereProtocol.FlowRejectCode.DIAL_FAILED.description)
        assertEquals("session replaced", NowhereProtocol.FlowRejectCode.SESSION_REPLACED.description)
        assertEquals("internal error", NowhereProtocol.FlowRejectCode.INTERNAL_ERROR.description)

        assertEquals("tcp", NowhereNetwork.TCP.wireName)
        assertEquals("udp", NowhereNetwork.UDP.wireName)
        assertEquals(NowhereNetwork.UDP, NowhereNetwork.fromWireName("UDP"))
        assertNull(NowhereNetwork.fromWireName("sctp"))
    }

    // Flow header bit layout.

    @Test
    fun `a flow header is a flags byte and a big-endian flow id`() {
        val encoded = NowhereProtocol.encodeFlowHeader(duplexHeader(flowId = 0x01020304))
        assertEquals(NowhereProtocol.FLOW_HEADER_SIZE, encoded.size)
        assertArrayEquals(bytes(0x00, 0x01, 0x02, 0x03, 0x04), encoded)
    }

    @Test
    fun `the flow id occupies bytes one through four unsigned`() {
        val encoded = NowhereProtocol.encodeFlowHeader(duplexHeader(flowId = 0xFFFFFFFFL))
        assertArrayEquals(bytes(0x00, 0xFF, 0xFF, 0xFF, 0xFF), encoded)
        assertEquals(0xFFFFFFFFL, NowhereProtocol.decodeFlowHeader(encoded)!!.flowId)
    }

    @Test
    fun `role sits in bits zero and one`() {
        for (role in NowhereProtocol.FlowRole.entries) {
            val header = NowhereProtocol.FlowHeader(
                role = role,
                flowId = 1,
                kind = NowhereProtocol.FlowKind.TCP,
                uplink = NowhereNetwork.TCP,
                downlink = NowhereNetwork.TCP
            )
            val flags = NowhereProtocol.encodeFlowHeader(header)[0].toInt() and 0xFF
            assertEquals(role.value, flags and 0x03)
            assertEquals(0, flags and 0xFC)
        }
    }

    @Test
    fun `kind sits in bit two and the two carriers in bits three and four`() {
        fun flagsOf(
            kind: NowhereProtocol.FlowKind,
            up: NowhereNetwork,
            down: NowhereNetwork
        ): Int = NowhereProtocol.encodeFlowHeader(
            NowhereProtocol.FlowHeader(NowhereProtocol.FlowRole.OPEN, 1, kind, up, down)
        )[0].toInt() and 0xFF

        assertEquals(
            0x01,
            flagsOf(NowhereProtocol.FlowKind.TCP, NowhereNetwork.TCP, NowhereNetwork.TCP)
        )
        assertEquals(
            0x01 or 0x04,
            flagsOf(NowhereProtocol.FlowKind.UDP, NowhereNetwork.TCP, NowhereNetwork.TCP)
        )
        assertEquals(
            0x01 or 0x08,
            flagsOf(NowhereProtocol.FlowKind.TCP, NowhereNetwork.UDP, NowhereNetwork.TCP)
        )
        assertEquals(
            0x01 or 0x10,
            flagsOf(NowhereProtocol.FlowKind.TCP, NowhereNetwork.TCP, NowhereNetwork.UDP)
        )
        assertEquals(
            0x01 or 0x04 or 0x08 or 0x10,
            flagsOf(NowhereProtocol.FlowKind.UDP, NowhereNetwork.UDP, NowhereNetwork.UDP)
        )
    }

    @Test
    fun `a header decodes back to the fields it was built from`() {
        // role OPEN, kind UDP, uplink UDP, downlink TCP, five hops.
        val flags = 0x01 or 0x04 or 0x08 or (5 shl 5)
        assertEquals(0xAD, flags)
        val header = NowhereProtocol.decodeFlowHeader(bytes(flags, 0x00, 0x00, 0x00, 0x09))!!

        assertEquals(NowhereProtocol.FlowRole.OPEN, header.role)
        assertEquals(NowhereProtocol.FlowKind.UDP, header.kind)
        assertEquals(NowhereNetwork.UDP, header.uplink)
        assertEquals(NowhereNetwork.TCP, header.downlink)
        assertEquals(5, header.hops)
        assertEquals(9L, header.flowId)
        assertArrayEquals(bytes(flags, 0x00, 0x00, 0x00, 0x09), NowhereProtocol.encodeFlowHeader(header))
    }

    @Test
    fun `a truncated or overlong header is refused rather than misread`() {
        assertNull(NowhereProtocol.decodeFlowHeader(ByteArray(0)))
        assertNull(NowhereProtocol.decodeFlowHeader(bytes(0x00, 0x00, 0x00, 0x01)))
        assertNull(NowhereProtocol.decodeFlowHeader(bytes(0x00, 0x00, 0x00, 0x00, 0x01, 0x00)))
    }

    @Test
    fun `a header naming role three, flow zero or a mismatched duplex is refused`() {
        // Role 3 is not assigned.
        assertNull(NowhereProtocol.decodeFlowHeader(bytes(0x03, 0x00, 0x00, 0x00, 0x01)))
        // Flow id zero never names a flow.
        assertNull(NowhereProtocol.decodeFlowHeader(bytes(0x00, 0x00, 0x00, 0x00, 0x00)))
        // Duplex with uplink UDP and downlink TCP describes something that
        // cannot exist, since duplex means one carrier both ways.
        assertNull(NowhereProtocol.decodeFlowHeader(bytes(0x08, 0x00, 0x00, 0x00, 0x01)))
        // The same flags with role OPEN are legitimate.
        assertNotNull(NowhereProtocol.decodeFlowHeader(bytes(0x09, 0x00, 0x00, 0x00, 0x01)))
    }

    @Test
    fun `encoding refuses the headers decoding refuses`() {
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeFlowHeader(duplexHeader(flowId = 0))
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeFlowHeader(
                NowhereProtocol.FlowHeader(
                    NowhereProtocol.FlowRole.DUPLEX, 1, NowhereProtocol.FlowKind.TCP,
                    NowhereNetwork.UDP, NowhereNetwork.TCP
                )
            )
        }
    }

    @Test
    fun `validate checks the header against the carrier it travelled on`() {
        val open = NowhereProtocol.FlowHeader(
            NowhereProtocol.FlowRole.OPEN, 7, NowhereProtocol.FlowKind.TCP,
            uplink = NowhereNetwork.UDP, downlink = NowhereNetwork.TCP
        )
        val attach = open.copy(role = NowhereProtocol.FlowRole.ATTACH)

        // An open belongs on the uplink carrier, an attach on the downlink.
        open.validate(NowhereNetwork.UDP)
        attach.validate(NowhereNetwork.TCP)
        assertThrows(NowhereError::class.java) { open.validate(NowhereNetwork.TCP) }
        assertThrows(NowhereError::class.java) { attach.validate(NowhereNetwork.UDP) }
    }

    // The portal hop counter.

    @Test
    fun `every legal hop count round trips through the top three bits`() {
        for (hops in 0..NowhereProtocol.MAX_PORTAL_HOPS) {
            val header = duplexHeader(flowId = 0x11223344, hops = hops)
            val encoded = NowhereProtocol.encodeFlowHeader(header)
            assertArrayEquals(
                bytes(hops shl 5, 0x11, 0x22, 0x33, 0x44),
                encoded
            )
            // The counter must not have leaked into any other field.
            val flags = encoded[0].toInt() and 0xFF
            assertEquals(0, flags and 0x1F)
            assertEquals(hops, flags ushr 5)

            val decoded = NowhereProtocol.decodeFlowHeader(encoded)!!
            assertEquals(hops, decoded.hops)
            assertEquals(0x11223344L, decoded.flowId)
            assertEquals(NowhereProtocol.FlowRole.DUPLEX, decoded.role)
        }
    }

    @Test
    fun `an eighth hop cannot be encoded at all`() {
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeFlowHeader(duplexHeader(hops = 8))
        }
        assertThrows(NowhereError::class.java) { duplexHeader(hops = 8).validate() }
    }

    @Test
    fun `three bits of hop counter cannot express more than the budget`() {
        // Nothing a peer can put in the flags byte decodes to an over-budget
        // header, which is why the field is exactly three bits wide.
        for (flags in 0..255) {
            val header = NowhereProtocol.decodeFlowHeader(
                bytes(flags, 0x00, 0x00, 0x00, 0x01)
            ) ?: continue
            assertTrue(header.hops <= NowhereProtocol.MAX_PORTAL_HOPS)
        }
    }

    @Test
    fun `forwarding raises the counter and stops at the budget`() {
        var header = duplexHeader(flowId = 42)
        for (expected in 1..NowhereProtocol.MAX_PORTAL_HOPS) {
            header = header.forwarded()
            assertEquals(expected, header.hops)
            // Nothing else about the flow changes as it crosses a portal.
            assertEquals(42L, header.flowId)
            assertEquals(NowhereProtocol.FlowRole.DUPLEX, header.role)
        }
        assertEquals(NowhereProtocol.MAX_PORTAL_HOPS, header.hops)
        assertThrows(NowhereError::class.java) { header.forwarded() }
    }

    @Test
    fun `a forwarded header stays decodable at every hop`() {
        var header = NowhereProtocol.FlowHeader(
            NowhereProtocol.FlowRole.ATTACH, 0x0A0B0C0D, NowhereProtocol.FlowKind.UDP,
            uplink = NowhereNetwork.TCP, downlink = NowhereNetwork.UDP
        )
        repeat(NowhereProtocol.MAX_PORTAL_HOPS) {
            header = header.forwarded()
            val round = NowhereProtocol.decodeFlowHeader(NowhereProtocol.encodeFlowHeader(header))
            assertEquals(header, round)
        }
    }

    // Flow requests.

    @Test
    fun `a flow request is the header, then the target, then early data`() {
        val header = NowhereProtocol.FlowHeader(
            NowhereProtocol.FlowRole.OPEN, 0x00000101, NowhereProtocol.FlowKind.TCP,
            uplink = NowhereNetwork.TCP, downlink = NowhereNetwork.TCP
        )
        val request = NowhereProtocol.encodeFlowRequest(
            header,
            NowhereProtocol.Target.of("192.0.2.1", 443),
            "hi".toByteArray(Charsets.US_ASCII)
        )

        assertArrayEquals(
            wire(
                0x01, 0x00, 0x00, 0x01, 0x01,
                0x01, 192, 0, 2, 1, 0x01, 0xBB,
                "hi"
            ),
            request
        )
        assertEquals(NowhereProtocol.FLOW_HEADER_SIZE + 7 + 2, request.size)
    }

    @Test
    fun `only an attach omits the target`() {
        val target = NowhereProtocol.Target.of("example.com", 80)
        val open = NowhereProtocol.FlowHeader(
            NowhereProtocol.FlowRole.OPEN, 1, NowhereProtocol.FlowKind.TCP,
            NowhereNetwork.TCP, NowhereNetwork.UDP
        )
        val attach = open.copy(role = NowhereProtocol.FlowRole.ATTACH)

        assertTrue(open.carriesTarget)
        assertTrue(duplexHeader().carriesTarget)
        assertFalse(attach.carriesTarget)

        assertEquals(
            NowhereProtocol.FLOW_HEADER_SIZE,
            NowhereProtocol.encodeFlowRequest(attach, null).size
        )
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeFlowRequest(attach, target)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeFlowRequest(open, null)
        }
    }

    // Targets.

    @Test
    fun `an IPv4 target is seven bytes of type, address and port`() {
        val target = NowhereProtocol.Target.of("127.0.0.1", 8080)
        assertTrue(target is NowhereProtocol.Target.Ipv4)
        assertEquals(7, target.encodedLength)
        assertArrayEquals(bytes(0x01, 127, 0, 0, 1, 0x1F, 0x90), target.encode())
    }

    @Test
    fun `an IPv6 target is nineteen bytes and brackets are stripped first`() {
        val plain = NowhereProtocol.Target.of("2001:db8::1", 443)
        val bracketed = NowhereProtocol.Target.of("[2001:db8::1]", 443)
        assertTrue(plain is NowhereProtocol.Target.Ipv6)
        assertEquals(19, plain.encodedLength)
        assertArrayEquals(
            bytes(
                0x04,
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
                0x01, 0xBB
            ),
            plain.encode()
        )
        assertArrayEquals(plain.encode(), bracketed.encode())
    }

    @Test
    fun `an IPv4-mapped literal keeps its sixteen byte form`() {
        // The address is written the way the wire defines it, not collapsed to
        // four bytes the way some resolvers would.
        val target = NowhereProtocol.Target.of("::ffff:192.0.2.128", 53)
        assertTrue(target is NowhereProtocol.Target.Ipv6)
        assertArrayEquals(
            bytes(
                0x04,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 0, 2, 128,
                0x00, 0x35
            ),
            target.encode()
        )
    }

    @Test
    fun `a domain target is a length-prefixed name and is four bytes longer than it`() {
        val target = NowhereProtocol.Target.of("Example.COM", 80)
        assertTrue(target is NowhereProtocol.Target.Domain)
        assertEquals("example.com", (target as NowhereProtocol.Target.Domain).host)
        assertEquals(4 + "example.com".length, target.encodedLength)
        assertArrayEquals(wire(0x03, 11, "example.com", 0x00, 0x50), target.encode())
    }

    @Test
    fun `a non-ASCII name goes out in its IDNA form`() {
        // Escaped rather than written literally so the expectation cannot be
        // changed by whatever encoding this file is read with.
        val unicodeHost = "M\u00dcNCHEN.example"
        val target = NowhereProtocol.Target.of(unicodeHost, 443)
        assertTrue(target is NowhereProtocol.Target.Domain)
        val host = (target as NowhereProtocol.Target.Domain).host
        assertTrue(host.all { it.code < 0x80 })
        assertEquals(host, host.lowercase())
        assertEquals(IDN.toASCII(unicodeHost, IDN.ALLOW_UNASSIGNED).lowercase(), host)
        assertTrue(host.startsWith("xn--"))
        // And it is the punycode name, not the UTF-8 one, that goes on the wire.
        assertArrayEquals(wire(0x03, host.length, host, 0x01, 0xBB), target.encode())
    }

    @Test
    fun `a name of exactly the maximum length is accepted and one more is not`() {
        val label63 = "a".repeat(63)
        val longest = "$label63.$label63.$label63.${"a".repeat(61)}"
        assertEquals(NowhereProtocol.MAX_DOMAIN_LENGTH, longest.length)
        assertEquals(
            NowhereProtocol.MAX_DOMAIN_LENGTH,
            (NowhereProtocol.Target.of(longest, 443) as NowhereProtocol.Target.Domain).host.length
        )

        val tooLong = "$label63.$label63.$label63.${"a".repeat(62)}"
        assertEquals(NowhereProtocol.MAX_DOMAIN_LENGTH + 1, tooLong.length)
        assertThrows(NowhereError::class.java) { NowhereProtocol.Target.of(tooLong, 443) }
    }

    @Test
    fun `the DNS label rules are enforced`() {
        val rejected = listOf(
            "",                 // no host at all
            ".",                // an empty label
            "example..com",     // a doubled separator
            "example.com.",     // a trailing dot, which names the same host twice
            "-example.com",     // a label may not begin with a hyphen
            "example-.com",     // nor end with one
            "exa_mple.com",     // underscore is not a host character
            "a".repeat(64)      // a label may not exceed 63 bytes
        )
        for (host in rejected) {
            assertThrows("expected $host to be refused", NowhereError::class.java) {
                NowhereProtocol.Target.of(host, 443)
            }
        }
        // A hyphen inside a label is fine, and so is a 63-byte one.
        assertNotNull(NowhereProtocol.Target.of("my-host.example", 443))
        assertNotNull(NowhereProtocol.Target.of("a".repeat(63), 443))
    }

    @Test
    fun `port zero is not a destination`() {
        assertThrows(NowhereError::class.java) { NowhereProtocol.Target.of("example.com", 0) }
        assertThrows(NowhereError::class.java) { NowhereProtocol.Target.of("127.0.0.1", 0) }
    }

    @Test
    fun `a dotted quad with a leading zero is not an IPv4 literal`() {
        // The strictness matters: some resolvers read a leading zero as octal,
        // so an address two pieces of software disagree about must not become
        // an address at all. It falls through to the name path instead.
        val target = NowhereProtocol.Target.of("010.0.0.1", 443)
        assertTrue(target is NowhereProtocol.Target.Domain)
        assertEquals("010.0.0.1", (target as NowhereProtocol.Target.Domain).host)
    }

    @Test
    fun `a target decodes from the bytes the encoder writes`() {
        val ipv4 = NowhereProtocol.decodeTarget(bytes(0x01, 10, 0, 0, 7, 0x00, 0x35))!!
        assertEquals(7, ipv4.consumed)
        assertEquals(NowhereProtocol.Target.of("10.0.0.7", 53), ipv4.target)

        val ipv6Bytes = bytes(
            0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0xBB
        )
        val ipv6 = NowhereProtocol.decodeTarget(ipv6Bytes)!!
        assertEquals(19, ipv6.consumed)
        assertEquals(NowhereProtocol.Target.of("2001:db8::1", 443), ipv6.target)

        val domain = NowhereProtocol.decodeTarget(wire(0x03, 11, "example.com", 0x00, 0x50))!!
        assertEquals(15, domain.consumed)
        assertEquals(NowhereProtocol.Target.of("example.com", 80), domain.target)
    }

    @Test
    fun `a truncated or unknown target is refused rather than misparsed`() {
        assertNull(NowhereProtocol.decodeTarget(ByteArray(0)))
        assertNull(NowhereProtocol.decodeTarget(bytes(0x01, 10, 0, 0, 7, 0x00)))
        assertNull(NowhereProtocol.decodeTarget(bytes(0x04, 0, 0, 0, 0)))
        assertNull(NowhereProtocol.decodeTarget(wire(0x03, 11, "example.co", 0x00, 0x50)))
        // Address type 2 is not assigned.
        assertNull(NowhereProtocol.decodeTarget(bytes(0x02, 10, 0, 0, 7, 0x00, 0x35)))
        // A zero port is no more a destination on the way in than on the way out.
        assertNull(NowhereProtocol.decodeTarget(bytes(0x01, 10, 0, 0, 7, 0x00, 0x00)))
        // A name that the encoder would have refused is refused here too.
        assertNull(NowhereProtocol.decodeTarget(wire(0x03, 12, "example..com", 0x00, 0x50)))
    }

    // Flow results.

    @Test
    fun `a flow result is one byte, zero meaning ready`() {
        assertArrayEquals(bytes(0), NowhereProtocol.encodeFlowResult(NowhereProtocol.FlowResult.Ready))
        assertEquals(
            NowhereProtocol.FLOW_RESULT_SIZE,
            NowhereProtocol.encodeFlowResult(NowhereProtocol.FlowResult.Ready).size
        )
        assertSame(NowhereProtocol.FlowResult.Ready, NowhereProtocol.decodeFlowResult(bytes(0)))

        for (code in NowhereProtocol.FlowRejectCode.entries) {
            val encoded = NowhereProtocol.encodeFlowResult(NowhereProtocol.FlowResult.Reject(code))
            assertArrayEquals(bytes(code.value), encoded)
            assertEquals(
                NowhereProtocol.FlowResult.Reject(code),
                NowhereProtocol.decodeFlowResult(encoded)
            )
        }
    }

    @Test
    fun `an unknown or absent result byte is refused`() {
        assertNull(NowhereProtocol.decodeFlowResult(ByteArray(0)))
        assertNull(NowhereProtocol.decodeFlowResult(bytes(8)))
        assertNull(NowhereProtocol.decodeFlowResult(bytes(0xFF)))
        assertNull(NowhereProtocol.decodeFlowResult(bytes(0), offset = 1))
        assertNull(NowhereProtocol.decodeFlowResult(bytes(0), offset = -1))
    }

    @Test
    fun `a result can be read from part-way into a buffer`() {
        val buffer = bytes(0xAA, 0xBB, 5)
        assertEquals(
            NowhereProtocol.FlowResult.Reject(NowhereProtocol.FlowRejectCode.DIAL_FAILED),
            NowhereProtocol.decodeFlowResult(buffer, offset = 2)
        )
    }

    // Authentication.

    @Test
    fun `the auth key is an HKDF of the shared secret, salted with the version label`() {
        val secret = "correct horse battery staple"
        // Recomputed here from the format's description rather than taken from
        // the implementation: extract with the hash of the root label as salt,
        // expand with the info string and HKDF's first counter byte.
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(NowhereProtocol.AUTH_ROOT_LABEL.toByteArray(Charsets.UTF_8))
        val authRoot = hmac(salt, secret.toByteArray(Charsets.UTF_8))
        val expected = hmac(
            authRoot,
            NowhereProtocol.AUTH_INFO_LABEL.toByteArray(Charsets.UTF_8) + byteArrayOf(0x01)
        )

        val derived = NowhereProtocol.deriveAuthKey(secret)
        assertEquals(NowhereProtocol.AUTH_KEY_SIZE, derived.size)
        assertArrayEquals(expected, derived)
    }

    @Test
    fun `a missing or oversized shared secret is refused`() {
        assertThrows(NowhereError::class.java) { NowhereProtocol.deriveAuthKey("") }
        assertThrows(NowhereError::class.java) { NowhereProtocol.deriveAuthKey("k".repeat(256)) }
        assertNotNull(NowhereProtocol.deriveAuthKey("k".repeat(255)))
    }

    @Test
    fun `an auth frame is the session id then half a tag over transport, exporter and session`() {
        val authKey = ByteArray(32) { it.toByte() }
        val exporter = ByteArray(32) { (0x40 + it).toByte() }
        val sessionId = ByteArray(16) { (0xF0 - it).toByte() }

        val frame = NowhereProtocol.makeAuthFrame(
            authKey, NowhereProtocol.AuthTransport.QUIC, exporter, sessionId
        )
        assertEquals(NowhereProtocol.AUTH_FRAME_SIZE, frame.size)
        assertArrayEquals(sessionId, frame.copyOfRange(0, 16))

        val signed = byteArrayOf(NowhereProtocol.AuthTransport.QUIC.value.toByte()) +
            exporter + sessionId
        assertEquals(49, signed.size)
        assertArrayEquals(hmac(authKey, signed).copyOfRange(0, 16), frame.copyOfRange(16, 32))
    }

    @Test
    fun `the carrier is bound into the tag, so a frame cannot move between them`() {
        val authKey = ByteArray(32) { it.toByte() }
        val exporter = ByteArray(32) { (it * 7).toByte() }
        val sessionId = ByteArray(16) { it.toByte() }

        val tls = NowhereProtocol.makeAuthFrame(
            authKey, NowhereProtocol.AuthTransport.TLS_TCP, exporter, sessionId
        )
        val quic = NowhereProtocol.makeAuthFrame(
            authKey, NowhereProtocol.AuthTransport.QUIC, exporter, sessionId
        )
        assertArrayEquals(tls.copyOfRange(0, 16), quic.copyOfRange(0, 16))
        assertFalse(tls.copyOfRange(16, 32).contentEquals(quic.copyOfRange(16, 32)))
    }

    @Test
    fun `authentication material of the wrong size is refused`() {
        val key = ByteArray(32)
        val exporter = ByteArray(32)
        val session = ByteArray(16)
        val transport = NowhereProtocol.AuthTransport.TLS_TCP

        assertThrows(NowhereError::class.java) {
            NowhereProtocol.makeAuthFrame(ByteArray(31), transport, exporter, session)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.makeAuthFrame(key, transport, ByteArray(16), session)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.makeAuthFrame(key, transport, exporter, ByteArray(8))
        }
    }

    // Datagram envelopes.

    @Test
    fun `a datagram begins with a type byte and a big-endian flow id`() {
        val envelope = NowhereProtocol.decodeUdpEnvelope(bytes(0x00, 0xDE, 0xAD, 0xBE, 0xEF))!!
        assertEquals(NowhereProtocol.UdpType.DATA, envelope.type)
        assertEquals(0xDEADBEEFL, envelope.flowId)
    }

    @Test
    fun `the bits above the type are reserved and must be clear`() {
        // Only 0x00, 0x01 and 0x02 name a type; every other first byte is a
        // frame this version does not understand and must not guess at.
        for (flags in 0..255) {
            val decoded = NowhereProtocol.decodeUdpEnvelope(bytes(flags, 0, 0, 0, 1))
            if (flags in 0..2) assertNotNull("flags $flags", decoded)
            else assertNull("flags $flags", decoded)
        }
    }

    @Test
    fun `a short datagram or a zero flow id is refused`() {
        assertNull(NowhereProtocol.decodeUdpEnvelope(bytes(0x00, 0x00, 0x00, 0x01)))
        assertNull(NowhereProtocol.decodeUdpEnvelope(bytes(0x00, 0x00, 0x00, 0x00, 0x00)))
        assertNull(NowhereProtocol.decodeUdpDatagram(bytes(0x02, 0x00, 0x00, 0x00, 0x00)))
    }

    @Test
    fun `a close frame is exactly the five byte header`() {
        val frame = NowhereProtocol.encodeUdpControl(NowhereProtocol.UdpType.CLOSE, 0x01020304)
        assertEquals(NowhereProtocol.UDP_HEADER_SIZE, frame.size)
        assertArrayEquals(bytes(0x02, 0x01, 0x02, 0x03, 0x04), frame)

        val message = NowhereProtocol.decodeUdpDatagram(frame)!!
        assertEquals(NowhereProtocol.UdpType.CLOSE, message.type)
        assertEquals(0x01020304L, message.flowId)
        assertEquals(0, message.payload.size)
        assertEquals(0, message.totalLength)

        // A close carrying anything is not a close.
        assertNull(NowhereProtocol.decodeUdpDatagram(bytes(0x02, 0x01, 0x02, 0x03, 0x04, 0x00)))
    }

    @Test
    fun `only a close may be built as a control frame`() {
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpControl(NowhereProtocol.UdpType.DATA, 1)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpControl(NowhereProtocol.UdpType.FRAGMENT, 1)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpControl(NowhereProtocol.UdpType.CLOSE, 0)
        }
    }

    // Unfragmented data.

    @Test
    fun `a packet that fits goes as one data frame with a five byte header`() {
        val payload = "hello".toByteArray(Charsets.US_ASCII)
        val frames = NowhereProtocol.encodeUdpDataFragments(
            flowId = 0x00000102, packetId = 9, payload = payload, maxDatagramSize = 1200
        )
        assertEquals(1, frames.size)
        assertArrayEquals(wire(0x00, 0x00, 0x00, 0x01, 0x02, "hello"), frames[0])

        val message = NowhereProtocol.decodeUdpDatagram(frames[0])!!
        assertEquals(NowhereProtocol.UdpType.DATA, message.type)
        assertEquals(0x102L, message.flowId)
        assertEquals(0, message.fragmentCount)
        assertEquals(payload.size, message.totalLength)
        assertArrayEquals(payload, message.payload)
    }

    @Test
    fun `the unfragmented limit is the datagram size less the five byte header`() {
        val exact = ByteArray(1200 - NowhereProtocol.UDP_HEADER_SIZE) { 0x41.toByte() }
        val single = NowhereProtocol.encodeUdpDataFragments(1, 1, exact, 1200)
        assertEquals(1, single.size)
        assertEquals(1200, single[0].size)
        assertEquals(NowhereProtocol.UdpType.DATA.value, single[0][0].toInt())

        // One byte more and the larger fragment header has to appear, which is
        // why a packet just past the limit becomes two pieces and never one.
        val over = ByteArray(exact.size + 1) { 0x41.toByte() }
        val split = NowhereProtocol.encodeUdpDataFragments(1, 1, over, 1200)
        assertEquals(2, split.size)
        assertEquals(NowhereProtocol.UdpType.FRAGMENT.value, split[0][0].toInt())
    }

    // Fragmentation.

    @Test
    fun `a fragment header is thirteen bytes in the order the format names`() {
        val payload = ByteArray(96) { it.toByte() }
        val frames = NowhereProtocol.encodeUdpDataFragments(
            flowId = 0xAABBCCDDL, packetId = 0x00010203, payload = payload, maxDatagramSize = 100
        )
        // capacity = 100 - 13 = 87, so 96 bytes becomes 87 and 9.
        assertEquals(2, frames.size)
        assertEquals(100, frames[0].size)
        assertEquals(NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 9, frames[1].size)

        val first = frames[0]
        assertEquals(NowhereProtocol.UdpType.FRAGMENT.value, first[0].toInt())
        assertArrayEquals(bytes(0xAA, 0xBB, 0xCC, 0xDD), first.copyOfRange(1, 5))
        assertArrayEquals(bytes(0x00, 0x01, 0x02, 0x03), first.copyOfRange(5, 9))
        assertEquals(0, first[9].toInt())
        assertEquals(2, first[10].toInt())
        assertArrayEquals(bytes(0x00, 0x60), first.copyOfRange(11, 13))
        assertArrayEquals(payload.copyOfRange(0, 87), first.copyOfRange(13, 100))

        val second = frames[1]
        assertEquals(1, second[9].toInt())
        assertEquals(2, second[10].toInt())
        assertArrayEquals(bytes(0x00, 0x60), second.copyOfRange(11, 13))
        assertArrayEquals(payload.copyOfRange(87, 96), second.copyOfRange(13, second.size))
    }

    @Test
    fun `every fragment names the same packet, count and total length`() {
        val payload = ByteArray(1000) { (it * 3).toByte() }
        val frames = NowhereProtocol.encodeUdpDataFragments(77, 0x1234, payload, 100)
        // capacity 87, so ceil(1000 / 87) = 12 pieces, the last of 43 bytes.
        assertEquals(12, frames.size)
        assertEquals(NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 43, frames.last().size)

        frames.forEachIndexed { index, frame ->
            val message = NowhereProtocol.decodeUdpDatagram(frame)!!
            assertEquals(NowhereProtocol.UdpType.FRAGMENT, message.type)
            assertEquals(77L, message.flowId)
            assertEquals(0x1234L, message.packetId)
            assertEquals(index, message.fragmentId)
            assertEquals(12, message.fragmentCount)
            assertEquals(1000, message.totalLength)
            assertTrue(frame.size <= 100)
        }
        assertEquals(1000, frames.sumOf { it.size - NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE })
    }

    @Test
    fun `fragmenting needs a packet id and a datagram larger than its header`() {
        val payload = ByteArray(500)
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(1, packetId = 0, payload = payload, maxDatagramSize = 100)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, payload, NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE
            )
        }
        // One byte of room for payload is enough to be legal, if wasteful:
        // twenty bytes become twenty datagrams of fourteen.
        val single = NowhereProtocol.encodeUdpDataFragments(
            1, 1, ByteArray(20), NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 1
        )
        assertEquals(20, single.size)
        assertTrue(single.all { it.size == NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 1 })
    }

    @Test
    fun `a flow id of zero and an oversized packet are both refused`() {
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(0, 1, ByteArray(4), 1200)
        }
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, ByteArray(NowhereProtocol.MAX_UDP_PACKET_SIZE + 1), 1200
            )
        }
        assertNotNull(
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, ByteArray(NowhereProtocol.MAX_UDP_PACKET_SIZE), 1200
            )
        )
    }

    @Test
    fun `a datagram budget too small for even the plain header is refused`() {
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, ByteArray(0), NowhereProtocol.UDP_HEADER_SIZE - 1
            )
        }
    }

    @Test
    fun `a packet needing more than 255 pieces cannot be sent`() {
        // One byte of payload per datagram, so 300 bytes wants 300 pieces and
        // the one-byte fragment index has nowhere to put them.
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, ByteArray(300), NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 1
            )
        }
        assertEquals(
            255,
            NowhereProtocol.encodeUdpDataFragments(
                1, 1, ByteArray(255), NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 1
            ).size
        )
    }

    @Test
    fun `a fragment decodes from literal bytes at the offsets the format names`() {
        val frame = wire(
            0x01,                    // type FRAGMENT
            0x00, 0x00, 0x00, 0x2A,  // flow 42
            0x00, 0x00, 0x03, 0xE8,  // packet 1000
            0x02,                    // index 2
            0x04,                    // of 4
            0x00, 0x14,              // whole packet is 20 bytes
            "abcde"
        )
        assertEquals(NowhereProtocol.UDP_FRAGMENT_HEADER_SIZE + 5, frame.size)

        val message = NowhereProtocol.decodeUdpDatagram(frame)!!
        assertEquals(NowhereProtocol.UdpType.FRAGMENT, message.type)
        assertEquals(42L, message.flowId)
        assertEquals(1000L, message.packetId)
        assertEquals(2, message.fragmentId)
        assertEquals(4, message.fragmentCount)
        assertEquals(20, message.totalLength)
        assertArrayEquals("abcde".toByteArray(Charsets.US_ASCII), message.payload)
    }

    @Test
    fun `a fragment that could never complete is refused at decode`() {
        fun fragment(
            packetId: Int = 1,
            index: Int = 0,
            count: Int = 2,
            total: Int = 20,
            payloadSize: Int = 5
        ) = wire(
            0x01, 0x00, 0x00, 0x00, 0x2A,
            (packetId ushr 24) and 0xFF, (packetId ushr 16) and 0xFF,
            (packetId ushr 8) and 0xFF, packetId and 0xFF,
            index, count, (total ushr 8) and 0xFF, total and 0xFF,
            ByteArray(payloadSize)
        )

        assertNotNull(NowhereProtocol.decodeUdpDatagram(fragment()))
        // A zero packet id cannot be keyed on.
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(packetId = 0)))
        // Fewer than two pieces is not a fragmented packet.
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(count = 1, index = 0)))
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(count = 0, index = 0)))
        // An index at or past the count names a piece that cannot exist.
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(index = 2, count = 2)))
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(index = 200, count = 2)))
        // A packet of zero length, or shorter than it has pieces.
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(total = 0)))
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(count = 30, total = 20)))
        // An empty payload is a reassembly slot for free.
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(payloadSize = 0)))
        // This piece plus one byte for each sibling must still fit the total.
        assertNotNull(NowhereProtocol.decodeUdpDatagram(fragment(count = 4, total = 20, payloadSize = 17)))
        assertNull(NowhereProtocol.decodeUdpDatagram(fragment(count = 4, total = 20, payloadSize = 18)))
    }

    // Fragment reassembly.

    private fun fragmentsOf(
        payload: ByteArray,
        flowId: Long = 1,
        packetId: Long = 7,
        maxDatagramSize: Int = 100
    ): List<NowhereProtocol.UdpMessage> =
        NowhereProtocol.encodeUdpDataFragments(flowId, packetId, payload, maxDatagramSize)
            .map { NowhereProtocol.decodeUdpDatagram(it)!! }

    @Test
    fun `fragments arriving in order rebuild the packet exactly once`() {
        val payload = ByteArray(1000) { (it * 5).toByte() }
        val pieces = fragmentsOf(payload)
        val reassembler = NowhereFragmentReassembler()

        for (piece in pieces.dropLast(1)) {
            assertNull(reassembler.accept(piece))
        }
        assertEquals(1, reassembler.size)
        assertArrayEquals(payload, reassembler.accept(pieces.last()))
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `fragments arriving in reverse order rebuild the same packet`() {
        val payload = ByteArray(1000) { (it * 5).toByte() }
        val pieces = fragmentsOf(payload).reversed()
        val reassembler = NowhereFragmentReassembler()

        for (piece in pieces.dropLast(1)) {
            assertNull(reassembler.accept(piece))
        }
        assertArrayEquals(payload, reassembler.accept(pieces.last()))
    }

    @Test
    fun `every arrival order rebuilds the same packet`() {
        val payload = ByteArray(400) { (it xor 0x5A).toByte() }
        val pieces = fragmentsOf(payload, maxDatagramSize = 113)
        assertEquals(4, pieces.size)

        // All 24 permutations of four pieces, so no ordering is special.
        fun permutations(items: List<NowhereProtocol.UdpMessage>): List<List<NowhereProtocol.UdpMessage>> =
            if (items.size <= 1) listOf(items)
            else items.flatMapIndexed { index, item ->
                permutations(items.filterIndexed { at, _ -> at != index }).map { listOf(item) + it }
            }

        val orders = permutations(pieces)
        assertEquals(24, orders.size)
        for (order in orders) {
            val reassembler = NowhereFragmentReassembler()
            val results = order.map { reassembler.accept(it) }
            assertEquals(3, results.count { it == null })
            assertArrayEquals(payload, results.last())
            assertEquals(0, reassembler.size)
        }
    }

    @Test
    fun `two packets on one flow reassemble independently`() {
        val first = ByteArray(300) { 0x11.toByte() }
        val second = ByteArray(300) { 0x22.toByte() }
        val firstPieces = fragmentsOf(first, packetId = 1)
        val secondPieces = fragmentsOf(second, packetId = 2)
        val reassembler = NowhereFragmentReassembler()

        // Interleaved, which is what a reordering path actually delivers.
        assertNull(reassembler.accept(firstPieces[0]))
        assertNull(reassembler.accept(secondPieces[0]))
        assertEquals(2, reassembler.size)
        assertNull(reassembler.accept(secondPieces[1]))
        assertNull(reassembler.accept(firstPieces[1]))

        var firstOut: ByteArray? = null
        var secondOut: ByteArray? = null
        for (piece in firstPieces.drop(2)) firstOut = reassembler.accept(piece)
        for (piece in secondPieces.drop(2)) secondOut = reassembler.accept(piece)

        assertArrayEquals(first, firstOut)
        assertArrayEquals(second, secondOut)
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `the same packet id on two flows does not collide`() {
        val payload = ByteArray(150) { it.toByte() }
        val onOne = fragmentsOf(payload, flowId = 1, packetId = 5)
        val onTwo = fragmentsOf(payload, flowId = 2, packetId = 5)
        assertEquals(2, onOne.size)
        val reassembler = NowhereFragmentReassembler()

        assertNull(reassembler.accept(onOne[0]))
        assertNull(reassembler.accept(onTwo[0]))
        assertEquals(2, reassembler.size)
        assertArrayEquals(payload, reassembler.accept(onOne[1]))
        assertArrayEquals(payload, reassembler.accept(onTwo[1]))
    }

    @Test
    fun `a repeated fragment is ignored if identical and fatal if not`() {
        val payload = ByteArray(300) { it.toByte() }
        val pieces = fragmentsOf(payload)

        val tolerant = NowhereFragmentReassembler()
        assertNull(tolerant.accept(pieces[0]))
        assertNull(tolerant.accept(pieces[0]))
        assertEquals(1, tolerant.size)
        var out: ByteArray? = null
        for (piece in pieces.drop(1)) out = tolerant.accept(piece)
        assertArrayEquals(payload, out)

        // The same index with different bytes is an attempt to rewrite a
        // packet mid-assembly, so the whole slot goes.
        val strict = NowhereFragmentReassembler()
        assertNull(strict.accept(pieces[0]))
        val forged = NowhereProtocol.UdpMessage(
            type = pieces[0].type,
            flowId = pieces[0].flowId,
            packetId = pieces[0].packetId,
            fragmentId = pieces[0].fragmentId,
            fragmentCount = pieces[0].fragmentCount,
            totalLength = pieces[0].totalLength,
            payload = ByteArray(pieces[0].payload.size) { 0x7F.toByte() }
        )
        assertNull(strict.accept(forged))
        assertEquals(0, strict.size)
        // The remaining fragments open a fresh slot that can never complete,
        // because index zero is gone.
        for (piece in pieces.drop(1)) assertNull(strict.accept(piece))
    }

    @Test
    fun `a fragment contradicting the packet's shape drops the slot`() {
        val payload = ByteArray(300) { it.toByte() }
        val pieces = fragmentsOf(payload)

        for (mutated in listOf(
            { p: NowhereProtocol.UdpMessage ->
                NowhereProtocol.UdpMessage(
                    p.type, p.flowId, p.packetId, p.fragmentId,
                    p.fragmentCount + 1, p.totalLength, p.payload
                )
            },
            { p: NowhereProtocol.UdpMessage ->
                NowhereProtocol.UdpMessage(
                    p.type, p.flowId, p.packetId, p.fragmentId,
                    p.fragmentCount, p.totalLength + 1, p.payload
                )
            }
        )) {
            val reassembler = NowhereFragmentReassembler()
            assertNull(reassembler.accept(pieces[0]))
            assertNull(reassembler.accept(mutated(pieces[1])))
            assertEquals(0, reassembler.size)
        }
    }

    @Test
    fun `pieces that would overrun the announced length drop the slot`() {
        fun piece(index: Int, size: Int) = NowhereProtocol.UdpMessage(
            NowhereProtocol.UdpType.FRAGMENT, flowId = 1, packetId = 1,
            fragmentId = index, fragmentCount = 2, totalLength = 10,
            payload = ByteArray(size) { index.toByte() }
        )

        val reassembler = NowhereFragmentReassembler()
        assertNull(reassembler.accept(piece(0, 6)))
        assertNull(reassembler.accept(piece(1, 6)))
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `pieces that fall short of the announced length are discarded`() {
        fun piece(index: Int, size: Int) = NowhereProtocol.UdpMessage(
            NowhereProtocol.UdpType.FRAGMENT, flowId = 1, packetId = 1,
            fragmentId = index, fragmentCount = 2, totalLength = 10,
            payload = ByteArray(size) { index.toByte() }
        )

        val reassembler = NowhereFragmentReassembler()
        assertNull(reassembler.accept(piece(0, 3)))
        // Every index has arrived, but the bytes do not add up to the packet
        // the sender described, so there is nothing safe to deliver.
        assertNull(reassembler.accept(piece(1, 3)))
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `an incomplete packet is dropped once its time to live passes`() {
        var now = 0L
        val reassembler = NowhereFragmentReassembler(ttlNanos = 1_000L, clock = { now })
        val payload = ByteArray(300) { it.toByte() }
        val pieces = fragmentsOf(payload)
        assertEquals(4, pieces.size)

        assertNull(reassembler.accept(pieces[0]))
        assertEquals(1, reassembler.size)

        // Exactly at the deadline is still inside the window, so both pieces
        // remain in the one slot.
        now = 1_000L
        assertNull(reassembler.accept(pieces[1]))
        assertEquals(1, reassembler.size)

        // Past it, and the slot goes; this piece opens a fresh one.
        now = 2_001L
        assertNull(reassembler.accept(pieces[2]))
        assertEquals(1, reassembler.size)

        // The first two pieces went with the expired slot, so the packet can
        // no longer complete however many of the rest arrive.
        assertNull(reassembler.accept(pieces[3]))
        assertEquals(1, reassembler.size)
    }

    @Test
    fun `no more than the configured number of packets are held at once`() {
        val reassembler = NowhereFragmentReassembler(maxSlots = 2)
        val payload = ByteArray(300) { it.toByte() }

        assertNull(reassembler.accept(fragmentsOf(payload, packetId = 1)[0]))
        assertNull(reassembler.accept(fragmentsOf(payload, packetId = 2)[0]))
        assertEquals(2, reassembler.size)
        assertNull(reassembler.accept(fragmentsOf(payload, packetId = 3)[0]))
        assertEquals(2, reassembler.size)
    }

    @Test
    fun `closing a flow forgets what was being assembled for it`() {
        val payload = ByteArray(300) { it.toByte() }
        val reassembler = NowhereFragmentReassembler()

        assertNull(reassembler.accept(fragmentsOf(payload, flowId = 1, packetId = 1)[0]))
        assertNull(reassembler.accept(fragmentsOf(payload, flowId = 1, packetId = 2)[0]))
        assertNull(reassembler.accept(fragmentsOf(payload, flowId = 2, packetId = 1)[0]))
        assertEquals(3, reassembler.size)

        reassembler.forget(1)
        assertEquals(1, reassembler.size)
        reassembler.clear()
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `the reassembler refuses anything that is not a fragment`() {
        val reassembler = NowhereFragmentReassembler()
        val data = NowhereProtocol.decodeUdpDatagram(
            NowhereProtocol.encodeUdpDataFragments(1, 1, ByteArray(4), 1200)[0]
        )!!
        assertNull(reassembler.accept(data))
        assertEquals(0, reassembler.size)
    }

    @Test
    fun `a maximum sized packet survives being cut up and put back together`() {
        val payload = ByteArray(NowhereProtocol.MAX_UDP_PACKET_SIZE) { (it * 31).toByte() }
        // 65535 bytes into 1187-byte pieces is 56, comfortably inside the
        // 255 a one-byte index allows.
        val pieces = fragmentsOf(payload, maxDatagramSize = 1200)
        assertEquals(56, pieces.size)

        val reassembler = NowhereFragmentReassembler()
        var out: ByteArray? = null
        for (piece in pieces.shuffled(java.util.Random(20260530L))) out = reassembler.accept(piece)
        assertArrayEquals(payload, out)
    }

    // UDP carried over a stream.

    @Test
    fun `a stream packet is a sixteen bit length and then the bytes`() {
        val encoded = NowhereProtocol.encodeUdpStreamPacket("hello".toByteArray(Charsets.US_ASCII))
        assertArrayEquals(wire(0x00, 0x05, "hello"), encoded)

        val decoded = NowhereProtocol.decodeUdpStreamPacket(encoded)!!
        assertEquals(7, decoded.consumed)
        assertArrayEquals("hello".toByteArray(Charsets.US_ASCII), decoded.payload)
    }

    @Test
    fun `back to back stream packets are separated by their announced lengths`() {
        val first = NowhereProtocol.encodeUdpStreamPacket(bytes(1, 2, 3))
        val second = NowhereProtocol.encodeUdpStreamPacket(bytes(4, 5))
        val buffer = first + second

        val one = NowhereProtocol.decodeUdpStreamPacket(buffer)!!
        assertArrayEquals(bytes(1, 2, 3), one.payload)
        val two = NowhereProtocol.decodeUdpStreamPacket(buffer, one.consumed)!!
        assertArrayEquals(bytes(4, 5), two.payload)
        assertEquals(buffer.size, one.consumed + two.consumed)
        assertNull(NowhereProtocol.decodeUdpStreamPacket(buffer, one.consumed + two.consumed))
    }

    @Test
    fun `a stream packet still short of its length is not delivered early`() {
        assertNull(NowhereProtocol.decodeUdpStreamPacket(bytes(0x00)))
        assertNull(NowhereProtocol.decodeUdpStreamPacket(bytes(0x00, 0x05, 0x61, 0x62)))
        assertNull(NowhereProtocol.decodeUdpStreamPacket(bytes(0x00, 0x05, 0x61), offset = -1))
        // An empty packet is legal and consumes just its length prefix.
        val empty = NowhereProtocol.decodeUdpStreamPacket(bytes(0x00, 0x00))!!
        assertEquals(2, empty.consumed)
        assertEquals(0, empty.payload.size)
    }

    @Test
    fun `a stream packet larger than the length field can describe is refused`() {
        assertEquals(
            2 + NowhereProtocol.MAX_UDP_PACKET_SIZE,
            NowhereProtocol.encodeUdpStreamPacket(
                ByteArray(NowhereProtocol.MAX_UDP_PACKET_SIZE)
            ).size
        )
        assertThrows(NowhereError::class.java) {
            NowhereProtocol.encodeUdpStreamPacket(ByteArray(NowhereProtocol.MAX_UDP_PACKET_SIZE + 1))
        }
    }

    // Configuration.

    private fun configuration(
        key: String = "shared",
        uplink: NowhereNetwork = NowhereNetwork.TCP,
        downlink: NowhereNetwork = NowhereNetwork.TCP,
        multiplex: Boolean = true,
        sessionId: ByteArray = ByteArray(16) { it.toByte() },
        tls: TlsConfiguration = TlsConfiguration(serverName = "portal.example")
    ) = NowhereConfiguration(
        proxyHost = "portal.example",
        proxyPort = 443,
        key = key,
        uplink = uplink,
        downlink = downlink,
        requestedMultiplex = multiplex,
        sessionId = sessionId,
        tls = tls
    )

    @Test
    fun `a configuration without a named ALPN uses the protocol's own`() {
        val config = configuration()
        assertEquals(NowhereProtocol.DEFAULT_ALPN, config.alpn)
        assertEquals("now/1", config.alpn)
        assertTrue(config.acceptsNegotiatedAlpn("now/1"))
        assertFalse(config.acceptsNegotiatedAlpn("h3"))
        assertFalse(config.acceptsNegotiatedAlpn(""))
    }

    @Test
    fun `a named ALPN wins and is the only one the stream carrier offers`() {
        val config = configuration(
            tls = TlsConfiguration(serverName = "portal.example", alpn = listOf("h2", "http/1.1"))
        )
        assertEquals("h2", config.alpn)
        assertEquals(listOf("h2"), config.tcpTlsConfiguration.alpn)
        // The auth frame is bound to a TLS exporter, which only TLS 1.3 defines
        // the way this protocol needs.
        assertEquals(TlsVersion.TLS13, config.tcpTlsConfiguration.minVersion)
        assertEquals(TlsVersion.TLS13, config.tcpTlsConfiguration.maxVersion)
        assertEquals("portal.example", config.tcpTlsConfiguration.serverName)
    }

    @Test
    fun `multiplexing is dropped when neither direction is a stream`() {
        assertTrue(configuration(uplink = NowhereNetwork.TCP, downlink = NowhereNetwork.TCP).multiplex)
        assertTrue(configuration(uplink = NowhereNetwork.TCP, downlink = NowhereNetwork.UDP).multiplex)
        assertTrue(configuration(uplink = NowhereNetwork.UDP, downlink = NowhereNetwork.TCP).multiplex)
        // Nothing to multiplex onto: both carriers are datagrams.
        assertFalse(configuration(uplink = NowhereNetwork.UDP, downlink = NowhereNetwork.UDP).multiplex)
        // And asking for none never turns into some.
        assertFalse(configuration(multiplex = false).multiplex)
    }

    @Test
    fun `the configuration derives the auth key once, from the shared secret`() {
        assertArrayEquals(NowhereProtocol.deriveAuthKey("shared"), configuration().authKey)
        assertEquals(NowhereProtocol.AUTH_KEY_SIZE, configuration().authKey.size)
        assertThrows(NowhereError::class.java) { configuration(key = "") }
    }

    @Test
    fun `a session id that is not sixteen bytes is refused`() {
        assertThrows(NowhereError::class.java) { configuration(sessionId = ByteArray(15)) }
        assertThrows(NowhereError::class.java) { configuration(sessionId = ByteArray(17)) }
        assertThrows(NowhereError::class.java) { configuration(sessionId = ByteArray(0)) }
        assertEquals(
            NowhereProtocol.SESSION_ID_SIZE,
            configuration(sessionId = ByteArray(16)).sessionId.size
        )
    }
}
