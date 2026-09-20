package com.mythaia.vpn.tun

import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.util.PacketUtil
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the TUN stack answers on port 53. A wrong answer here sends a
 * connection past the router, so every branch is pinned: fake A, AAAA
 * only when IPv6 is on, SVCB and DDR refused, everything else let through.
 */
class FakeIpDnsTest {

    private fun query(name: String, qtype: Int, id: Int = 0x1234): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00)             // RD
        out.write(0); out.write(1)                   // QDCOUNT
        repeat(6) { out.write(0) }                   // AN/NS/AR
        for (label in name.split('.')) {
            out.write(label.length)
            out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0)
        out.write(qtype shr 8); out.write(qtype and 0xFF)
        out.write(0); out.write(1)                   // IN
        return out.toByteArray()
    }

    private fun ancount(response: ByteArray) = ((response[6].toInt() and 0xFF) shl 8) or (response[7].toInt() and 0xFF)

    @Test
    fun `A queries get a fake IPv4 from the pool`() {
        val pool = FakeIpPool()
        val q = query("example.com", 1)
        val answer = FakeIpDns.answer(q, pool, ipv6Dns = false, encryptedDnsEnabled = false)
        assertTrue(answer is FakeIpDns.Answer.Reply)
        val response = (answer as FakeIpDns.Answer.Reply).response
        assertEquals(0x12, response[0].toInt()); assertEquals(0x34, response[1].toInt())   // same id
        assertEquals(1, ancount(response))
        val rdata = response.copyOfRange(response.size - 4, response.size)
        val offset = pool.allocate("example.com")
        assertArrayEquals(FakeIpPool.ipv4Bytes(offset), rdata)
        assertEquals("example.com", pool.lookup("198.18.0.$offset")?.domain)
    }

    @Test
    fun `the domain is matched case-insensitively`() {
        val pool = FakeIpPool()
        FakeIpDns.answer(query("Example.COM", 1), pool, ipv6Dns = false, encryptedDnsEnabled = false)
        assertEquals(1, pool.count)
        assertEquals(1, pool.allocate("example.com"))
    }

    @Test
    fun `AAAA is NODATA unless IPv6 DNS is on`() {
        val pool = FakeIpPool()
        val q = query("example.com", 28)
        val off = FakeIpDns.answer(q, pool, ipv6Dns = false, encryptedDnsEnabled = false) as FakeIpDns.Answer.Reply
        assertEquals(0, ancount(off.response))
        val on = FakeIpDns.answer(q, pool, ipv6Dns = true, encryptedDnsEnabled = false) as FakeIpDns.Answer.Reply
        assertEquals(1, ancount(on.response))
        val rdata = on.response.copyOfRange(on.response.size - 16, on.response.size)
        assertArrayEquals(FakeIpPool.ipv6Bytes(pool.allocate("example.com")), rdata)
    }

    @Test
    fun `SVCB and HTTPS records are refused with NODATA`() {
        val answer = FakeIpDns.answer(query("example.com", 65), FakeIpPool(), ipv6Dns = false, encryptedDnsEnabled = false)
        val reply = answer as FakeIpDns.Answer.Reply
        assertEquals("SVCB", reply.reason)
        assertEquals(0, ancount(reply.response))
        assertEquals(0x80, reply.response[2].toInt() and 0x80)   // QR set
    }

    @Test
    fun `DDR discovery is refused only while encrypted DNS is off`() {
        val q = query("_dns.resolver.arpa", 64)
        val blocked = FakeIpDns.answer(q, FakeIpPool(), ipv6Dns = false, encryptedDnsEnabled = false)
        assertEquals("DDR", (blocked as FakeIpDns.Answer.Reply).reason)
        val allowed = FakeIpDns.answer(q, FakeIpPool(), ipv6Dns = false, encryptedDnsEnabled = true)
        assertEquals(FakeIpDns.Answer.PassThrough, allowed)
    }

    @Test
    fun `other record types and garbage pass through`() {
        assertEquals(FakeIpDns.Answer.PassThrough, FakeIpDns.answer(query("example.com", 15), FakeIpPool(), false, false))  // MX
        assertEquals(FakeIpDns.Answer.PassThrough, FakeIpDns.answer(ByteArray(5), FakeIpPool(), false, false))
    }

    @Test
    fun `the answer still parses as a response to the same question`() {
        val q = query("a.b.example.org", 1)
        val reply = FakeIpDns.answer(q, FakeIpPool(), false, false) as FakeIpDns.Answer.Reply
        val parsed = PacketUtil.parseDnsQueryExt(reply.response)
        assertEquals("a.b.example.org", parsed?.domain)
        assertEquals(1, parsed?.qtype)
    }
}
