package com.mythaia.vpn.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The CIDR handling behind a WireGuard profile's Address and AllowedIPs. */
class CidrTest {

    @Test
    fun `a prefix is split from its address`() {
        assertEquals(Cidr.Entry("10.0.0.2", 24), Cidr.split("10.0.0.2/24"))
        assertEquals(Cidr.Entry("0.0.0.0", 0), Cidr.split("0.0.0.0/0"))
        assertEquals(Cidr.Entry("::", 0), Cidr.split("::/0"))
        assertEquals(Cidr.Entry("fd00::2", 128), Cidr.split("fd00::2/128"))
    }

    @Test
    fun `surrounding space is not part of the entry`() {
        assertEquals(Cidr.Entry("10.0.0.2", 32), Cidr.split("  10.0.0.2/32  "))
    }

    @Test
    fun `a bare address is a host route`() {
        assertEquals(Cidr.Entry("1.2.3.4", 32), Cidr.split("1.2.3.4"))
        assertEquals(Cidr.Entry("fd00::1", 128), Cidr.split("fd00::1"))
    }

    @Test
    fun `a name is refused rather than looked up`() {
        // A DNS lookup on the thread bringing the tunnel up is the one thing
        // this must never do.
        assertNull(Cidr.split("example.com/32"))
        assertNull(Cidr.split("example.com"))
    }

    @Test
    fun `a prefix outside its family's range is refused`() {
        assertNull(Cidr.split("10.0.0.0/33"))
        assertNull(Cidr.split("10.0.0.0/-1"))
        assertNull(Cidr.split("fd00::/129"))
        assertNull(Cidr.split("10.0.0.0/x"))
        assertNull(Cidr.split("/24"))
        assertNull(Cidr.split(""))
    }

    @Test
    fun `an IPv4 prefix is masked to its network`() {
        // addRoute refuses host bits, so `AllowedIPs = 10.0.0.2/24` would drop
        // the whole subnet out of the tunnel instead of routing it.
        assertEquals("10.0.0.0", Cidr.networkOf("10.0.0.2", 24))
        assertEquals("10.0.0.0", Cidr.networkOf("10.0.0.255", 24))
        assertEquals("192.168.16.0", Cidr.networkOf("192.168.19.7", 20))
        assertEquals("0.0.0.0", Cidr.networkOf("8.8.8.8", 0))
        assertEquals("1.2.3.4", Cidr.networkOf("1.2.3.4", 32))
    }

    @Test
    fun `a prefix that does not fall on a byte boundary is masked bitwise`() {
        // 130 is 1000_0010, so a /25 keeps its top bit: the network is .128.
        assertEquals("10.0.0.128", Cidr.networkOf("10.0.0.130", 25))
        assertEquals("10.0.0.128", Cidr.networkOf("10.0.0.200", 25))
        assertEquals("10.128.0.0", Cidr.networkOf("10.170.0.0", 9))
    }

    @Test
    fun `an IPv6 prefix is masked to its network`() {
        // hostAddress spells an IPv6 address out in full; it does not abbreviate.
        assertEquals("0:0:0:0:0:0:0:0", Cidr.networkOf("2001:db8::1", 0))
        assertEquals("2001:db8:0:0:0:0:0:0", Cidr.networkOf("2001:db8::dead:beef", 32))
        assertEquals("fd00:0:0:0:0:0:0:1", Cidr.networkOf("fd00::1", 128))
    }

    @Test
    fun `something that is not an address has no network`() {
        assertNull(Cidr.networkOf("not-an-address", 24))
    }
}
