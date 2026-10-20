package com.mythaia.data.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.InetAddress

class V2rayGeoFileTest {

    @Test
    fun `picks only the categories asked for`() {
        val sites = V2rayGeoFile.readSites(ByteArrayInputStream(GeoFixtures.sites), setOf("cn", "Ads", "missing"))
        assertEquals(setOf("CN", "ADS"), sites.keys)
        val cn = sites.getValue("CN")
        assertEquals(5, cn.size)
        assertEquals(V2rayGeoFile.Domain(V2rayGeoFile.DomainType.ROOT_DOMAIN, "baidu.com"), cn[0])
        assertEquals(V2rayGeoFile.DomainType.FULL, cn[1].type)
        assertEquals(V2rayGeoFile.DomainType.PLAIN, cn[2].type)
        assertEquals(V2rayGeoFile.DomainType.REGEX, cn[3].type)
        assertEquals(setOf("ads"), cn[4].attributes)
    }

    @Test
    fun `lists every entry name`() {
        assertEquals(listOf("CN", "CATEGORY-RU", "ADS", "UNUSED"), V2rayGeoFile.readCodes(ByteArrayInputStream(GeoFixtures.sites)))
    }

    @Test
    fun `reads address lists, inverse flag and zero prefixes`() {
        val withDefault = GeoFixtures.list(GeoFixtures.ip("ALL", "0.0.0.0/0"))
        val all = V2rayGeoFile.readIps(ByteArrayInputStream(withDefault), setOf("all")).getValue("ALL")
        assertEquals(0, all.cidrs.single().prefix)

        val ips = V2rayGeoFile.readIps(ByteArrayInputStream(GeoFixtures.ips), setOf("cn", "telegram", "notcn"))
        val cn = ips.getValue("CN")
        assertFalse(cn.inverse)
        assertEquals(3, cn.cidrs.size)
        assertEquals(18, cn.cidrs[2].prefix)
        assertEquals(16, cn.cidrs[2].ip.size)
        assertTrue(ips.getValue("NOTCN").inverse)
        assertNull(ips["RU"])
    }

    @Test
    fun `tells a rule file from an error page`() {
        assertTrue(V2rayGeoFile.looksValid(ByteArrayInputStream(GeoFixtures.sites)))
        assertTrue(V2rayGeoFile.looksValid(ByteArrayInputStream(GeoFixtures.ips)))
        assertFalse(V2rayGeoFile.looksValid(ByteArrayInputStream("<html>Not Found</html>".toByteArray())))
        assertFalse(V2rayGeoFile.looksValid(ByteArrayInputStream(ByteArray(0))))
        val cut = GeoFixtures.sites.copyOf(GeoFixtures.sites.size - 5)
        assertFalse(V2rayGeoFile.looksValid(ByteArrayInputStream(cut)))
    }

    @Test
    fun `store keeps existing rule file when replacement is invalid or truncated`() {
        val dir = java.nio.file.Files.createTempDirectory("geo-store-test").toFile()
        try {
            val store = GeoFileStore(dir)
            val url = "https://example.com/geosite.dat"
            val target = store.fileFor(url)
            val temp = java.io.File(dir, target.name + ".tmp")

            store.streamBounded(ByteArrayInputStream(GeoFixtures.sites), temp, GeoFixtures.sites.size.toLong())
            store.installVerified(temp, target)
            assertTrue(store.has(url))
            assertEquals(GeoFixtures.sites.size.toLong(), target.length())

            // Corrupt replacement must fail without deleting the good target file.
            temp.writeBytes("<html>502 Bad Gateway</html>".toByteArray())
            val failed = runCatching { store.installVerified(temp, target) }.exceptionOrNull()
            assertTrue(failed is java.io.IOException)
            assertFalse(temp.exists())
            assertTrue(target.isFile)
            assertEquals(GeoFixtures.sites.size.toLong(), target.length())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test(expected = java.io.IOException::class)
    fun `a truncated file fails rather than reading garbage`() {
        val cut = GeoFixtures.sites.copyOf(GeoFixtures.sites.size - 5)
        V2rayGeoFile.readSites(ByteArrayInputStream(cut), setOf("unused"))
    }

    @Test
    fun `ranges match the addresses they hold`() {
        val ranges = IpRanges.Builder().apply {
            add(InetAddress.getByName("10.0.0.0").address, 8)
            add(InetAddress.getByName("10.1.2.3").address, 32)
            add(InetAddress.getByName("11.0.0.0").address, 8)
            add(InetAddress.getByName("2001:db8::").address, 32)
        }.build()
        // 10/8 and 11/8 merge; the /32 inside them disappears.
        assertEquals(2, ranges.size)
        assertTrue(ranges.contains(InetAddress.getByName("10.200.0.1").address))
        assertTrue(ranges.contains(InetAddress.getByName("11.255.255.255").address))
        assertFalse(ranges.contains(InetAddress.getByName("12.0.0.0").address))
        assertFalse(ranges.contains(InetAddress.getByName("9.255.255.255").address))
        assertTrue(ranges.contains(InetAddress.getByName("2001:db8:ffff::1").address))
        assertFalse(ranges.contains(InetAddress.getByName("2001:db9::1").address))
        // An IPv4-mapped address is its IPv4 address.
        assertTrue(ranges.contains(IpRanges.parseAddress("::ffff:10.0.0.1")!!))
    }

    @Test
    fun `v6 ranges across the halves merge and match`() {
        val ranges = IpRanges.Builder().apply {
            add(IpRanges.parseAddress("::")!!, 1)
            add(IpRanges.parseAddress("8000::")!!, 1)
        }.build()
        assertEquals(1, ranges.size)
        assertTrue(ranges.contains(IpRanges.parseAddress("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")!!))
        assertTrue(ranges.contains(IpRanges.parseAddress("::1")!!))
    }

    @Test
    fun `addresses parse without ever resolving a name`() {
        assertEquals(listOf(192, 168, 1, 0), IpRanges.parseCidr("192.168.1.0/24")!!.first.map { it.toInt() and 0xFF })
        assertEquals(24, IpRanges.parseCidr("192.168.1.0/24")!!.second)
        assertEquals(32, IpRanges.parseCidr("255.255.255.255")!!.second)
        assertEquals(128, IpRanges.parseCidr("2001:db8::1")!!.second)
        assertNull(IpRanges.parseCidr("example.com"))
        assertNull(IpRanges.parseCidr("10.0.0.0/33"))
        assertNull(IpRanges.parseCidr("1.2.3"))
        assertNull(IpRanges.parseAddress("1:2:3:4:5:6:7:8:9"))
        val mapped = IpRanges.parseAddress("::ffff:1.2.3.4")!!
        assertEquals(16, mapped.size)
        assertEquals(listOf(0xFF, 0xFF, 1, 2, 3, 4), mapped.drop(10).map { it.toInt() and 0xFF })
    }
}
