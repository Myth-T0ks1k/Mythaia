package com.mythaia.vpn.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress

/**
 * Reads MaxMind's own published test databases, so the parser is checked
 * against files a real GeoLite2 build is byte-compatible with rather than
 * against an encoder written alongside it.
 *
 * `GeoIP2-Country-Test.mmdb` uses 28-bit records over an IPv6 tree — the shape
 * GeoLite2-Country ships — and the addresses below are the ones MaxMind's own
 * suite asserts on.
 */
class MaxMindDbTest {

    private fun fixture(name: String): File? {
        val url = javaClass.classLoader?.getResource("geoip/$name") ?: return null
        return File(url.toURI())
    }

    private fun open(name: String): MaxMindDb? = fixture(name)?.let { MaxMindDb.open(it) }

    private fun bytes(ip: String): ByteArray = InetAddress.getByName(ip).address

    @Test
    fun `resolves countries from the GeoIP2 country test database`() {
        val db = open("GeoIP2-Country-Test.mmdb")
        assumeTrue("fixture missing", db != null)
        db!!

        assertEquals("GB", db.countryCode(bytes("81.2.69.160")))
        assertEquals("GB", db.countryCode(bytes("2.125.160.216")))
        assertEquals("SE", db.countryCode(bytes("89.160.20.112")))
        assertEquals("US", db.countryCode(bytes("216.160.83.56")))
        assertEquals("JP", db.countryCode(bytes("2001:218::1")))
    }

    @Test
    fun `an address the database does not cover returns null`() {
        val db = open("GeoIP2-Country-Test.mmdb")
        assumeTrue("fixture missing", db != null)
        db!!

        // Private space is deliberately absent from a country database; a
        // lookup must come back empty rather than guess.
        assertNull(db.countryCode(bytes("10.0.0.1")))
        assertNull(db.countryCode(bytes("127.0.0.1")))
        assertNull(db.countryCode(bytes("192.168.1.1")))
    }

    @Test
    fun `an IPv4 address resolves the same whether given as v4 or v4-mapped v6`() {
        val db = open("GeoIP2-Country-Test.mmdb")
        assumeTrue("fixture missing", db != null)
        db!!

        val mapped = ByteArray(16).also {
            it[10] = 0xFF.toByte()
            it[11] = 0xFF.toByte()
            bytes("81.2.69.160").copyInto(it, 12)
        }
        assertEquals(db.countryCode(bytes("81.2.69.160")), db.countryCode(mapped))
        assertEquals("GB", db.countryCode(mapped))
    }

    @Test
    fun `a 24-bit record database opens and answers`() {
        // The same format at the other record width; getting the node reader
        // wrong for one width would go unnoticed if only 28 were exercised.
        val db = open("MaxMind-DB-test-ipv4-24.mmdb")
        assumeTrue("fixture missing", db != null)
        assertNotNull(db)
        // This fixture carries no country field — what matters is that the tree
        // walk and metadata parse succeed without throwing.
        db!!.countryCode(bytes("1.1.1.1"))
    }

    @Test
    fun `an IPv6 address gets no answer from an IPv4-only database`() {
        // Walking it anyway would follow its first four bytes and return
        // whichever IPv4 address happens to share them — a confident wrong
        // country rather than no answer.
        val db = open("MaxMind-DB-test-ipv4-24.mmdb")
        assumeTrue("fixture missing", db != null)
        db!!

        assertNull(db.countryCode(bytes("2001:218::1")))
        assertNull(db.countryCode(bytes("::1")))
        // The v4 form of an address whose bytes a v6 address could shadow still
        // resolves normally.
        db.countryCode(bytes("1.1.1.1"))
    }

    @Test
    fun `a header describing more nodes than the file holds is refused`() {
        // The tree size comes from header fields, so an inflated node_count
        // would put every node read past the end of the mapping.
        val source = fixture("GeoIP2-Country-Test.mmdb")
        assumeTrue("fixture missing", source != null)

        val bytes = source!!.readBytes()
        val marker = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()) +
            "MaxMind.com".toByteArray(Charsets.US_ASCII)

        // Find the metadata, then the node_count value inside it, and inflate it.
        var metadataStart = -1
        outer@ for (start in bytes.size - marker.size downTo 0) {
            for (i in marker.indices) {
                if (bytes[start + i] != marker[i]) continue@outer
            }
            metadataStart = start + marker.size
            break
        }
        assertTrue("no metadata marker", metadataStart > 0)

        val key = "node_count".toByteArray(Charsets.US_ASCII)
        var keyAt = -1
        outer2@ for (start in metadataStart until bytes.size - key.size) {
            for (i in key.indices) {
                if (bytes[start + i] != key[i]) continue@outer2
            }
            keyAt = start
            break
        }
        assertTrue("no node_count key", keyAt > 0)

        // The value follows the key: a control byte then its big-endian bytes.
        val valueControl = keyAt + key.size
        val valueSize = bytes[valueControl].toInt() and 0x1F
        assertTrue("unexpected node_count encoding", valueSize in 1..4)
        for (i in 0 until valueSize) {
            bytes[valueControl + 1 + i] = 0xFF.toByte()
        }

        val corrupt = File.createTempFile("mythaia-geoip-corrupt", ".mmdb").apply {
            writeBytes(bytes)
            deleteOnExit()
        }
        assertNull(MaxMindDb.open(corrupt))
    }

    @Test
    fun `a file that is not a database is refused rather than throwing`() {
        val notADatabase = File.createTempFile("mythaia-geoip", ".mmdb").apply {
            writeBytes(ByteArray(4096) { it.toByte() })
            deleteOnExit()
        }
        assertNull(MaxMindDb.open(notADatabase))

        val empty = File.createTempFile("mythaia-geoip-empty", ".mmdb").apply { deleteOnExit() }
        assertNull(MaxMindDb.open(empty))

        assertNull(MaxMindDb.open(File("does-not-exist.mmdb")))
    }

    @Test
    fun `a malformed address length is refused`() {
        val db = open("GeoIP2-Country-Test.mmdb")
        assumeTrue("fixture missing", db != null)
        assertNull(db!!.countryCode(ByteArray(7)))
        assertNull(db.countryCode(ByteArray(0)))
    }
}
