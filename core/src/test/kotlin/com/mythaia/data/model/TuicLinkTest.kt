package com.mythaia.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.UUID

/** `tuic://uuid:password@host:port`, the shape every TUIC client emits. */
class TuicLinkTest {

    private val uuid = "b1a2c3d4-0000-4000-8000-000000000001"

    @Test
    fun `a link splits into a uuid and a password`() {
        val config = ProxyConfiguration.fromUrl("tuic://$uuid:hunter2@example.com:8443#Tokyo")

        assertEquals(OutboundProtocol.TUIC, config.outboundProtocol)
        assertEquals(UUID.fromString(uuid), config.uuid)
        assertEquals("hunter2", config.password)
        assertEquals("example.com", config.serverAddress)
        assertEquals(8443.toUShort(), config.serverPort)
        assertEquals("Tokyo", config.name)
    }

    @Test
    fun `a link without a port takes 443`() {
        val config = ProxyConfiguration.fromUrl("tuic://$uuid:pw@example.com")
        assertEquals(443.toUShort(), config.serverPort)
    }

    @Test
    fun `sni overrides the host for the certificate name`() {
        val config = ProxyConfiguration.fromUrl("tuic://$uuid:pw@1.2.3.4:443?sni=example.com")
        assertEquals("example.com", config.tls?.serverName)
    }

    @Test
    fun `a percent-encoded password survives the round trip`() {
        val config = ProxyConfiguration.fromUrl("tuic://$uuid:p%40ss%3Aword@example.com:443")
        assertEquals("p@ss:word", config.password)
    }

    @Test
    fun `a percent sign in the password survives the round trip`() {
        // The userinfo is decoded once, by the link splitter; decoding the
        // password a second time turned "a%41b" into "aAb".
        val original = ProxyConfiguration.fromUrl("tuic://$uuid:a%2541b@example.com:443#N")
        assertEquals("a%41b", original.password)
        assertEquals("a%41b", ProxyConfiguration.fromUrl(original.toUrl()).password)
    }

    @Test
    fun `a link round-trips back to itself`() {
        val original = ProxyConfiguration.fromUrl("tuic://$uuid:hunter2@example.com:8443#Tokyo")
        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())

        assertEquals(original.uuid, reparsed.uuid)
        assertEquals(original.password, reparsed.password)
        assertEquals(original.serverAddress, reparsed.serverAddress)
        assertEquals(original.serverPort, reparsed.serverPort)
        assertEquals(original.name, reparsed.name)
    }

    @Test
    fun `a link with no password is refused`() {
        try {
            ProxyConfiguration.fromUrl("tuic://$uuid@example.com:443")
            fail("expected a refusal")
        } catch (e: Exception) {
            assertTrue(e is ProxyError.InvalidUrl)
        }
    }

    @Test
    fun `a user part that is not a UUID is refused`() {
        try {
            ProxyConfiguration.fromUrl("tuic://not-a-uuid:pw@example.com:443")
            fail("expected a refusal")
        } catch (e: Exception) {
            assertTrue(e is ProxyError.InvalidUrl)
        }
    }

    @Test
    fun `the scheme is one the importer recognises`() {
        assertTrue(ProxyConfiguration.canParseUrl("tuic://$uuid:pw@example.com"))
    }
}
