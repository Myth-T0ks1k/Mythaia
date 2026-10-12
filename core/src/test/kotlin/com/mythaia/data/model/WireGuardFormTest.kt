package com.mythaia.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireGuardFormTest {

    private val ini = """
        [Interface]
        # from the panel
        PrivateKey = ADAS9brqmHVG11XeR2owXGOqZnYvZMvr4Zl2ZB24ImM=
        Address = 10.77.0.2/32
        Address = fd00::2/128
        DNS = 1.1.1.1
        MTU = 1280
        Jc = 4
        Jmin = 40
        Jmax = 70
        H1 = 1234
        FwMark = 51820

        [Peer]
        PublicKey = 8f8vrIkNUX7YeEmFFDOm40WjPrdFJx7FYrQxrH7kHUo=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = example.com:51820
        PersistentKeepalive = 25

        [Peer]
        PublicKey = QANhijWsyxQzzFP07g1lIY75OK57fF0HGuJJdrsPiFA=
        Endpoint = second.example.com:51820
    """.trimIndent()

    @Test
    fun `fields read and unknown lines survive a round trip`() {
        val form = WireGuardForm.fromIni(ini)
        assertEquals("10.77.0.2/32, fd00::2/128", form.addresses)
        assertEquals("1280", form.mtu)
        assertEquals("example.com:51820", form.endpoint)
        assertTrue(form.isAmnezia)
        assertTrue(form.extraInterface.any { it.contains("FwMark") })
        assertTrue(form.extraInterface.any { it.contains("# from the panel") })
        val out = form.copy(mtu = "1420").toIni()
        assertTrue(out.contains("MTU = 1420"))
        assertTrue(out.contains("FwMark = 51820"))
        assertTrue(out.contains("second.example.com:51820"))
        // What the form writes is what the tunnel parses.
        val parsed = com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse(out)
        assertEquals("example.com", parsed.peer.endpointHost)
        assertEquals(1420, parsed.mtu)
    }

    @Test
    fun `a blank profile has a valid key pair`() {
        val form = WireGuardForm.blank()
        val pub = WireGuardForm.publicKeyOf(form.privateKey)
        assertNotNull(pub)
        assertEquals(44, pub!!.length)
    }
}
