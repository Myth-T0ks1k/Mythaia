package com.mythaia.desktop.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The parts of the macOS proxy switch that do not need a Mac: parsing and the commands built. */
class MacSystemProxyTest {

    @Test
    fun `services skip the header line and disabled services`() {
        val out = """
            An asterisk (*) denotes that a network service is disabled.
            Wi-Fi
            *Bluetooth PAN
            USB 10/100/1000 LAN
            Thunderbolt Bridge
        """.trimIndent()
        assertEquals(listOf("Wi-Fi", "USB 10/100/1000 LAN", "Thunderbolt Bridge"), MacSystemProxy.parseServices(out))
    }

    @Test
    fun `proxy entry is read from networksetup output`() {
        val on = MacSystemProxy.parseEntry("Enabled: Yes\nServer: 192.0.2.10\nPort: 3128\nAuthenticated Proxy Enabled: 0\n")
        assertTrue(on.enabled)
        assertEquals("192.0.2.10", on.server)
        assertEquals(3128, on.port)

        val off = MacSystemProxy.parseEntry("Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n")
        assertFalse(off.enabled)
        assertEquals("", off.server)
        assertEquals(0, off.port)
    }

    @Test
    fun `no bypass domains reads as an empty list`() {
        assertEquals(emptyList<String>(), MacSystemProxy.parseBypass("There aren't any bypass domains set on Wi-Fi.\n"))
        assertEquals(listOf("*.local", "169.254/16"), MacSystemProxy.parseBypass("*.local\n169.254/16\n"))
    }

    @Test
    fun `the Windows exception list becomes macOS bypass entries`() {
        val domains = MacSystemProxy.bypassDomains("localhost;127.*;10.*;192.168.*;172.2*;<local>")
        assertTrue("localhost" in domains)
        assertTrue("127.0.0.0/8" in domains)
        assertTrue("10.0.0.0/8" in domains)
        assertTrue("192.168.0.0/16" in domains)
        assertTrue("172.20.0.0/16" in domains)
        assertTrue("172.29.0.0/16" in domains)
        assertFalse("172.2.0.0/16" in domains)
        assertTrue("*.local" in domains)
        assertTrue("169.254/16" in domains)
    }

    @Test
    fun `enabling sets three proxies and the bypass list on every service`() {
        val commands = MacSystemProxy.enableCommands(
            listOf("Wi-Fi", "Ethernet"), "127.0.0.1:10809", "127.0.0.1:10808", "localhost;<local>"
        )
        assertEquals(8, commands.size)
        assertEquals(listOf("-setwebproxy", "Wi-Fi", "127.0.0.1", "10809", "off"), commands[0])
        assertEquals(listOf("-setsecurewebproxy", "Wi-Fi", "127.0.0.1", "10809", "off"), commands[1])
        assertEquals(listOf("-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "10808", "off"), commands[2])
        assertEquals(listOf("-setproxybypassdomains", "Wi-Fi", "localhost", "*.local", "169.254/16"), commands[3])
        assertEquals("Ethernet", commands[4][1])
    }

    @Test
    fun `restoring puts back the user's own proxy and its state`() {
        val saved = MacSystemProxy.ServiceSettings(
            service = "Wi-Fi",
            web = MacSystemProxy.Entry(enabled = true, server = "192.0.2.10", port = 3128),
            secureWeb = MacSystemProxy.Entry(enabled = false, server = "", port = 0),
            socks = MacSystemProxy.Entry(enabled = false, server = "192.0.2.11", port = 1080),
            bypass = emptyList()
        )
        val commands = MacSystemProxy.restoreCommands(saved)
        assertEquals(
            listOf(
                listOf("-setwebproxy", "Wi-Fi", "192.0.2.10", "3128", "off"),
                listOf("-setwebproxystate", "Wi-Fi", "on"),
                listOf("-setsecurewebproxystate", "Wi-Fi", "off"),
                listOf("-setsocksfirewallproxy", "Wi-Fi", "192.0.2.11", "1080", "off"),
                listOf("-setsocksfirewallproxystate", "Wi-Fi", "off"),
                listOf("-setproxybypassdomains", "Wi-Fi", "Empty")
            ),
            commands
        )
    }

    @Test
    fun `launch agent runs the launcher minimised`() {
        val plist = LaunchAtLogin.launchAgentPlist("/Applications/Mythaia Pro.app/Contents/MacOS/Mythaia Pro")
        assertTrue(plist.startsWith("<?xml"))
        assertTrue(plist.contains("<string>/Applications/Mythaia Pro.app/Contents/MacOS/Mythaia Pro</string>"))
        assertTrue(plist.contains("<string>--minimized</string>"))
        assertTrue(plist.contains("<key>RunAtLoad</key>"))
    }
}
