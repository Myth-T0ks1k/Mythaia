package com.mythaia.desktop.engine

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.network.ProtocolProbe
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Holds one server open as local proxies so outside tools (curl, a browser)
 * can be pointed at it: `MYTHAIA_HOLD_LINK` is the share link, the SOCKS5 and
 * HTTP listeners take `MYTHAIA_HOLD_SOCKS` / `MYTHAIA_HOLD_HTTP` (default
 * 21080 / 21081), and the engine stays up for `MYTHAIA_HOLD_SECONDS`
 * (default 120), printing traffic every ten seconds. The system proxy is left
 * alone.
 */
class ProxyHoldSmoke {
    @Test
    fun `hold one server open as local proxies`() = runBlocking {
        val link = System.getenv("MYTHAIA_HOLD_LINK")
        assumeTrue("MYTHAIA_HOLD_LINK not set", !link.isNullOrBlank())
        if (System.getenv("MYTHAIA_HOLD_LOG") != null) {
            com.mythaia.vpn.util.MythaiaLogger.debugEnabled = true
            com.mythaia.vpn.util.MythaiaLogger.backend = object : com.mythaia.vpn.util.LogBackend {
                override fun log(level: com.mythaia.vpn.util.MythaiaLogger.Level, category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} $level [$category] $message")
                override fun debug(category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} debug [$category] $message")
            }
        }
        val input = ProtocolProbe.readInput(link!!.toByteArray())
        val config = ProtocolProbe.configurationsOf("hold", input).first()
        CertificatePolicy.setAllowInsecure(input.insecure)
        // The app-wide fragment switch (on by default in both apps), for servers
        // whose link carries no fragment= of its own: MYTHAIA_HOLD_FRAGMENT=off|on.
        val fragment = System.getenv("MYTHAIA_HOLD_FRAGMENT") != "off"
        FragmentPolicy.set(FragmentSettings(isEnabled = fragment))
        println("HOLD ${config.name} ${config.outboundProtocol} ${config.serverAddress}:${config.serverPort} link-fragment=${config.tls?.fragment} app-fragment=$fragment")

        val settings = DesktopSettings(
            socksPort = System.getenv("MYTHAIA_HOLD_SOCKS")?.toInt() ?: 21080,
            httpPort = System.getenv("MYTHAIA_HOLD_HTTP")?.toInt() ?: 21081,
            setSystemProxy = false,
            routeMode = "global",
            bypassTurkmenistan = false
        )
        val engine = ProxyEngine(TrafficStats())
        engine.updateRouting(emptyList(), settings)
        engine.start(settings, config)
        println("HOLD ready socks=${settings.socksPort} http=${settings.httpPort}")
        try {
            val seconds = System.getenv("MYTHAIA_HOLD_SECONDS")?.toInt() ?: 120
            repeat(seconds / 10) {
                delay(10_000)
                println("HOLD traffic up=${engine.stats.up.get()} down=${engine.stats.down.get()}")
            }
        } finally {
            engine.stop()
            CertificatePolicy.setAllowInsecure(false)
            FragmentPolicy.set(FragmentSettings())
        }
    }
}
