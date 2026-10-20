package com.mythaia.desktop.update

import com.mythaia.data.update.UpdateRoute
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy

class DesktopUpdaterRoutesTest {

    @Test
    fun `with the tunnel up in proxy mode the update goes through the local port only`() {
        val routes = DesktopUpdater.routesFor(connected = true, tunnelMode = "proxy", httpPort = 12334)
        assertEquals(1, routes.size)
        val proxy = (routes.single() as UpdateRoute.LocalProxy).proxy
        assertEquals(Proxy.Type.HTTP, proxy.type())
        assertEquals(InetSocketAddress("127.0.0.1", 12334), proxy.address())
        // Never a direct attempt next to it: that would bypass the tunnel.
        assertTrue(routes.none { it === UpdateRoute.Direct })
    }

    @Test
    fun `in TUN mode or disconnected the system routes a plain request`() {
        assertEquals(listOf(UpdateRoute.Direct), DesktopUpdater.routesFor(connected = true, tunnelMode = "tun", httpPort = 12334))
        assertEquals(listOf(UpdateRoute.Direct), DesktopUpdater.routesFor(connected = false, tunnelMode = "proxy", httpPort = 12334))
    }
}
