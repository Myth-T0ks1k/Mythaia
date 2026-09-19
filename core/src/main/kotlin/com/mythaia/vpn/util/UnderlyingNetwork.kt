package com.mythaia.vpn.util

import java.net.InetAddress
import java.net.URL
import java.net.URLConnection

/**
 * The physical network DNS bootstrap goes over while a tunnel is up, so a
 * resolver lookup never enters the tunnel it is resolving for. Android wraps
 * `android.net.Network`; the desktop app has no tunnel interface and uses
 * the default routes.
 */
interface UnderlyingNetwork {
    fun getAllByName(host: String): Array<InetAddress>
    fun openConnection(url: URL): URLConnection
}
