package com.mythaia.vpn

import android.net.Network
import com.mythaia.vpn.util.UnderlyingNetwork
import java.net.InetAddress
import java.net.URL
import java.net.URLConnection

/** The physical network under the VPN, as [DnsCache] sees it. */
class AndroidUnderlyingNetwork(val network: Network) : UnderlyingNetwork {
    override fun getAllByName(host: String): Array<InetAddress> = network.getAllByName(host)
    override fun openConnection(url: URL): URLConnection = network.openConnection(url)
}
