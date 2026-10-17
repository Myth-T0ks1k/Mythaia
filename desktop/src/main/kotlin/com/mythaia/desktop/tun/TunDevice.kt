package com.mythaia.desktop.tun

import java.io.IOException

/**
 * A layer-3 interface as [TunEngine] sees it: IP packets in, IP packets
 * out. A Wintun adapter on Windows, a utun socket on macOS. Each array
 * handed over holds exactly one IPv4 or IPv6 packet, with no link-layer or
 * address-family header.
 */
interface TunDevice {
    /** The interface name the system knows it by (`Mythaia`, `utun5`). */
    val name: String

    /** Begins packet exchange; called once the routes and the stack are ready. */
    @Throws(IOException::class)
    fun start()

    /**
     * Receives packets until [keepRunning] returns false or the device is
     * stopped, handing them over in batches of up to [batchSize]. Runs on
     * the caller's thread and returns within a fraction of a second of
     * either condition.
     */
    fun readLoop(keepRunning: () -> Boolean, batchSize: Int = 64, onBatch: (List<ByteArray>) -> Unit)

    /** Queues one packet for the system; a full queue drops it, as a NIC would. False when dropped. */
    fun send(packet: ByteArray, length: Int): Boolean

    /** Ends packet exchange: a [readLoop] in progress returns, [send] drops from now on. */
    fun stop()

    /** Releases the interface; the system removes it and every route on it. Idempotent. */
    fun close()
}

/**
 * The system side of TUN mode, one implementation per platform: what has to
 * be true before anything is touched, where the physical network is, how
 * the interface is made and how traffic is pointed at it and back.
 *
 * An instance belongs to one [TunEngine] and remembers what it changed, so
 * [restore] undoes exactly that.
 */
interface TunPlatform {
    /** Throws [IOException] with a user-readable reason when TUN mode cannot start here. */
    @Throws(IOException::class)
    fun checkReady()

    /** Undoes what a run that died left in the system, if this run may. */
    fun cleanupLeftovers()

    /** The path the default route takes now; must be read before the routes move. Null when offline. */
    fun physicalPath(): PhysicalPath?

    /** Creates the interface. */
    @Throws(IOException::class)
    fun openDevice(): TunDevice

    /**
     * Addresses [device] and points the system's traffic at it, except
     * [excludedHosts] and [excludedNetworks] (IPv4, `a.b.c.d/n`), which keep
     * going out [path]. Throws when the essentials fail, having undone what
     * it did.
     */
    @Throws(IOException::class)
    fun configure(device: TunDevice, path: PhysicalPath, excludedHosts: List<String>, excludedNetworks: List<String>)

    /** Keeps [ip] on the physical side from now on (a newly selected proxy server, say). */
    fun excludeHost(ip: String)

    /** Undoes [configure]. Safe to call twice, and without a [configure]. */
    fun restore()
}
