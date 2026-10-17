package com.mythaia.desktop.tun

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.io.IOException

/**
 * TUN mode on Windows: a Wintun adapter, addressed and routed with `netsh`
 * and `route` ([WindowsRoutes]), the routes snapshotted in [snapshot] so a
 * crash is cleaned up on the next start.
 */
class WindowsTunPlatform(snapshot: File) : TunPlatform {
    private val logger = MythaiaLogger("TunEngine")
    private val routes = WindowsRoutes(snapshot)

    override fun checkReady() {
        if (!WindowsNet.isWindows) throw IOException("TUN mode is only available on Windows")
        if (!NativeBridge.isLoaded) throw IOException("The native library (mythaia_native.dll) is not loaded")
        wintun()
        if (!Elevation.isElevated()) throw IOException("TUN mode needs administrator rights")
    }

    override fun cleanupLeftovers() = routes.cleanupLeftovers()

    override fun physicalPath(): PhysicalPath? = WindowsNet.physicalPath()

    override fun openDevice(): TunDevice {
        val dll = wintun()
        val adapter = WintunAdapter.create(dll, ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)
        val ifIndex = try {
            adapter.interfaceIndex()
        } catch (e: Exception) {
            adapter.close()
            throw e
        }
        logger.info("Wintun adapter '$ADAPTER_NAME' is interface $ifIndex (driver ${WintunAdapter.runningDriverVersion(dll) ?: "?"})")
        return WintunDevice(adapter, ifIndex)
    }

    override fun configure(device: TunDevice, path: PhysicalPath, excludedHosts: List<String>, excludedNetworks: List<String>) {
        val wintun = device as WintunDevice
        routes.apply(
            TunNetConfig(
                interfaceIndex = wintun.interfaceIndex,
                physicalInterfaceIndex = path.interfaceIndex,
                physicalGateway = path.gateway,
                excludedHosts = excludedHosts,
                excludedNetworks = excludedNetworks
            )
        )
    }

    override fun excludeHost(ip: String) = routes.excludeHost(ip)

    override fun restore() = routes.restore()

    private fun wintun(): File =
        AppPaths.wintunLibrary() ?: throw IOException("wintun.dll not found (expected in ${AppPaths.resourcesDir ?: "resources/windows-x64"})")

    companion object {
        const val ADAPTER_NAME = "Mythaia"
        private const val TUNNEL_TYPE = "Mythaia"
        /** Fixed so Windows keeps one network profile for the adapter across runs. */
        private const val ADAPTER_GUID = "{9E2F1A8C-4B6D-4C3E-9F0A-2D7B5C1E8A4F}"
    }
}

/** A Wintun adapter and, once [start]ed, its session. */
class WintunDevice(private val adapter: WintunAdapter, val interfaceIndex: Int) : TunDevice {
    @Volatile
    private var session: WintunAdapter.Session? = null

    override val name: String get() = adapter.name

    override fun start() {
        session = adapter.startSession()
    }

    override fun readLoop(keepRunning: () -> Boolean, batchSize: Int, onBatch: (List<ByteArray>) -> Unit) {
        session?.readLoop(keepRunning, batchSize, onBatch)
    }

    override fun send(packet: ByteArray, length: Int): Boolean = session?.send(packet, length) ?: false

    override fun stop() {
        session?.end()
        session = null
    }

    override fun close() {
        stop()
        adapter.close()
    }
}
