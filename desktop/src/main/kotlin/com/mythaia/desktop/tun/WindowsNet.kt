package com.mythaia.desktop.tun

import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Memory
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.LongByReference
import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

/**
 * What the TUN engine needs to know about the physical network before it
 * takes the default route over: which interface carries it, through which
 * gateway, with which address, and which DNS servers it was using.
 */
data class PhysicalPath(
    val interfaceIndex: Int,
    /** Null when the best route is on-link (no gateway). */
    val gateway: String?,
    /** The interface's IPv4 address, for binding sockets to it. */
    val address: InetAddress,
    /** The interface's IPv4 networks, as `address/prefix`, so on-link hosts are not given host routes. */
    val networks: List<Pair<InetAddress, Int>>,
    /** IPv4 DNS servers configured on that interface (static or DHCP). */
    val dnsServers: List<String>
) {
    /** Whether [ip] is already reachable on-link through this interface. */
    fun isOnLink(ip: InetAddress): Boolean {
        val bytes = ip.address
        return networks.any { (net, prefix) ->
            val n = net.address
            if (n.size != bytes.size) return@any false
            var bits = prefix
            for (i in n.indices) {
                if (bits <= 0) return@any true
                val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
                if ((n[i].toInt() and mask) != (bytes[i].toInt() and mask)) return@any false
                bits -= 8
            }
            true
        }
    }
}

/** Reading the Windows network state and running its configuration tools. */
object WindowsNet {
    private val logger = MythaiaLogger("WindowsNet")
    private val ipv4Literal = Regex("""\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b""")

    val isWindows: Boolean = System.getProperty("os.name").orEmpty().startsWith("Windows")

    /**
     * The path packets to [probe] take right now: interface and next hop
     * from `GetBestRoute`, addresses from the JDK, DNS from the registry.
     * Must be called before the TUN routes exist, or it finds the TUN.
     */
    fun physicalPath(probe: String = "8.8.8.8"): PhysicalPath? {
        val (ifIndex, nextHop) = bestRoute(probe) ?: return null
        return pathVia(ifIndex, nextHop)
    }

    /**
     * The physical path while a tunnel adapter ([excludeIfIndex]) is up and
     * may hold the default: the best route if it is not the adapter's, else
     * the lowest-metric default route on any other interface. For noticing
     * that the network under a running tunnel changed.
     */
    fun physicalPathExcluding(excludeIfIndex: Int, probe: String = "8.8.8.8"): PhysicalPath? {
        val best = bestRoute(probe)
        if (best != null && best.first != excludeIfIndex) return pathVia(best.first, best.second)
        val route = defaultRoutes().filter { it.interfaceIndex != excludeIfIndex }.minByOrNull { it.metric } ?: return null
        return pathVia(route.interfaceIndex, route.nextHop)
    }

    /** One IPv4 default route from the routing table. */
    data class DefaultRoute(val interfaceIndex: Int, val nextHop: String?, val metric: Int)

    /** Every 0.0.0.0/0 route in the IPv4 table (GetIpForwardTable). */
    fun defaultRoutes(): List<DefaultRoute> {
        val lib = runCatching { IpHlpApiLib.INSTANCE }.getOrNull() ?: return emptyList()
        val size = IntByReference(0)
        lib.GetIpForwardTable(null, size, false)
        if (size.value <= 0) return emptyList()
        // The table can grow between the two calls; a little room spares a retry.
        val table = Memory(size.value.toLong() + 56L * 8)
        size.value = table.size().toInt()
        if (lib.GetIpForwardTable(table, size, false) != 0) return emptyList()
        val count = table.getInt(0)
        val out = ArrayList<DefaultRoute>()
        for (i in 0 until count) {
            val row = 4L + i * 56L
            if (row + 56 > table.size()) break
            val dest = table.getInt(row)
            val mask = table.getInt(row + 4)
            val type = table.getInt(row + 20)          // 2 = invalid
            if (dest != 0 || mask != 0 || type == 2) continue
            val nextHop = unpackAddress(table.getInt(row + 12))
            out += DefaultRoute(table.getInt(row + 16), nextHop.takeIf { type != 3 && it != "0.0.0.0" }, table.getInt(row + 36))
        }
        return out
    }

    private fun pathVia(ifIndex: Int, nextHop: String?): PhysicalPath? {
        val nic = runCatching { NetworkInterface.getByIndex(ifIndex) }.getOrNull() ?: return null
        val v4 = nic.interfaceAddresses.filter { it.address is Inet4Address }
        val address = v4.firstOrNull()?.address ?: return null
        val networks = v4.map { it.address to it.networkPrefixLength.toInt() }
        val gateway = nextHop?.takeIf { it != "0.0.0.0" && it != address.hostAddress }
        return PhysicalPath(ifIndex, gateway, address, networks, dnsServers(ifIndex))
    }

    /** `(interfaceIndex, nextHop)` for [destination], or null when Windows has no route. */
    fun bestRoute(destination: String): Pair<Int, String?>? {
        val dest = runCatching { InetAddress.getByName(destination) }.getOrNull() as? Inet4Address ?: return null
        val row = Memory(56)
        row.clear()
        val status = runCatching { IpHlpApiLib.INSTANCE.GetBestRoute(packAddress(dest.address), 0, row) }
            .onFailure { logger.warning("GetBestRoute unavailable: ${it.message}") }
            .getOrNull() ?: return null
        if (status != 0) {
            logger.warning("GetBestRoute($destination) failed: $status")
            return null
        }
        val nextHop = unpackAddress(row.getInt(12))
        val ifIndex = row.getInt(16)
        val type = row.getInt(20)          // 3 = direct (on-link), 4 = indirect (via gateway)
        if (ifIndex == 0) return null
        return ifIndex to (if (type == 3) null else nextHop)
    }

    /**
     * The IPv4 DNS servers of interface [ifIndex]: the static list if one is
     * set, else what DHCP handed out. From the registry, which is the same
     * in every Windows language; `netsh` output is not.
     */
    fun dnsServers(ifIndex: Int): List<String> {
        val guid = interfaceGuid(ifIndex)
        if (guid != null) {
            val key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$guid"
            for (value in listOf("NameServer", "DhcpNameServer")) {
                val text = runCatching {
                    if (Advapi32Util.registryValueExists(WinReg.HKEY_LOCAL_MACHINE, key, value))
                        Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, key, value) else null
                }.getOrNull()
                val servers = text?.let { ipv4Literal.findAll(it).map { m -> m.value }.toList() }.orEmpty()
                if (servers.isNotEmpty()) return servers
            }
        }
        // Fallback: whatever netsh prints, in any language, contains the literals.
        val output = run(listOf("netsh", "interface", "ipv4", "show", "dnsservers", "name=$ifIndex")).output
        return ipv4Literal.findAll(output).map { it.value }.filter { it != "0.0.0.0" }.distinct().toList()
    }

    /** The `{GUID}` of interface [ifIndex], as the registry keys it. */
    fun interfaceGuid(ifIndex: Int): String? = runCatching {
        val luid = LongByReference()
        if (IpHlpApiLib.INSTANCE.ConvertInterfaceIndexToLuid(ifIndex, luid) != 0) return null
        val guid = com.sun.jna.platform.win32.Guid.GUID()
        if (IpHlpApiLib.INSTANCE.ConvertInterfaceLuidToGuid(luid, guid.pointer) != 0) return null
        guid.read()
        guid.toGuidString()
    }.getOrNull()

    /** The result of one external command. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
    }

    /**
     * Runs [argv] hidden, waiting at most [timeoutSec]; the output is for the
     * log. A tool still running at the deadline is killed and the result is
     * a failure.
     *
     * The output is drained on a thread of its own: reading it here blocked
     * until the tool closed its end, so a hung `netsh` never got as far as
     * the timeout and held TUN start (and its locks) for good.
     */
    fun run(argv: List<String>, timeoutSec: Long = 20): Result {
        val process = try {
            ProcessBuilder(argv).redirectErrorStream(true).start()
        } catch (e: Exception) {
            return Result(-1, e.message ?: e.toString())
        }
        runCatching { process.outputStream.close() }
        val output = ByteArrayOutputStream()
        val drain = Thread({
            runCatching { process.inputStream.use { it.copyTo(output) } }
        }, "command-output").apply {
            isDaemon = true
            start()
        }
        val finished = try {
            process.waitFor(timeoutSec, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!finished) {
            process.destroyForcibly()
            logger.warning("Timed out after $timeoutSec s: ${argv.joinToString(" ")}")
            return Result(-1, "timed out: ${argv.joinToString(" ")}")
        }
        // The pipe only ends once everything holding it has let go; a child
        // the tool left running in the background must not hold this up.
        try {
            drain.join(OUTPUT_DRAIN_MS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        return Result(process.exitValue(), String(output.toByteArray(), consoleCharset).trim())
    }

    private const val OUTPUT_DRAIN_MS = 2_000L

    @Suppress("FunctionName")
    private interface Kernel32Ex : com.sun.jna.win32.StdCallLibrary {
        fun GetOEMCP(): Int
    }

    /**
     * The console (OEM) code page the tools write in, so their output reads
     * correctly on a localised Windows. The system's, from the registry:
     * this process runs with UTF-8 as its own code page (the launcher's
     * manifest), so GetOEMCP here says 65001 while netsh and route, which
     * have no such manifest, still write in the system's.
     */
    private val consoleCharset: java.nio.charset.Charset by lazy {
        val fromRegistry = runCatching {
            Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage", "OEMCP")
                .trim().toIntOrNull()
        }.getOrNull()
        val cp = fromRegistry ?: runCatching { com.sun.jna.Native.load("kernel32", Kernel32Ex::class.java).GetOEMCP() }.getOrNull()
        cp?.takeIf { it > 0 }?.let { runCatching { java.nio.charset.Charset.forName(if (it == 65001) "UTF-8" else "cp$it") }.getOrNull() }
            ?: runCatching { java.nio.charset.Charset.forName("cp866") }.getOrNull() ?: Charsets.UTF_8
    }

    /** The SID of [file]'s owner (`S-1-5-18` for SYSTEM), or null when it cannot be read. */
    fun fileOwnerSid(file: java.io.File): String? = runCatching {
        val descriptor = Advapi32Util.getFileSecurityDescriptor(file, false)
        Advapi32Util.convertSidToStringSid(descriptor.owner)
    }.getOrNull()

    /** The SID of the account this process runs as, or null off Windows. */
    val currentUserSid: String? by lazy {
        if (!isWindows) return@lazy null
        runCatching {
            val token = com.sun.jna.platform.win32.WinNT.HANDLEByReference()
            val process = com.sun.jna.platform.win32.Kernel32.INSTANCE.GetCurrentProcess()
            if (!com.sun.jna.platform.win32.Advapi32.INSTANCE.OpenProcessToken(process, com.sun.jna.platform.win32.WinNT.TOKEN_QUERY, token)) return@runCatching null
            try {
                Advapi32Util.getTokenAccount(token.value).sidString
            } finally {
                com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(token.value)
            }
        }.getOrNull()
    }

    /** Resolves [host] to IPv4 literals, through the app's own cache (which is on the physical network once set). */
    fun resolveV4(host: String): List<String> {
        if (DnsCache.isIpAddress(host)) return if (host.contains(':')) emptyList() else listOf(host)
        return runCatching { DnsCache.resolveAll(host) }.getOrDefault(emptyList()).filterNot { it.contains(':') }
    }

    /** `in_addr` as `GetBestRoute` wants it: the four bytes in memory order. */
    internal fun packAddress(bytes: ByteArray): Int =
        (bytes[0].toInt() and 0xFF) or ((bytes[1].toInt() and 0xFF) shl 8) or
            ((bytes[2].toInt() and 0xFF) shl 16) or ((bytes[3].toInt() and 0xFF) shl 24)

    internal fun unpackAddress(packed: Int): String =
        "${packed and 0xFF}.${(packed ushr 8) and 0xFF}.${(packed ushr 16) and 0xFF}.${(packed ushr 24) and 0xFF}"
}
