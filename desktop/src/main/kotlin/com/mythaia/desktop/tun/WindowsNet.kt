package com.mythaia.desktop.tun

import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Memory
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import com.sun.jna.ptr.LongByReference
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.TimeUnit

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

    /** Runs [argv] hidden, waiting at most [timeoutSec]; the output is for the log. */
    fun run(argv: List<String>, timeoutSec: Long = 20): Result {
        return try {
            val process = ProcessBuilder(argv).redirectErrorStream(true).start()
            runCatching { process.outputStream.close() }
            val output = process.inputStream.use { String(it.readBytes(), consoleCharset) }
            if (!process.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                Result(-1, "timed out: ${argv.joinToString(" ")}")
            } else Result(process.exitValue(), output.trim())
        } catch (e: Exception) {
            Result(-1, e.message ?: e.toString())
        }
    }

    @Suppress("FunctionName")
    private interface Kernel32Ex : com.sun.jna.win32.StdCallLibrary {
        fun GetOEMCP(): Int
    }

    /** The console (OEM) code page, so tool output reads correctly on a localised Windows. */
    private val consoleCharset: java.nio.charset.Charset by lazy {
        runCatching {
            val cp = com.sun.jna.Native.load("kernel32", Kernel32Ex::class.java).GetOEMCP()
            if (cp > 0) java.nio.charset.Charset.forName("cp$cp") else null
        }.getOrNull() ?: runCatching { java.nio.charset.Charset.forName("cp866") }.getOrNull() ?: Charsets.UTF_8
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
    fun resolveV4(host: String): List<String> = PhysicalNet.resolveV4(host)

    /** `in_addr` as `GetBestRoute` wants it: the four bytes in memory order. */
    internal fun packAddress(bytes: ByteArray): Int =
        (bytes[0].toInt() and 0xFF) or ((bytes[1].toInt() and 0xFF) shl 8) or
            ((bytes[2].toInt() and 0xFF) shl 16) or ((bytes[3].toInt() and 0xFF) shl 24)

    internal fun unpackAddress(packed: Int): String =
        "${packed and 0xFF}.${(packed ushr 8) and 0xFF}.${(packed ushr 16) and 0xFF}.${(packed ushr 24) and 0xFF}"
}
