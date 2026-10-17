package com.mythaia.desktop.engine

import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.Platform
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The system-wide proxy setting, which browsers and most apps read: the
 * per-user Internet Settings on Windows, every network service's web, secure
 * web and SOCKS proxy on macOS.
 *
 * What was there before is snapshotted to disk the first time it is
 * replaced and restored on disconnect, so a crash cannot leave the user with
 * a dead proxy after a reboot: the next start restores it too.
 */
object SystemProxy {
    val isWindows: Boolean get() = Platform.isWindows

    /**
     * Points the system at the local listeners: [httpServer] (host:port) for
     * HTTP and HTTPS, [socksServer] for SOCKS where the system has a separate
     * setting for it. [bypass] is the exception list in the Windows format
     * (`a;b;<local>`); macOS gets it translated.
     */
    fun enable(httpServer: String, bypass: String, socksServer: String? = null) {
        when {
            Platform.isWindows -> WindowsSystemProxy.enable(httpServer, bypass)
            Platform.isMac -> MacSystemProxy.enable(httpServer, socksServer, bypass)
        }
    }

    /** Puts back what was there before [enable], or simply turns the proxy off. */
    fun restore() {
        when {
            Platform.isWindows -> WindowsSystemProxy.restore()
            Platform.isMac -> MacSystemProxy.restore()
        }
    }

    /** On start: a snapshot left behind means the last run did not get to restore. */
    fun restoreIfLeftOver() {
        if (AppPaths.proxySnapshot.isFile) restore()
    }
}

/**
 * The Windows per-user proxy (what Edge, Chrome, WinHTTP-using apps and the
 * system itself read). Set through the registry and announced with
 * WinINet's settings-changed notification so browsers pick it up at once.
 */
internal object WindowsSystemProxy {
    private val logger = MythaiaLogger("SystemProxy")
    private const val KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    private const val INTERNET_OPTION_REFRESH = 37
    private const val INTERNET_OPTION_SETTINGS_CHANGED = 39

    @Serializable
    data class Snapshot(val enable: Int, val server: String?, val override: String?)

    @Suppress("FunctionName")
    private interface WinInet : Library {
        fun InternetSetOptionW(hInternet: Pointer?, option: Int, buffer: Pointer?, length: Int): Boolean
    }

    private val winInet: WinInet? by lazy {
        runCatching { Native.load("wininet", WinInet::class.java) }
            .onFailure { logger.warning("wininet unavailable: ${it.message}") }
            .getOrNull()
    }

    private val json = Json { ignoreUnknownKeys = true }

    fun current(): Snapshot? = runCatching {
        Snapshot(
            enable = intValue("ProxyEnable") ?: 0,
            server = stringValue("ProxyServer"),
            override = stringValue("ProxyOverride")
        )
    }.getOrNull()

    fun enable(server: String, bypass: String) {
        try {
            if (!AppPaths.proxySnapshot.exists()) {
                current()?.let { AppPaths.proxySnapshot.writeText(json.encodeToString(Snapshot.serializer(), it)) }
            }
            Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 1)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", server)
            Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", bypass)
            announceChange()
            logger.info("System proxy set to $server")
        } catch (e: Exception) {
            logger.error("Could not set the system proxy: ${e.message}")
        }
    }

    fun restore() {
        try {
            val snapshot = AppPaths.proxySnapshot.takeIf { it.isFile }
                ?.let { runCatching { json.decodeFromString(Snapshot.serializer(), it.readText()) }.getOrNull() }
            // The user's own server and exception strings go back whether or
            // not their proxy was switched on: a disabled corporate proxy is
            // still theirs to keep.
            if (snapshot != null) {
                snapshot.server?.let { Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyServer", it) }
                snapshot.override?.let { Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyOverride", it) }
                val enable = if (snapshot.enable == 1 && !snapshot.server.isNullOrBlank()) 1 else 0
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", enable)
            } else {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, KEY, "ProxyEnable", 0)
            }
            announceChange()
            AppPaths.proxySnapshot.delete()
            logger.info("System proxy restored")
        } catch (e: Exception) {
            logger.error("Could not restore the system proxy: ${e.message}")
        }
    }

    private fun announceChange() {
        val lib = winInet ?: return
        lib.InternetSetOptionW(null, INTERNET_OPTION_SETTINGS_CHANGED, null, 0)
        lib.InternetSetOptionW(null, INTERNET_OPTION_REFRESH, null, 0)
    }

    private fun intValue(name: String): Int? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, KEY, name))
            Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, KEY, name) else null

    private fun stringValue(name: String): String? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, KEY, name))
            Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, KEY, name) else null
}

/**
 * The macOS proxy settings, per network service (Wi-Fi, Ethernet, a USB
 * modem ...), through `networksetup`. Every enabled service gets the same
 * three proxies, since the one in use can change under a running app (the
 * user plugs in a cable).
 *
 * `networksetup` changes the system preferences; an administrator account
 * may do that without a prompt, a standard account may not. When a direct
 * run is refused, the same commands run once more through `osascript ...
 * with administrator privileges`, which asks for the password a single time.
 */
internal object MacSystemProxy {
    private val logger = MythaiaLogger("SystemProxy")
    private const val NETWORKSETUP = "/usr/sbin/networksetup"
    private val json = Json { ignoreUnknownKeys = true }
    private val partialOctet = Regex("""^(\d{1,3}(?:\.\d{1,3}){0,2})\.(\d)\*$""")

    @Serializable
    data class Entry(val enabled: Boolean, val server: String, val port: Int)

    @Serializable
    data class ServiceSettings(
        val service: String,
        val web: Entry,
        val secureWeb: Entry,
        val socks: Entry,
        val bypass: List<String>
    )

    @Serializable
    data class Snapshot(val services: List<ServiceSettings>)

    fun enable(httpServer: String, socksServer: String?, bypass: String) {
        try {
            val services = services()
            if (services.isEmpty()) {
                logger.warning("No network services to set a proxy on")
                return
            }
            if (!AppPaths.proxySnapshot.exists()) {
                val snapshot = Snapshot(services.map { read(it) })
                AppPaths.proxySnapshot.writeText(json.encodeToString(Snapshot.serializer(), snapshot))
            }
            run(enableCommands(services, httpServer, socksServer, bypass))
            logger.info("System proxy set to $httpServer on ${services.joinToString()}")
        } catch (e: Exception) {
            logger.error("Could not set the system proxy: ${e.message}")
        }
    }

    internal fun enableCommands(
        services: List<String>,
        httpServer: String,
        socksServer: String?,
        bypass: String
    ): List<List<String>> {
        val (httpHost, httpPort) = split(httpServer)
        val socks = socksServer?.let { split(it) }
        val domains = bypassDomains(bypass).ifEmpty { listOf("Empty") }
        return services.flatMap { service ->
            buildList {
                add(listOf("-setwebproxy", service, httpHost, httpPort.toString(), "off"))
                add(listOf("-setsecurewebproxy", service, httpHost, httpPort.toString(), "off"))
                if (socks != null) {
                    add(listOf("-setsocksfirewallproxy", service, socks.first, socks.second.toString(), "off"))
                }
                add(listOf("-setproxybypassdomains", service) + domains)
            }
        }
    }

    fun restore() {
        try {
            val snapshot = AppPaths.proxySnapshot.takeIf { it.isFile }
                ?.let { runCatching { json.decodeFromString(Snapshot.serializer(), it.readText()) }.getOrNull() }
            val present = services().toSet()
            val commands = if (snapshot != null) {
                snapshot.services.filter { it.service in present }.flatMap { restoreCommands(it) }
            } else {
                // Nothing remembered: at least do not leave our proxy behind.
                present.flatMap { service ->
                    listOf(
                        listOf("-setwebproxystate", service, "off"),
                        listOf("-setsecurewebproxystate", service, "off"),
                        listOf("-setsocksfirewallproxystate", service, "off")
                    )
                }
            }
            if (commands.isNotEmpty()) run(commands)
            AppPaths.proxySnapshot.delete()
            logger.info("System proxy restored")
        } catch (e: Exception) {
            logger.error("Could not restore the system proxy: ${e.message}")
        }
    }

    internal fun restoreCommands(saved: ServiceSettings): List<List<String>> = buildList {
        addAll(entryCommands("-setwebproxy", "-setwebproxystate", saved.service, saved.web))
        addAll(entryCommands("-setsecurewebproxy", "-setsecurewebproxystate", saved.service, saved.secureWeb))
        addAll(entryCommands("-setsocksfirewallproxy", "-setsocksfirewallproxystate", saved.service, saved.socks))
        add(listOf("-setproxybypassdomains", saved.service) + saved.bypass.ifEmpty { listOf("Empty") })
    }

    /** The user's own server goes back even when it was switched off, then its on/off state. */
    private fun entryCommands(set: String, state: String, service: String, entry: Entry): List<List<String>> = buildList {
        if (entry.server.isNotBlank() && entry.port > 0) {
            add(listOf(set, service, entry.server, entry.port.toString(), "off"))
        }
        add(listOf(state, service, if (entry.enabled && entry.server.isNotBlank()) "on" else "off"))
    }

    /** The enabled network services; `networksetup` marks disabled ones with a leading `*`. */
    fun services(): List<String> = parseServices(exec(listOf("-listallnetworkservices")))

    internal fun parseServices(text: String?): List<String> =
        text.orEmpty().lines()
            .map { it.trim() }
            // The first line explains the asterisk: "An asterisk (*) denotes ...".
            .filter { it.isNotEmpty() && !it.startsWith("*") && !it.startsWith("An asterisk") }

    private fun read(service: String): ServiceSettings = ServiceSettings(
        service = service,
        web = parseEntry(exec(listOf("-getwebproxy", service))),
        secureWeb = parseEntry(exec(listOf("-getsecurewebproxy", service))),
        socks = parseEntry(exec(listOf("-getsocksfirewallproxy", service))),
        bypass = parseBypass(exec(listOf("-getproxybypassdomains", service)))
    )

    /** `Enabled: Yes / Server: 127.0.0.1 / Port: 8080 / Authenticated Proxy Enabled: 0`. */
    internal fun parseEntry(text: String?): Entry {
        val fields = text.orEmpty().lines().mapNotNull { line ->
            val i = line.indexOf(':')
            if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
        }.toMap()
        return Entry(
            enabled = fields["Enabled"].equals("Yes", ignoreCase = true),
            server = fields["Server"].orEmpty(),
            port = fields["Port"]?.toIntOrNull() ?: 0
        )
    }

    /** One domain per line, or a sentence saying there are none. */
    internal fun parseBypass(text: String?): List<String> =
        text.orEmpty().lines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.contains(' ') }

    /**
     * The Windows exception list in macOS terms: `<local>` becomes plain
     * names and link-local addresses, `10.*` style wildcards become CIDR
     * blocks (the form the macOS list understands for addresses), names stay.
     */
    internal fun bypassDomains(bypass: String): List<String> {
        val out = LinkedHashSet<String>()
        for (raw in bypass.split(';', ',', ' ', '\n', '\t')) {
            val item = raw.trim()
            if (item.isEmpty()) continue
            val wholeOctets = item.removeSuffix(".*").split('.')
            val partial = partialOctet.find(item)
            when {
                item.equals("<local>", ignoreCase = true) -> {
                    out += "*.local"
                    out += "169.254/16"
                }
                item.endsWith(".*") && wholeOctets.size in 1..3 && wholeOctets.all { (it.toIntOrNull() ?: -1) in 0..255 } ->
                    out += cidr(wholeOctets)
                // "172.2*": a partial last octet, here 172.20 to 172.29.
                partial != null -> {
                    val head = partial.groupValues[1].split('.')
                    val digit = partial.groupValues[2]
                    val octets = (0..9).map { "$digit$it" }
                    for (octet in octets) {
                        if ((octet.toIntOrNull() ?: 256) > 255 || head.size + 1 > 3) continue
                        out += cidr(head + octet)
                    }
                }
                else -> out += item
            }
        }
        return out.toList()
    }

    private fun cidr(octets: List<String>): String =
        (octets + List(4 - octets.size) { "0" }).joinToString(".") + "/" + (octets.size * 8)

    private fun split(server: String): Pair<String, Int> {
        val host = server.substringBeforeLast(':')
        val port = server.substringAfterLast(':').toIntOrNull() ?: 0
        return host to port
    }

    /** Runs the commands directly; if the system refuses, runs them all again as administrator. */
    private fun run(commands: List<List<String>>) {
        val refused = commands.any { command ->
            val result = execResult(command)
            result == null || result.first != 0
        }
        if (!refused) return
        logger.info("networksetup needs administrator rights; asking once")
        val script = commands.joinToString(" && ") { command ->
            (listOf(NETWORKSETUP) + command).joinToString(" ") { shellQuote(it) }
        }
        val apple = "do shell script \"" + script.replace("\\", "\\\\").replace("\"", "\\\"") +
            "\" with administrator privileges"
        val process = ProcessBuilder("/usr/bin/osascript", "-e", apple).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            throw IllegalStateException("the administrator prompt timed out")
        }
        if (process.exitValue() != 0) throw IllegalStateException(output.trim().ifEmpty { "declined" })
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun exec(args: List<String>): String? = execResult(args)?.takeIf { it.first == 0 }?.second

    private fun execResult(args: List<String>): Pair<Int, String>? = try {
        val process = ProcessBuilder(listOf(NETWORKSETUP) + args).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        if (!process.waitFor(15, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            null
        } else {
            // networksetup prints a refusal and may still exit with 0.
            val code = if (output.contains("requires admin", ignoreCase = true)) 14 else process.exitValue()
            code to output
        }
    } catch (e: Exception) {
        logger.warning("networksetup ${args.firstOrNull()}: ${e.message}")
        null
    }
}

/** Starts the app with the user's session: the `Run` key on Windows, a LaunchAgent on macOS. */
object LaunchAtLogin {
    private const val RUN_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    private const val VALUE = "Mythaia Pro"
    private const val AGENT_LABEL = "com.mythaia.desktop"
    private val logger = MythaiaLogger("LaunchAtLogin")

    private val agentFile: File
        get() = File(System.getProperty("user.home"), "Library/LaunchAgents/$AGENT_LABEL.plist")

    fun isEnabled(): Boolean = when {
        Platform.isWindows -> runCatching {
            Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE)
        }.getOrDefault(false)
        Platform.isMac -> agentFile.isFile
        else -> false
    }

    /** Returns false when there is no installed launcher to point the entry at. */
    fun set(enabled: Boolean): Boolean = when {
        Platform.isWindows -> setWindows(enabled)
        Platform.isMac -> setMac(enabled)
        else -> false
    }

    private fun setWindows(enabled: Boolean): Boolean = try {
        if (enabled) {
            val exe = AppPaths.launcherExe()
            if (exe == null) {
                false
            } else {
                Advapi32Util.registrySetStringValue(
                    WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE, "\"${exe.absolutePath}\" --minimized"
                )
                true
            }
        } else {
            if (isEnabled()) Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, RUN_KEY, VALUE)
            true
        }
    } catch (e: Exception) {
        logger.error("Run key: ${e.message}")
        false
    }

    private fun setMac(enabled: Boolean): Boolean = try {
        if (enabled) {
            val exe = AppPaths.launcherExe()
            if (exe == null) {
                false
            } else {
                agentFile.parentFile.mkdirs()
                agentFile.writeText(launchAgentPlist(exe.absolutePath))
                true
            }
        } else {
            agentFile.delete()
            true
        }
    } catch (e: Exception) {
        logger.error("LaunchAgent: ${e.message}")
        false
    }

    internal fun launchAgentPlist(executable: String): String {
        val path = executable.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return """
            |<?xml version="1.0" encoding="UTF-8"?>
            |<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            |<plist version="1.0">
            |<dict>
            |    <key>Label</key>
            |    <string>$AGENT_LABEL</string>
            |    <key>ProgramArguments</key>
            |    <array>
            |        <string>$path</string>
            |        <string>--minimized</string>
            |    </array>
            |    <key>RunAtLoad</key>
            |    <true/>
            |    <key>ProcessType</key>
            |    <string>Interactive</string>
            |</dict>
            |</plist>
            |""".trimMargin()
    }
}
