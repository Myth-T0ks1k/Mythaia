package com.mythaia.desktop.engine

import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import kotlinx.serialization.Serializable
import java.lang.ref.Reference

/**
 * WinINet's proxy options of one connection. The LAN options are what
 * [SystemProxy] writes to the registry; a PC online through a dial-up,
 * PPPoE or VPN connection from the phonebook uses that connection's own
 * options instead, which only `InternetSetOption` with
 * `INTERNET_OPTION_PER_CONNECTION_OPTION` reaches. Without them, proxy
 * mode did nothing on such a PC.
 */
object PerConnectionProxy {
    private val logger = MythaiaLogger("SystemProxy")

    const val PROXY_TYPE_DIRECT = 0x1
    const val PROXY_TYPE_PROXY = 0x2

    /** A connection's proxy options: what it has, or what it is to get back. */
    @Serializable
    data class Options(val flags: Int, val server: String? = null, val bypass: String? = null) {
        fun pointsAt(proxy: String): Boolean = (flags and PROXY_TYPE_PROXY) != 0 && server == proxy
    }

    /**
     * Only the local proxy, nothing automatic: a PAC script or WPAD on the
     * connection would otherwise decide instead, and the mode would again
     * quietly do nothing. What the connection had goes back on restore.
     */
    fun proxied(server: String, bypass: String) = Options(PROXY_TYPE_DIRECT or PROXY_TYPE_PROXY, server, bypass)

    /** What to put back for a connection whose options are [current]: nothing of ours, ever. */
    fun before(current: Options, proxy: String): Options =
        if (current.pointsAt(proxy)) Options(PROXY_TYPE_DIRECT) else current

    private const val INTERNET_OPTION_PER_CONNECTION_OPTION = 75
    private const val INTERNET_PER_CONN_FLAGS = 1
    private const val INTERNET_PER_CONN_PROXY_SERVER = 2
    private const val INTERNET_PER_CONN_PROXY_BYPASS = 3
    /** What the settings dialog shows, auto-detect included; Windows 7 and later read it, and restore through [INTERNET_PER_CONN_FLAGS]. */
    private const val INTERNET_PER_CONN_FLAGS_UI = 10

    /*
     * INTERNET_PER_CONN_OPTIONW is { DWORD dwOption; union { DWORD; LPWSTR;
     * FILETIME } Value }: the union sits at the pointer's alignment.
     * INTERNET_PER_CONN_OPTION_LISTW is { DWORD dwSize; LPWSTR pszConnection;
     * DWORD dwOptionCount; DWORD dwOptionError; LPINTERNET_PER_CONN_OPTIONW
     * pOptions }. Laid out by hand: a JNA union of a pointer and a FILETIME
     * is more trouble than four offsets.
     */
    private val pointer = Native.POINTER_SIZE
    private val optionSize = if (pointer == 8) 16 else 12
    private val valueOffset = pointer.toLong()
    private val listSize = pointer * 3 + 8
    private val listConnectionOffset = pointer.toLong()
    private val listCountOffset = pointer * 2L
    private val listOptionsOffset = pointer * 2L + 8

    /** sizeof(RASENTRYNAMEW) for Windows 2000 and later: name, flags and phonebook path. */
    private const val RAS_ENTRY_NAME_SIZE = 1048
    private const val ERROR_BUFFER_TOO_SMALL = 603

    @Suppress("FunctionName")
    private interface WinInet : StdCallLibrary {
        fun InternetSetOptionW(hInternet: Pointer?, option: Int, buffer: Pointer?, length: Int): Boolean
        fun InternetQueryOptionW(hInternet: Pointer?, option: Int, buffer: Pointer?, length: IntByReference): Boolean
    }

    @Suppress("FunctionName")
    private interface RasApi : StdCallLibrary {
        fun RasEnumEntriesW(reserved: Pointer?, phonebook: Pointer?, entries: Pointer, size: IntByReference, count: IntByReference): Int
    }

    private val winInet: WinInet? by lazy {
        runCatching { Native.load("wininet", WinInet::class.java) }
            .onFailure { logger.warning("wininet unavailable: ${it.message}") }
            .getOrNull()
    }

    private val rasApi: RasApi? by lazy {
        runCatching { Native.load("rasapi32", RasApi::class.java) }
            .onFailure { logger.warning("rasapi32 unavailable: ${it.message}") }
            .getOrNull()
    }

    /**
     * The dial-up, PPPoE and VPN connections in the phonebooks, this user's
     * and everyone's; null when they could not be listed.
     */
    fun connectionNames(): List<String>? {
        val ras = rasApi ?: return null
        var bytes = RAS_ENTRY_NAME_SIZE * 8
        repeat(3) {
            val buffer = Memory(bytes.toLong()).apply { clear() }
            buffer.setInt(0, RAS_ENTRY_NAME_SIZE)
            val size = IntByReference(bytes)
            val count = IntByReference(0)
            when (val rc = ras.RasEnumEntriesW(null, null, buffer, size, count)) {
                0 -> return (0 until count.value)
                    .map { buffer.getWideString(it.toLong() * RAS_ENTRY_NAME_SIZE + 4) }
                    .filter { it.isNotEmpty() }
                    .distinct()
                ERROR_BUFFER_TOO_SMALL -> bytes = maxOf(size.value, bytes * 2)
                else -> {
                    logger.warning("Dial-up connections could not be listed: RasEnumEntries $rc")
                    return null
                }
            }
        }
        return null
    }

    /** The options of [connection] (null: the LAN), or null when WinINet would not say. */
    fun query(connection: String?): Options? {
        val lib = winInet ?: return null
        for (flagsOption in intArrayOf(INTERNET_PER_CONN_FLAGS_UI, INTERNET_PER_CONN_FLAGS)) {
            val options = Memory(optionSize * 3L).apply { clear() }
            options.setInt(0, flagsOption)
            options.setInt(optionSize.toLong(), INTERNET_PER_CONN_PROXY_SERVER)
            options.setInt(optionSize * 2L, INTERNET_PER_CONN_PROXY_BYPASS)
            val name = connection?.let(::wide)
            val list = list(name, options, 3)
            val ok = lib.InternetQueryOptionW(null, INTERNET_OPTION_PER_CONNECTION_OPTION, list, IntByReference(listSize))
            Reference.reachabilityFence(name)
            if (!ok) continue
            // WinINet allocated the strings; they are the caller's to free.
            return Options(
                flags = options.getInt(valueOffset),
                server = takeString(options.getPointer(optionSize + valueOffset)),
                bypass = takeString(options.getPointer(optionSize * 2 + valueOffset))
            )
        }
        return null
    }

    /** Gives [connection] these [options]; false when WinINet refused. */
    fun set(connection: String?, options: Options): Boolean {
        val lib = winInet ?: return false
        val server = wide(options.server.orEmpty())
        val bypass = wide(options.bypass.orEmpty())
        val entries = Memory(optionSize * 3L).apply { clear() }
        entries.setInt(0, INTERNET_PER_CONN_FLAGS)
        entries.setInt(valueOffset, options.flags)
        entries.setInt(optionSize.toLong(), INTERNET_PER_CONN_PROXY_SERVER)
        entries.setPointer(optionSize + valueOffset, server)
        entries.setInt(optionSize * 2L, INTERNET_PER_CONN_PROXY_BYPASS)
        entries.setPointer(optionSize * 2 + valueOffset, bypass)
        val name = connection?.let(::wide)
        val ok = lib.InternetSetOptionW(null, INTERNET_OPTION_PER_CONNECTION_OPTION, list(name, entries, 3), listSize)
        // The list holds these by address only.
        Reference.reachabilityFence(name)
        Reference.reachabilityFence(entries)
        Reference.reachabilityFence(server)
        Reference.reachabilityFence(bypass)
        if (!ok) logger.warning("Proxy options of ${connection ?: "the LAN"} not set: error ${Native.getLastError()}")
        return ok
    }

    private fun list(connection: Memory?, options: Memory, count: Int): Memory =
        Memory(listSize.toLong()).apply {
            clear()
            setInt(0, listSize)
            setPointer(listConnectionOffset, connection)
            setInt(listCountOffset, count)
            setPointer(listOptionsOffset, options)
        }

    private fun wide(text: String): Memory =
        Memory((text.length + 1) * 2L).apply { setWideString(0, text) }

    private fun takeString(p: Pointer?): String? {
        if (p == null) return null
        return try {
            p.getWideString(0).takeIf { it.isNotEmpty() }
        } finally {
            runCatching { Kernel32.INSTANCE.GlobalFree(p) }
        }
    }
}
