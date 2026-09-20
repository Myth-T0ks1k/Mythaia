package com.mythaia.desktop.tun

import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Guid
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.LongByReference
import java.io.File
import java.io.IOException

/**
 * `wintun.dll` as JNA sees it (Wintun 0.14 API). Every function is
 * `WINAPI`, which on x64 is the one calling convention there is.
 */
@Suppress("FunctionName")
internal interface WintunLib : Library {
    fun WintunCreateAdapter(name: WString, tunnelType: WString, requestedGuid: Pointer?): Pointer?
    fun WintunOpenAdapter(name: WString): Pointer?
    fun WintunCloseAdapter(adapter: Pointer?)
    fun WintunDeleteDriver(): Boolean
    fun WintunGetAdapterLUID(adapter: Pointer?, luid: LongByReference)
    fun WintunGetRunningDriverVersion(): Int
    fun WintunSetLogger(logger: LoggerCallback?)
    fun WintunStartSession(adapter: Pointer?, capacity: Int): Pointer?
    fun WintunEndSession(session: Pointer?)
    fun WintunGetReadWaitEvent(session: Pointer?): Pointer?
    fun WintunReceivePacket(session: Pointer?, packetSize: IntByReference): Pointer?
    fun WintunReleaseReceivePacket(session: Pointer?, packet: Pointer?)
    fun WintunAllocateSendPacket(session: Pointer?, packetSize: Int): Pointer?
    fun WintunSendPacket(session: Pointer?, packet: Pointer?)

    /** `VOID CALLBACK (WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message)`. */
    interface LoggerCallback : Callback {
        fun invoke(level: Int, timestamp: Long, message: Pointer?)
    }
}

/** `iphlpapi.dll`: the LUID Wintun reports, turned into the index `netsh` and `route` take. */
@Suppress("FunctionName")
internal interface IpHlpApiLib : Library {
    fun ConvertInterfaceLuidToIndex(luid: LongByReference, index: IntByReference): Int
    fun ConvertInterfaceIndexToLuid(index: Int, luid: LongByReference): Int
    fun ConvertInterfaceLuidToGuid(luid: LongByReference, guid: Pointer): Int

    /** `GetBestRoute(DWORD dest, DWORD src, PMIB_IPFORWARDROW)`; the row is 14 DWORDs. */
    fun GetBestRoute(destAddress: Int, sourceAddress: Int, bestRoute: Pointer): Int

    companion object {
        val INSTANCE: IpHlpApiLib by lazy { Native.load("iphlpapi", IpHlpApiLib::class.java) }
    }
}

/**
 * One Wintun adapter: created by name, gone again when [close] is called
 * (or the process dies — the driver deletes orphans). Packets flow through
 * a [Session].
 */
class WintunAdapter private constructor(
    private val lib: WintunLib,
    private var handle: Pointer?,
    val name: String
) {
    /** The NET_LUID Windows knows the adapter by. */
    val luid: Long

    init {
        val ref = LongByReference()
        lib.WintunGetAdapterLUID(handle, ref)
        luid = ref.value
    }

    /**
     * The interface index, which `netsh` and `route` address the adapter
     * by. The mapping can lag adapter creation by a moment, so this retries
     * briefly before giving up.
     */
    fun interfaceIndex(): Int {
        val luidRef = LongByReference(luid)
        val index = IntByReference()
        var attempt = 0
        while (true) {
            val status = IpHlpApiLib.INSTANCE.ConvertInterfaceLuidToIndex(luidRef, index)
            if (status == 0 && index.value != 0) return index.value
            if (++attempt >= 20) throw IOException("Wintun adapter has no interface index (status $status)")
            Thread.sleep(250)
        }
    }

    /** Starts packet exchange with a ring of [capacity] bytes (128 KiB … 64 MiB, power of two). */
    fun startSession(capacity: Int = DEFAULT_RING_CAPACITY): Session {
        val h = handle ?: throw IOException("adapter is closed")
        val session = lib.WintunStartSession(h, capacity)
            ?: throw IOException("WintunStartSession failed: ${lastErrorMessage()}")
        return Session(session)
    }

    /** Removes the adapter from the system. Idempotent. */
    fun close() {
        val h = handle ?: return
        handle = null
        runCatching { lib.WintunCloseAdapter(h) }
            .onFailure { logger.warning("WintunCloseAdapter: ${it.message}") }
    }

    /**
     * A running session. Reads happen on whichever thread calls [readLoop];
     * [send] may be called from one thread at a time (the lwIP thread).
     */
    inner class Session internal constructor(private var session: Pointer?) {
        private val readEvent: WinNT.HANDLE? = session?.let { lib.WintunGetReadWaitEvent(it) }?.let { WinNT.HANDLE(it) }
        @Volatile
        private var open = true
        private val sendLock = Any()

        val isOpen: Boolean get() = open

        /**
         * Receives packets until [keepRunning] returns false or the session
         * ends. Packets are handed over in batches of up to [batchSize],
         * each array holding exactly one IP packet.
         */
        fun readLoop(keepRunning: () -> Boolean, batchSize: Int = 64, onBatch: (List<ByteArray>) -> Unit) {
            val size = IntByReference()
            val batch = ArrayList<ByteArray>(batchSize)
            while (keepRunning() && open) {
                val s = session ?: break
                val packet = lib.WintunReceivePacket(s, size)
                if (packet != null) {
                    val n = size.value
                    if (n in 1..MAX_PACKET_SIZE) batch.add(packet.getByteArray(0, n))
                    lib.WintunReleaseReceivePacket(s, packet)
                    if (batch.size >= batchSize) {
                        onBatch(ArrayList(batch))
                        batch.clear()
                    }
                    continue
                }
                if (batch.isNotEmpty()) {
                    onBatch(ArrayList(batch))
                    batch.clear()
                }
                when (val error = Native.getLastError()) {
                    ERROR_NO_MORE_ITEMS -> {
                        val event = readEvent ?: break
                        Kernel32.INSTANCE.WaitForSingleObject(event, READ_WAIT_MS)
                    }
                    ERROR_HANDLE_EOF -> break
                    else -> {
                        logger.warning("WintunReceivePacket failed: error $error")
                        break
                    }
                }
            }
            if (batch.isNotEmpty()) onBatch(ArrayList(batch))
        }

        /** Queues one packet for the OS; a full ring drops it, as a NIC would. Returns false when dropped. */
        fun send(packet: ByteArray, length: Int): Boolean {
            if (!open || length <= 0 || length > MAX_PACKET_SIZE) return false
            synchronized(sendLock) {
                val s = session ?: return false
                val buffer = lib.WintunAllocateSendPacket(s, length) ?: return false
                buffer.write(0, packet, 0, length)
                lib.WintunSendPacket(s, buffer)
                return true
            }
        }

        fun end() {
            if (!open) return
            open = false
            synchronized(sendLock) {
                val s = session ?: return
                session = null
                runCatching { lib.WintunEndSession(s) }
                    .onFailure { logger.warning("WintunEndSession: ${it.message}") }
            }
        }
    }

    companion object {
        private val logger = MythaiaLogger("Wintun")
        const val DEFAULT_RING_CAPACITY = 0x400000            // 4 MiB
        const val MAX_PACKET_SIZE = 0xFFFF
        private const val READ_WAIT_MS = 250
        private const val ERROR_NO_MORE_ITEMS = 259
        private const val ERROR_HANDLE_EOF = 38

        @Volatile
        private var loaded: WintunLib? = null
        private var loadedFrom: File? = null

        // JNA only keeps a callback alive while something references it.
        private var loggerCallback: WintunLib.LoggerCallback? = null

        /** Loads `wintun.dll` from [dll] (once per process) and routes its log into ours. */
        @Synchronized
        internal fun load(dll: File): WintunLib {
            loaded?.let { if (loadedFrom == dll) return it }
            if (!dll.isFile) throw IOException("wintun.dll not found at $dll")
            val lib = Native.load(dll.absolutePath, WintunLib::class.java)
            val callback = object : WintunLib.LoggerCallback {
                override fun invoke(level: Int, timestamp: Long, message: Pointer?) {
                    val text = message?.getWideString(0) ?: return
                    when (level) {
                        2 -> logger.error(text)
                        1 -> logger.warning(text)
                        else -> logger.debug(text)
                    }
                }
            }
            runCatching { lib.WintunSetLogger(callback) }
            loggerCallback = callback
            loaded = lib
            loadedFrom = dll
            return lib
        }

        /** The driver version the running kernel module reports, or null when none is loaded. */
        fun runningDriverVersion(dll: File): String? = runCatching {
            val v = load(dll).WintunGetRunningDriverVersion()
            if (v == 0) null else "${v ushr 16}.${v and 0xFFFF}"
        }.getOrNull()

        /**
         * Creates the adapter, first deleting one of the same [name] left
         * behind by a run that died. Needs administrator rights.
         */
        fun create(dll: File, name: String, tunnelType: String, guid: String?): WintunAdapter {
            val lib = load(dll)
            lib.WintunOpenAdapter(WString(name))?.let { stale ->
                logger.info("Removing leftover adapter '$name'")
                lib.WintunCloseAdapter(stale)
            }
            val guidPointer = guid?.let { Guid.GUID.fromString(it).also { g -> g.write() }.pointer }
            val handle = lib.WintunCreateAdapter(WString(name), WString(tunnelType), guidPointer)
                ?: throw IOException("WintunCreateAdapter failed: ${lastErrorMessage()}")
            return WintunAdapter(lib, handle, name)
        }

        private fun lastErrorMessage(): String {
            val code = Native.getLastError()
            val text = runCatching { com.sun.jna.platform.win32.Kernel32Util.formatMessage(code) }.getOrNull()
            return if (text.isNullOrBlank()) "error $code" else "error $code: ${text.trim()}"
        }
    }
}
