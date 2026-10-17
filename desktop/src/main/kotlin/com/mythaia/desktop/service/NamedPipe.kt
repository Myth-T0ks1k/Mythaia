package com.mythaia.desktop.service

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinError
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.win32.W32APIOptions
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * A Windows named pipe, both ends through JNA: the JDK cannot create one,
 * and its file API opens the client end but reports failures only as
 * localised text and cannot bound a read. Messages are lines of UTF-8 text.
 */
object NamedPipe {

    private const val PIPE_ACCESS_DUPLEX = 0x00000003
    private const val PIPE_TYPE_BYTE = 0x00000000
    private const val PIPE_READMODE_BYTE = 0x00000000
    private const val PIPE_WAIT = 0x00000000
    private const val PIPE_UNLIMITED_INSTANCES = 255
    private const val BUFFER = 64 * 1024
    private const val SDDL_REVISION_1 = 1
    private const val RETRY_MS = 20L
    private const val POLL_MS = 5L
    private const val NOT_FOUND_GRACE_MS = 250L

    /**
     * SYSTEM and administrators get everything; any signed-in user may read
     * and write, which is what lets the unprivileged window talk to the
     * service. Anonymous and remote callers are not on the list.
     */
    private const val SDDL = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

    @Suppress("FunctionName")
    private interface Advapi32Sddl : StdCallLibrary {
        fun ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: String, revision: Int, descriptor: PointerByReference, size: IntByReference
        ): Boolean
    }

    private val sddlLib: Advapi32Sddl by lazy {
        Native.load("advapi32", Advapi32Sddl::class.java, W32APIOptions.DEFAULT_OPTIONS)
    }

    /** One connected client on the server side. */
    class ServerConnection internal constructor(private val handle: WinNT.HANDLE) : AutoCloseable {
        private val pending = ByteArrayOutputStream()

        /** The next line without its terminator, or null when the client went away. */
        fun readLine(): String? {
            val chunk = ByteArray(BUFFER)
            val read = IntByReference()
            while (true) {
                val buffered = pending.toByteArray()
                val newline = buffered.indexOf('\n'.code.toByte())
                if (newline >= 0) {
                    pending.reset()
                    pending.write(buffered, newline + 1, buffered.size - newline - 1)
                    return String(buffered, 0, newline, Charsets.UTF_8).trimEnd('\r')
                }
                if (!Kernel32.INSTANCE.ReadFile(handle, chunk, chunk.size, read, null) || read.value <= 0) {
                    return null
                }
                pending.write(chunk, 0, read.value)
            }
        }

        fun writeLine(text: String) {
            writeAll(handle, (text + "\n").toByteArray(Charsets.UTF_8))
            Kernel32.INSTANCE.FlushFileBuffers(handle)
        }

        override fun close() {
            runCatching { Kernel32.INSTANCE.DisconnectNamedPipe(handle) }
            runCatching { Kernel32.INSTANCE.CloseHandle(handle) }
        }
    }

    /** Creates one pipe instance and blocks until a client connects. */
    fun accept(name: String): ServerConnection {
        val descriptor = PointerByReference()
        val size = IntByReference()
        val attributes = WinBase.SECURITY_ATTRIBUTES()
        if (sddlLib.ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL, SDDL_REVISION_1, descriptor, size)) {
            attributes.lpSecurityDescriptor = descriptor.value
        }
        attributes.bInheritHandle = false
        attributes.write()
        val handle = Kernel32.INSTANCE.CreateNamedPipe(
            name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, attributes
        )
        if (handle == null || handle == WinBase.INVALID_HANDLE_VALUE) {
            throw IOException("CreateNamedPipe failed: ${Kernel32.INSTANCE.GetLastError()}")
        }
        val connected = Kernel32.INSTANCE.ConnectNamedPipe(handle, null) ||
            Kernel32.INSTANCE.GetLastError() == 535 // ERROR_PIPE_CONNECTED: the client got there first
        if (!connected) {
            val error = Kernel32.INSTANCE.GetLastError()
            Kernel32.INSTANCE.CloseHandle(handle)
            throw IOException("ConnectNamedPipe failed: $error")
        }
        descriptor.value?.let { Kernel32.INSTANCE.LocalFree(it) }
        return ServerConnection(handle)
    }

    /**
     * One request/response exchange as a client; null when no server is
     * listening. [timeoutMs] bounds the whole exchange, the reply included:
     * a server that accepts and then hangs ends in an [IOException], not in
     * a caller blocked for good.
     */
    @Throws(IOException::class)
    fun exchange(name: String, line: String, timeoutMs: Long = 5_000): String? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        try {
            val handle = openClient(name, deadline) ?: return null
            try {
                writeAll(handle, (line + "\n").toByteArray(Charsets.UTF_8))
                return readReply(handle, deadline)
                    ?: throw IOException("no reply on $name within $timeoutMs ms")
            } finally {
                Kernel32.INSTANCE.CloseHandle(handle)
            }
        } catch (e: LinkageError) {
            // JNA's native part could not be loaded (blocked in %TEMP%): an
            // Error the callers' Exception handlers would not see.
            throw IOException("named pipes unavailable: ${e.message ?: e}", e)
        }
    }

    /**
     * Opens the client end, retrying while every instance is busy. Null when
     * no server is there by [deadline]. Decided on the Win32 error code: the
     * message text is in the language of the Windows it runs on.
     */
    private fun openClient(name: String, deadline: Long): WinNT.HANDLE? {
        var missingSince: Long? = null
        while (true) {
            val handle = Kernel32.INSTANCE.CreateFile(
                name, WinNT.GENERIC_READ or WinNT.GENERIC_WRITE, 0, null, WinNT.OPEN_EXISTING, 0, null
            )
            if (handle != null && handle != WinBase.INVALID_HANDLE_VALUE) return handle
            val now = System.nanoTime()
            when (val error = Native.getLastError()) {
                // Every instance is serving another client; one frees up shortly.
                WinError.ERROR_PIPE_BUSY -> Unit
                // No instance at all: no server, or the moment between the
                // server closing one instance and creating the next (it serves
                // one client at a time). A short grace tells those apart
                // without making "no service" slow to report.
                WinError.ERROR_FILE_NOT_FOUND -> {
                    val since = missingSince ?: now.also { missingSince = it }
                    if (now - since >= TimeUnit.MILLISECONDS.toNanos(NOT_FOUND_GRACE_MS)) return null
                }
                else -> throw IOException("cannot open $name: error $error")
            }
            if (now - deadline >= 0) return null
            Thread.sleep(RETRY_MS)
        }
    }

    /**
     * The first line the server sends, without its terminator; whatever came
     * if the server closed its end first; null if nothing complete arrived
     * by [deadline]. Polls with PeekNamedPipe and only reads what is already
     * there, so no ReadFile ever blocks — a synchronous read cannot be
     * abandoned, and closing the handle under it blocks as well.
     */
    private fun readReply(handle: WinNT.HANDLE, deadline: Long): String? {
        val out = ByteArrayOutputStream()
        val chunk = ByteArray(BUFFER)
        val available = IntByReference()
        val read = IntByReference()
        while (true) {
            if (!Kernel32.INSTANCE.PeekNamedPipe(handle, null, 0, null, available, null)) {
                val error = Native.getLastError()
                if (isClosed(error)) break
                throw IOException("pipe read failed: $error")
            }
            if (available.value <= 0) {
                if (System.nanoTime() - deadline >= 0) return null
                Thread.sleep(POLL_MS)
                continue
            }
            if (!Kernel32.INSTANCE.ReadFile(handle, chunk, minOf(available.value, chunk.size), read, null)) {
                val error = Native.getLastError()
                if (isClosed(error)) break
                throw IOException("pipe read failed: $error")
            }
            val n = read.value
            val newline = (0 until n).firstOrNull { chunk[it] == '\n'.code.toByte() }
            if (newline != null) {
                out.write(chunk, 0, newline)
                break
            }
            out.write(chunk, 0, n)
        }
        return String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
    }

    /** The server closed or disconnected its end. */
    private fun isClosed(error: Int): Boolean =
        error == WinError.ERROR_BROKEN_PIPE || error == WinError.ERROR_PIPE_NOT_CONNECTED

    /**
     * Writes [bytes] whole, returning once the pipe has taken them in. For
     * a client that is no wait: the server reads from the moment it
     * accepted, and a request within its 64 KiB buffer goes in at once.
     */
    private fun writeAll(handle: WinNT.HANDLE, bytes: ByteArray) {
        var offset = 0
        val written = IntByReference()
        while (offset < bytes.size) {
            val piece = if (offset == 0) bytes else bytes.copyOfRange(offset, bytes.size)
            if (!Kernel32.INSTANCE.WriteFile(handle, piece, piece.size, written, null)) {
                throw IOException("pipe write failed: ${Native.getLastError()}")
            }
            offset += written.value
        }
    }

    /** Whether a server is listening (a connect that fails with "not found" means no). */
    fun exists(name: String): Boolean = runCatching {
        Kernel32.INSTANCE.WaitNamedPipe(name, 200)
    }.getOrDefault(false)

    @Suppress("unused")
    private val unusedPointer: Pointer? = null
}
