package com.mythaia.desktop.service

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.win32.W32APIOptions
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.RandomAccessFile

/**
 * A Windows named pipe: the server side through JNA (the JDK cannot create
 * one), the client side through the JDK's own file API, which opens pipes
 * like files. Messages are lines of UTF-8 text.
 */
object NamedPipe {

    private const val PIPE_ACCESS_DUPLEX = 0x00000003
    private const val PIPE_TYPE_BYTE = 0x00000000
    private const val PIPE_READMODE_BYTE = 0x00000000
    private const val PIPE_WAIT = 0x00000000
    private const val PIPE_UNLIMITED_INSTANCES = 255
    private const val BUFFER = 64 * 1024
    private const val SDDL_REVISION_1 = 1

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
    class ServerConnection internal constructor(private val handle: WinNT.HANDLE) : ServiceConnection {
        private val pending = ByteArrayOutputStream()

        /** The next line without its terminator, or null when the client went away. */
        override fun readLine(): String? {
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

        override fun writeLine(text: String) {
            val bytes = (text + "\n").toByteArray(Charsets.UTF_8)
            var offset = 0
            val written = IntByReference()
            while (offset < bytes.size) {
                val piece = bytes.copyOfRange(offset, bytes.size)
                if (!Kernel32.INSTANCE.WriteFile(handle, piece, piece.size, written, null)) {
                    throw IOException("pipe write failed: ${Kernel32.INSTANCE.GetLastError()}")
                }
                offset += written.value
            }
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

    /** One request/response exchange as a client; null when no server is listening. */
    fun exchange(name: String, line: String, timeoutMs: Long = 5_000): String? {
        val deadline = System.currentTimeMillis() + timeoutMs
        var file: RandomAccessFile? = null
        while (file == null) {
            file = try {
                RandomAccessFile(name, "rw")
            } catch (e: IOException) {
                // "All pipe instances are busy" while the server re-arms; wait a moment.
                if (System.currentTimeMillis() > deadline || e.message?.contains("cannot find", ignoreCase = true) == true) return null
                Thread.sleep(50)
                null
            }
        }
        file.use { pipe ->
            pipe.write((line + "\n").toByteArray(Charsets.UTF_8))
            val out = ByteArrayOutputStream()
            while (true) {
                val b = pipe.read()
                if (b < 0) break
                if (b == '\n'.code) break
                out.write(b)
            }
            return String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
        }
    }

    /** Whether a server is listening (a connect that fails with "not found" means no). */
    fun exists(name: String): Boolean = runCatching {
        Kernel32.INSTANCE.WaitNamedPipe(name, 200)
    }.getOrDefault(false)

    @Suppress("unused")
    private val unusedPointer: Pointer? = null
}
