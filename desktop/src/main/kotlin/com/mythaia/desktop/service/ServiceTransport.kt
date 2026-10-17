package com.mythaia.desktop.service

import com.mythaia.desktop.Platform
import com.mythaia.vpn.util.MythaiaLogger
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.ClosedChannelException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions

/** One window connected to the service: request lines in, reply lines out, until either side closes. */
interface ServiceConnection : AutoCloseable {
    /** The next line without its terminator, or null when the client went away. */
    fun readLine(): String?

    fun writeLine(text: String)

    override fun close()
}

/**
 * How the window reaches the service. What travels is [ServiceProtocol]'s
 * JSON lines either way; only the channel differs: a named pipe on Windows,
 * a Unix domain socket on macOS. Tests put an in-memory one behind
 * [ServiceCore].
 */
interface ServiceTransport {
    /** Where it listens, for the log. */
    val address: String

    /** Service side: blocks until a window connects; throws once [close]d. */
    fun accept(): ServiceConnection

    /** Window side: one request line and its reply; null when no service is listening. */
    fun exchange(line: String, timeoutMs: Long): String?

    /** Service side: stops listening and wakes an [accept] in progress. */
    fun close()
}

object ServiceTransports {
    /** The channel for this system: [ServiceProtocol.PIPE_NAME] on Windows, [ServiceProtocol.SOCKET_PATH] on macOS. */
    fun forThisSystem(): ServiceTransport =
        if (Platform.isMac) UnixSocketTransport(Path.of(ServiceProtocol.SOCKET_PATH), group = ServiceProtocol.SOCKET_GROUP)
        else NamedPipeTransport(ServiceProtocol.PIPE_NAME)
}

/** The Windows channel: [NamedPipe], readable and writable by every signed-in user. */
class NamedPipeTransport(private val name: String) : ServiceTransport {
    override val address: String get() = name

    override fun accept(): ServiceConnection = NamedPipe.accept(name)

    override fun exchange(line: String, timeoutMs: Long): String? = NamedPipe.exchange(name, line, timeoutMs)

    /** A pipe server cannot be interrupted; connecting once unblocks it. */
    override fun close() {
        runCatching { NamedPipe.exchange(name, """{"cmd":"ping"}""", 500) }
    }
}

/**
 * The macOS channel: a Unix domain socket at [path].
 *
 * The daemon runs as root and creates the socket in a directory only root
 * can write to, so nobody else can delete or replace it; the socket itself
 * is readable and writable by [group] (`staff`, every account that signs in
 * at the console), which is what lets the window connect. With [group] null
 * the socket keeps the permissions it was created with, as tests want.
 */
class UnixSocketTransport(private val path: Path, private val group: String? = null) : ServiceTransport {
    private val logger = MythaiaLogger("ServiceSocket")

    @Volatile
    private var server: ServerSocketChannel? = null

    @Volatile
    private var closed = false

    override val address: String get() = path.toString()

    override fun accept(): ServiceConnection {
        val channel = server ?: synchronized(this) { server ?: bind().also { server = it } }
        return Connection(channel.accept())
    }

    private fun bind(): ServerSocketChannel {
        if (closed) throw ClosedChannelException()
        path.parent?.let(::prepareDirectory)
        // A socket left by a run that died; only its owner (root, for the daemon's) can remove it.
        Files.deleteIfExists(path)
        val channel = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        try {
            channel.bind(UnixDomainSocketAddress.of(path))
        } catch (e: IOException) {
            channel.close()
            throw e
        }
        group?.let(::restrictTo)
        return channel
    }

    /**
     * The directory is created if missing; when this process is root it is
     * made root's and closed to writes by anyone else, and a link in its
     * place is refused rather than followed.
     */
    private fun prepareDirectory(dir: Path) {
        if (Files.isSymbolicLink(dir)) throw IOException("$dir is a link; refusing to listen there")
        Files.createDirectories(dir)
        if (!isPosix(dir) || System.getProperty("user.name") != "root") return
        val lookup = dir.fileSystem.userPrincipalLookupService
        val view = Files.getFileAttributeView(dir, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
        view.setOwner(lookup.lookupPrincipalByName("root"))
        view.setGroup(lookup.lookupPrincipalByGroupName("wheel"))
        view.setPermissions(PosixFilePermissions.fromString("rwxr-xr-x"))
    }

    /** Read and write for the owner and [name]'s members, nothing for others; closed entirely when that fails. */
    private fun restrictTo(name: String) {
        if (!isPosix(path)) return
        try {
            val view = Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            view.setGroup(path.fileSystem.userPrincipalLookupService.lookupPrincipalByGroupName(name))
            view.setPermissions(PosixFilePermissions.fromString("rw-rw----"))
        } catch (e: Exception) {
            logger.error("Could not open $path to group $name: ${e.message}; only its owner can connect")
            runCatching { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")) }
        }
    }

    private fun isPosix(p: Path): Boolean = "posix" in p.fileSystem.supportedFileAttributeViews()

    override fun exchange(line: String, timeoutMs: Long): String? {
        if (!Files.exists(path)) return null
        val channel = try {
            SocketChannel.open(StandardProtocolFamily.UNIX)
        } catch (e: IOException) {
            return null
        }
        channel.use { socket ->
            try {
                socket.connect(UnixDomainSocketAddress.of(path))
            } catch (e: IOException) {
                // A socket file nobody listens on: the daemon is not running.
                return null
            }
            val request = ByteBuffer.wrap((line + "\n").toByteArray(Charsets.UTF_8))
            while (request.hasRemaining()) socket.write(request)
            return readReply(socket, timeoutMs)
        }
    }

    /** Reads up to the first newline, giving up after [timeoutMs]. */
    private fun readReply(socket: SocketChannel, timeoutMs: Long): String? {
        socket.configureBlocking(false)
        Selector.open().use { selector ->
            socket.register(selector, SelectionKey.OP_READ)
            val deadline = System.currentTimeMillis() + timeoutMs
            val out = ByteArrayOutputStream()
            val buffer = ByteBuffer.allocate(64 * 1024)
            while (true) {
                val remaining = deadline - System.currentTimeMillis()
                if (remaining <= 0) return null
                selector.select(remaining)
                selector.selectedKeys().clear()
                while (true) {
                    buffer.clear()
                    val n = socket.read(buffer)
                    if (n < 0) return String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
                    if (n == 0) break
                    val bytes = buffer.array()
                    val newline = (0 until n).firstOrNull { bytes[it] == '\n'.code.toByte() }
                    if (newline != null) {
                        out.write(bytes, 0, newline)
                        return String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
                    }
                    out.write(bytes, 0, n)
                    if (out.size() > MAX_LINE) return null
                }
            }
        }
    }

    override fun close() {
        closed = true
        synchronized(this) {
            server?.let { runCatching { it.close() } }
            server = null
        }
        runCatching { Files.deleteIfExists(path) }
    }

    private class Connection(private val channel: SocketChannel) : ServiceConnection {
        private val input = BufferedInputStream(Channels.newInputStream(channel))
        private val output = Channels.newOutputStream(channel)

        override fun readLine(): String? = readLineFrom(input)

        override fun writeLine(text: String) {
            output.write((text + "\n").toByteArray(Charsets.UTF_8))
            output.flush()
        }

        override fun close() {
            runCatching { channel.close() }
        }
    }

    companion object {
        /** A request carries the settings, a server and the rules; nothing honest comes near this. */
        private const val MAX_LINE = 32 * 1024 * 1024

        /** One line from [input] without its terminator; null at the end of the stream or past [MAX_LINE]. */
        internal fun readLineFrom(input: InputStream): String? {
            val out = ByteArrayOutputStream()
            while (true) {
                val b = input.read()
                if (b < 0) return if (out.size() == 0) null else String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
                if (b == '\n'.code) return String(out.toByteArray(), Charsets.UTF_8).trimEnd('\r')
                out.write(b)
                if (out.size() > MAX_LINE) return null
            }
        }
    }
}
