package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.HopInterval
import com.mythaia.data.model.PortUnion
import com.mythaia.vpn.SocketProtector
import com.mythaia.vpn.util.MythaiaLogger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import kotlin.random.Random

private val logger = MythaiaLogger("Quic")

/**
 * Hysteria2 port hopping: the server answers on every port of [ports], and
 * the client moves to another of them every [interval].
 */
class QuicPortHopping(
    val ports: PortUnion,
    val interval: HopInterval = HopInterval.DEFAULT,
    internal val random: Random = Random.Default
) {
    /** The next wait, picked anew each time between the interval's ends as the official client does. */
    internal fun nextIntervalMillis(): Long {
        val min = interval.min * 1000L
        val max = interval.max * 1000L
        return if (max == min) min else min + random.nextLong(max - min + 1)
    }
}

/**
 * The UDP side of one QUIC connection: the socket its packets leave on and
 * the server port they go to.
 *
 * Without [hopping] that is one socket for the life of the connection. With
 * it, this does what the official Hysteria client's `udphop` connection does:
 * the first port is picked at random from the list, and every hop interval a
 * new local socket is opened and the packets go from it to another random
 * port, while the socket before is still read until the next hop — the
 * server goes on answering the old address until it has seen the new one, and
 * what it sends in that gap would otherwise be lost. The socket before that is
 * closed. A hop that cannot open its socket is skipped.
 *
 * ngtcp2 never sees any of this: the connection was created with one path and
 * every packet is fed to it as arriving on that path, so to QUIC the hop is
 * invisible and the streams on it carry on. The server sees the client's
 * address change, which every Hysteria2 server takes as the same connection
 * moving (its connection IDs say so).
 */
internal class QuicUdpPath(
    private val remote: InetAddress,
    private val firstPort: Int,
    private val hopping: QuicPortHopping? = null,
    private val openSocket: () -> DatagramSocket? = { openProtectedSocket() }
) {
    private class Route(val socket: DatagramSocket, val target: InetSocketAddress)

    /** Where packets leave from and go to now; null before [open] and after [close]. */
    @Volatile
    private var route: Route? = null

    /** The socket [route]'s replaced, still read until the next hop; guarded by [lock]. */
    private var previous: DatagramSocket? = null

    private val lock = Any()

    @Volatile
    private var closed = false

    private var spawn: ((String, () -> Unit) -> Unit)? = null
    private var receive: ((ByteArray) -> Boolean)? = null

    /** The server port packets go to now. */
    val port: Int get() = route?.target?.port ?: firstPort

    /** The local socket packets leave from now, for logging and tests. */
    internal val localPort: Int get() = route?.socket?.localPort ?: -1

    /**
     * Opens the first socket; null when no socket could be opened or kept out
     * of the tunnel. The first port is [firstPort], which the caller picks —
     * at random from the list when hopping, as the official client does.
     */
    fun open(): DatagramSocket? {
        val socket = openSocket() ?: return null
        synchronized(lock) {
            if (closed) {
                socket.close()
                return null
            }
            route = Route(socket, InetSocketAddress(remote, firstPort))
        }
        return socket
    }

    /**
     * Starts reading: [receive] gets every datagram, on the reading thread,
     * and stops that reader by returning false. [spawn] starts a thread, so
     * the connection keeps the threads in its own book.
     */
    fun start(spawn: (String, () -> Unit) -> Unit, receive: (ByteArray) -> Boolean) {
        val first = route ?: return
        this.spawn = spawn
        this.receive = receive
        spawn("quic-read") { read(first.socket) }
        if (hopping != null) spawn("quic-hop", ::runHops)
    }

    /** Puts one datagram on the wire; throws when the socket is gone. */
    fun send(datagram: ByteArray) {
        val current = route ?: throw SocketException("QUIC path closed")
        current.socket.send(DatagramPacket(datagram, datagram.size, current.target))
    }

    /**
     * Moves to a new local socket and a new random port of the list. False
     * when there is nothing to hop between or the hop was skipped.
     */
    fun hop(): Boolean {
        val hopping = hopping ?: return false
        val fresh = openSocket() ?: run {
            logger.debug("[QUIC] Hop skipped: no socket")
            return false
        }
        val stale: DatagramSocket?
        val target: InetSocketAddress
        synchronized(lock) {
            val current = route
            if (closed || current == null) {
                fresh.close()
                return false
            }
            stale = previous
            previous = current.socket
            target = InetSocketAddress(remote, hopping.ports.random(hopping.random))
            route = Route(fresh, target)
        }
        stale?.close()
        spawn?.invoke("quic-read") { read(fresh) }
        logger.debug("[QUIC] Hopped to port ${target.port} from local port ${fresh.localPort}")
        return true
    }

    fun close() {
        synchronized(lock) {
            closed = true
            route?.socket?.close()
            previous?.close()
            route = null
            previous = null
        }
    }

    private fun runHops() {
        val hopping = hopping ?: return
        while (!closed) {
            try {
                Thread.sleep(hopping.nextIntervalMillis())
            } catch (_: InterruptedException) {
                return
            }
            if (closed) return
            hop()
        }
    }

    private fun read(socket: DatagramSocket) {
        val buffer = ByteArray(MAX_DATAGRAM)
        val packet = DatagramPacket(buffer, buffer.size)
        while (!closed && !socket.isClosed) {
            try {
                packet.setData(buffer, 0, buffer.size)
                socket.receive(packet)
            } catch (e: java.net.SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                // A hop closes the socket two hops back on purpose.
                if (!closed && !socket.isClosed) logger.warning("[QUIC] Socket read failed: ${e.message}")
                return
            }
            if (receive?.invoke(buffer.copyOf(packet.length)) == false) return
        }
    }

    companion object {
        /** Everything a QUIC datagram can be, plus room to read a larger one. */
        const val MAX_DATAGRAM = 1500

        /** How long a read waits before it looks at whether the path was closed. */
        const val SOCKET_POLL_MS = 1000
        private const val SEND_BUFFER_BYTES = 1024 * 1024
        private const val RECEIVE_BUFFER_BYTES = 2 * 1024 * 1024

        /** A UDP socket kept out of the tunnel, or null. */
        fun openProtectedSocket(): DatagramSocket? {
            val socket = try {
                DatagramSocket()
            } catch (e: Exception) {
                logger.warning("[QUIC] Could not open a UDP socket: ${e.message}")
                return null
            }
            if (!SocketProtector.protect(socket)) {
                socket.close()
                logger.warning("[QUIC] Could not protect the socket from the tunnel")
                return null
            }
            socket.soTimeout = SOCKET_POLL_MS
            runCatching { socket.sendBufferSize = SEND_BUFFER_BYTES }
            runCatching { socket.receiveBufferSize = RECEIVE_BUFFER_BYTES }
            return socket
        }
    }
}
