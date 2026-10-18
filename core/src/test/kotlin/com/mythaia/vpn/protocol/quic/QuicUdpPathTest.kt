package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.HopInterval
import com.mythaia.data.model.PortUnion
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.random.Random

/**
 * Port hopping as the server sees it: which of its ports a packet arrives on,
 * from which client port, and where its answers still reach the client.
 *
 * The "server" is a handful of plain loopback sockets standing for one
 * server's port range; nothing here goes through the path's own reading of
 * what it sent.
 */
class QuicUdpPathTest {

    private val loopback = InetAddress.getLoopbackAddress()
    private val server = List(4) { DatagramSocket(0, loopback).apply { soTimeout = 2000 } }
    private val serverPorts = server.associateBy { it.localPort }
    private val ports = PortUnion.parse(server.joinToString(",") { it.localPort.toString() })!!
    private val received = LinkedBlockingQueue<ByteArray>()
    private val threads = mutableListOf<Thread>()
    private var path: QuicUdpPath? = null

    @After
    fun tearDown() {
        path?.close()
        server.forEach { it.close() }
        threads.forEach { it.join(3000) }
    }

    private fun start(hopping: QuicPortHopping?, firstPort: Int): QuicUdpPath {
        val p = QuicUdpPath(loopback, firstPort, hopping) {
            DatagramSocket(0, loopback).apply { soTimeout = 200 }
        }
        path = p
        p.open()!!
        // No hop timer here: the 5 s floor would make the test slow, and the
        // hops are driven by hand below.
        p.start({ _, body -> threads.add(Thread(body).apply { isDaemon = true; start() }) }) { bytes ->
            received.add(bytes); true
        }
        return p
    }

    /** What arrived at the server, and on which of its ports from which client address. */
    private fun serverReceive(): Triple<Int, InetSocketAddress, ByteArray> {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (System.nanoTime() < deadline) {
            for (socket in server) {
                socket.soTimeout = 50
                val buffer = ByteArray(2048)
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (_: java.net.SocketTimeoutException) {
                    continue
                } catch (e: java.net.SocketException) {
                    // Windows reports the ICMP for an answer sent to a closed
                    // client socket on the server socket's next read.
                    if (socket.isClosed) throw e
                    continue
                }
                return Triple(socket.localPort, packet.socketAddress as InetSocketAddress, buffer.copyOf(packet.length))
            }
        }
        throw AssertionError("nothing reached the server")
    }

    private fun reply(fromPort: Int, to: InetSocketAddress, bytes: ByteArray) {
        serverPorts.getValue(fromPort).send(DatagramPacket(bytes, bytes.size, to))
    }

    @Test
    fun `without hopping every packet leaves one socket for one port`() {
        val first = server[1].localPort
        val p = start(null, first)
        p.send(byteArrayOf(1))
        val (port, from, bytes) = serverReceive()
        assertEquals(first, port)
        assertArrayEquals(byteArrayOf(1), bytes)
        assertFalse(p.hop())
        p.send(byteArrayOf(2))
        val (port2, from2, _) = serverReceive()
        assertEquals(first, port2)
        assertEquals(from, from2)
    }

    @Test
    fun `a hop moves to a new local socket and a port of the list, and the old socket is still read`() {
        val hopping = QuicPortHopping(ports, HopInterval.DEFAULT, Random(1))
        val p = start(hopping, server[0].localPort)

        p.send("a".toByteArray())
        val (port0, client0, _) = serverReceive()
        assertEquals(server[0].localPort, port0)

        val seenPorts = HashSet<Int>()
        val clients = mutableListOf(client0)
        repeat(12) { i ->
            assertTrue(p.hop())
            p.send(byteArrayOf(i.toByte()))
            val (port, client, bytes) = serverReceive()
            assertArrayEquals(byteArrayOf(i.toByte()), bytes)
            assertTrue("port $port is one of the server's", port in ports)
            assertEquals(port, p.port)
            seenPorts.add(port)
            // Every hop leaves from a socket of its own.
            assertTrue("client port reused after a hop", clients.none { it.port == client.port })
            clients.add(client)

            // The server has not seen the move yet and answers the address
            // before: that still reaches the client.
            val late = "late$i".toByteArray()
            reply(port, clients[clients.size - 2], late)
            assertArrayEquals(late, received.poll(2, TimeUnit.SECONDS))
            // The address before that is closed: an answer there is lost.
            if (clients.size >= 3) {
                reply(port, clients[clients.size - 3], "gone".toByteArray())
                assertNull(received.poll(300, TimeUnit.MILLISECONDS))
            }
            // And the new address is read, of course.
            reply(port, client, "now$i".toByteArray())
            assertArrayEquals("now$i".toByteArray(), received.poll(2, TimeUnit.SECONDS))
        }
        assertTrue("hops landed on several of the server's ports: $seenPorts", seenPorts.size >= 2)
        assertNotEquals(client0.port, clients.last().port)
    }

    @Test
    fun `nothing is sent or read after close`() {
        val p = start(QuicPortHopping(ports), server[2].localPort)
        p.close()
        assertFalse(p.hop())
        try {
            p.send(byteArrayOf(1))
            throw AssertionError("send after close")
        } catch (_: java.net.SocketException) {
        }
    }

    @Test
    fun `hop intervals follow the official defaults and bounds`() {
        assertEquals(30_000L, QuicPortHopping(ports).nextIntervalMillis())
        val ranged = QuicPortHopping(ports, HopInterval(10, 20), Random(3))
        val waits = List(200) { ranged.nextIntervalMillis() }
        assertTrue(waits.all { it in 10_000L..20_000L })
        assertTrue("random, not fixed", waits.toSet().size > 50)
    }
}
