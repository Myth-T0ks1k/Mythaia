package com.mythaia.data.network

import com.mythaia.vpn.SocketProtector
import com.mythaia.vpn.protocol.hysteria.HysteriaObfuscator
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

/**
 * A ping for servers that listen on UDP only: Hysteria2, TUIC, Nowhere over
 * QUIC. A TCP connect means nothing there — the port is closed to TCP — so
 * the plain TCP ping reported every one of them as failed.
 *
 * It sends one QUIC long-header packet carrying a reserved version
 * (RFC 9000 §15, `0x?a?a?a?a`). A QUIC server answers such a packet with
 * Version Negotiation straight away, before any cryptography and without
 * keeping state, so the reply times the round trip to the server's own QUIC
 * endpoint. Servers only answer packets of at least 1200 bytes (the
 * anti-amplification rule), so the probe is padded to that. Hysteria2's
 * obfuscation is applied when the server uses one: it drops anything else.
 */
object QuicPing {

    /** The smallest datagram a server answers with Version Negotiation. */
    const val PROBE_SIZE = 1200

    /** A version no server speaks, from the range reserved to force negotiation. */
    private const val RESERVED_VERSION = 0x1a2a3a4a

    /** Length of each random connection id in the probe. */
    private const val CID_LENGTH = 8

    private val random = SecureRandom()

    /** One probe: long header, reserved version, random 8-byte connection ids, zero padding. */
    fun probe(): ByteArray {
        val packet = ByteArray(PROBE_SIZE)
        // Long header form and fixed bit set; the type bits are left random,
        // as they mean nothing under an unknown version.
        packet[0] = (0xC0 or random.nextInt(0x10)).toByte()
        packet[1] = (RESERVED_VERSION ushr 24).toByte()
        packet[2] = (RESERVED_VERSION ushr 16).toByte()
        packet[3] = (RESERVED_VERSION ushr 8).toByte()
        packet[4] = RESERVED_VERSION.toByte()
        packet[5] = CID_LENGTH.toByte()
        System.arraycopy(ByteArray(CID_LENGTH).also(random::nextBytes), 0, packet, 6, CID_LENGTH)
        packet[6 + CID_LENGTH] = CID_LENGTH.toByte()
        System.arraycopy(ByteArray(CID_LENGTH).also(random::nextBytes), 0, packet, 7 + CID_LENGTH, CID_LENGTH)
        return packet
    }

    /** Whether [datagram] is a Version Negotiation packet (long header, version 0). */
    fun isVersionNegotiation(datagram: ByteArray, length: Int = datagram.size): Boolean =
        length >= 7 && (datagram[0].toInt() and 0x80) != 0 &&
            datagram[1].toInt() == 0 && datagram[2].toInt() == 0 &&
            datagram[3].toInt() == 0 && datagram[4].toInt() == 0

    /**
     * Pings [target]. Returns the round trip in milliseconds, or null when
     * nothing came back. The probe is sent up to [attempts] times, each
     * waiting [windowMs], since a single lost datagram would otherwise read
     * as a dead server; the time is measured from the probe that was answered.
     *
     * Blocking: call it on an IO thread. It returns within
     * `attempts × windowMs` whatever happens.
     */
    fun ping(
        target: InetSocketAddress,
        obfuscator: HysteriaObfuscator? = null,
        attempts: Int = 3,
        windowMs: Int = 1000
    ): Int? {
        DatagramSocket().use { socket ->
            // Kept out of the tunnel, as every socket the app opens to a server is.
            SocketProtector.protect(socket)
            val buffer = ByteArray(2048)
            repeat(attempts) {
                val packet = probe()
                val datagrams = obfuscator?.seal(packet) ?: listOf(packet)
                val sentAt = System.nanoTime()
                for (datagram in datagrams) {
                    socket.send(DatagramPacket(datagram, datagram.size, target))
                }
                val deadline = sentAt + windowMs * 1_000_000L
                while (true) {
                    val remaining = ((deadline - System.nanoTime()) / 1_000_000L).toInt()
                    if (remaining <= 0) break
                    socket.soTimeout = remaining
                    val reply = DatagramPacket(buffer, buffer.size)
                    try {
                        socket.receive(reply)
                    } catch (_: SocketTimeoutException) {
                        break
                    }
                    // Anything from the server's own address and port proves its
                    // QUIC endpoint is there: Version Negotiation in the clear, or
                    // the same disguised by the server's obfuscation.
                    if (reply.address == target.address && reply.port == target.port) {
                        return ((System.nanoTime() - sentAt) / 1_000_000L).toInt().coerceAtLeast(1)
                    }
                }
            }
        }
        return null
    }
}
