package com.mythaia.vpn.protocol.wireguard

import android.os.ParcelFileDescriptor
import com.mythaia.vpn.SocketProtector
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong

private val logger = MythaiaLogger("WireGuard")

/**
 * A WireGuard interface: the TUN on one side, one peer over UDP on the other.
 *
 * Unlike every other outbound here, WireGuard is not a stream proxy — there is
 * no per-flow dial and nothing for lwIP to terminate. Whole IP packets go in
 * and come back out, so this runs *instead of* [com.mythaia.vpn.LwipStack]
 * rather than underneath it.
 *
 * Three threads: one pulling packets off the TUN, one reading the socket, and
 * a timer that handles rekeying and keepalives. The session they share is
 * swapped, never mutated, so a rekey cannot tear a packet in half.
 */
class WireGuardTunnel(private val config: WireGuardConfig) {

    private val bytesInCounter = AtomicLong(0)
    private val bytesOutCounter = AtomicLong(0)

    /** Bytes written to the TUN, i.e. received from the peer. */
    val bytesIn: Long get() = bytesInCounter.get()

    /** Bytes read from the TUN, i.e. sent to the peer. */
    val bytesOut: Long get() = bytesOutCounter.get()

    @Volatile
    private var running = false

    @Volatile
    private var socket: DatagramSocket? = null

    @Volatile
    private var endpoint: InetSocketAddress? = null

    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null

    /**
     * The live session, and the one it replaced.
     *
     * A rekey does not stop the peer sending under the old keys for a moment,
     * so the previous session stays readable until the next rekey retires it.
     */
    @Volatile
    private var session: WireGuardTransport? = null

    @Volatile
    private var previousSession: WireGuardTransport? = null

    @Volatile
    private var sessionStartedAt = 0L

    /** The handshake waiting for a response, if one is in flight. */
    @Volatile
    private var pending: WireGuardHandshake? = null

    @Volatile
    private var lastHandshakeAttempt = 0L

    @Volatile
    private var lastSendAt = 0L

    @Volatile
    private var cookie: ByteArray? = null

    /** When the stored cookie stops being usable; mac2 reverts to zero after. */
    @Volatile
    private var cookieExpiresAt = 0L

    /**
     * The mac1 of the initiation last sent.
     *
     * A cookie reply is sealed with it as the additional data, so it has to
     * outlive the message it belonged to.
     */
    @Volatile
    private var lastSentMac1: ByteArray? = null

    /** Raised when the peer has not completed a handshake for too long. */
    @Volatile
    var onFailure: ((String) -> Unit)? = null

    /** Called the first time a session is established. */
    @Volatile
    var onConnected: (() -> Unit)? = null

    private val threads = mutableListOf<Thread>()

    // The four message types this peer uses. Plain WireGuard leaves them at
    // 1-4; AmneziaWG replaces each with its H1-H4.
    private val amnezia = config.amnezia
    private val initiationType = amnezia.initiationType
    private val responseType = amnezia.responseType
    private val cookieType = amnezia.cookieType
    private val transportType = amnezia.transportType

    fun start(fd: ParcelFileDescriptor) {
        if (running) return
        running = true

        tunInput = FileInputStream(fd.fileDescriptor)
        tunOutput = FileOutputStream(fd.fileDescriptor)

        val bound = DatagramSocket()
        if (!SocketProtector.protect(bound)) {
            bound.close()
            running = false
            throw WireGuardError("could not protect the WireGuard socket from the tunnel")
        }
        bound.soTimeout = SOCKET_POLL_MS
        socket = bound

        resolveEndpoint()

        spawn("wg-downlink", ::runDownlink)
        spawn("wg-uplink", ::runUplink)
        spawn("wg-timer", ::runTimer)

        logger.debug(
            "[WG] Started, peer=${config.peer.endpointHost}:${config.peer.endpointPort}, " +
                "mtu=${config.mtu}, amnezia=${amnezia.isEnabled}"
        )
    }

    fun stop() {
        if (!running) return
        running = false

        socket?.close()
        socket = null

        runCatching { tunInput?.close() }
        runCatching { tunOutput?.close() }
        tunInput = null
        tunOutput = null

        threads.forEach { it.interrupt() }
        threads.clear()

        session = null
        previousSession = null
        pending = null

        logger.debug("[WG] Stopped")
    }

    private fun spawn(name: String, body: () -> Unit) {
        val thread = Thread({
            try {
                body()
            } catch (e: Exception) {
                if (running) logger.warning("[WG] $name ended: ${e.message}")
            }
        }, name).apply { isDaemon = true }
        threads.add(thread)
        thread.start()
    }

    // MARK: - Endpoint

    /**
     * Resolves the peer's endpoint outside the tunnel.
     *
     * A roaming peer changes address, and a name that resolved once can move,
     * so this is re-run whenever a handshake goes unanswered.
     */
    private fun resolveEndpoint() {
        val host = config.peer.endpointHost
        val address = if (DnsCache.isIpAddress(host)) {
            host
        } else {
            DnsCache.resolveHost(host)
        }
        if (address == null) {
            logger.warning("[WG] Could not resolve ${config.peer.endpointHost}")
            return
        }
        endpoint = try {
            InetSocketAddress(InetAddress.getByName(address), config.peer.endpointPort)
        } catch (e: Exception) {
            logger.warning("[WG] Bad endpoint $address: ${e.message}")
            null
        }
    }

    // MARK: - Handshake

    private fun beginHandshake() {
        val target = endpoint ?: run {
            resolveEndpoint()
            endpoint ?: return
        }

        lastHandshakeAttempt = System.currentTimeMillis()

        val handshake = WireGuardHandshake(
            localPrivateKey = config.privateKey,
            localPublicKey = config.publicKey,
            peerPublicKey = config.peer.publicKey,
            presharedKey = config.peer.presharedKey ?: ByteArray(WireGuardCrypto.KEY_SIZE),
            initiationType = initiationType,
            responseType = responseType,
            initiationJunkSize = amnezia.initPacketJunkSize,
            responseJunkSize = amnezia.responsePacketJunkSize
        )
        handshake.cookie = cookie?.takeIf { System.currentTimeMillis() < cookieExpiresAt }

        // AmneziaWG opens with a burst of junk datagrams, so the first packet
        // of a session is not a recognisable handshake initiation.
        sendJunkPackets(target)

        val initiation = try {
            handshake.buildInitiation()
        } catch (e: Exception) {
            logger.warning("[WG] Could not build the initiation: ${e.message}")
            return
        }

        // mac1 is the 16 bytes before mac2, at the very end of the message.
        lastSentMac1 = initiation.copyOfRange(
            initiation.size - 2 * WireGuardCrypto.MAC_SIZE,
            initiation.size - WireGuardCrypto.MAC_SIZE
        )

        pending = handshake
        send(initiation, target)
        logger.debug("[WG] Handshake initiation sent")
    }

    private fun sendJunkPackets(target: InetSocketAddress) {
        if (amnezia.junkPacketCount <= 0) return
        val random = java.security.SecureRandom()
        repeat(amnezia.junkPacketCount) {
            val size = amnezia.junkSize(random)
            if (size > 0) send(WireGuardCrypto.randomBytes(size), target)
        }
    }

    private fun completeHandshake(message: ByteArray) {
        val handshake = pending ?: return
        val keys = try {
            handshake.consumeResponse(message)
        } catch (e: Exception) {
            logger.warning("[WG] Handshake response refused: ${e.message}")
            return
        }

        pending = null
        previousSession = session
        session = WireGuardTransport(
            sendKey = keys.sendKey,
            receiveKey = keys.receiveKey,
            peerIndex = keys.peerIndex,
            localIndex = keys.localIndex,
            transportType = transportType
        )
        val first = sessionStartedAt == 0L
        sessionStartedAt = System.currentTimeMillis()

        logger.info("[WG] Session established with ${config.peer.endpointHost}")
        if (first) onConnected?.invoke()

        // A fresh session is silent until something is sent on it, and the peer
        // will not route to us before it has seen one authenticated packet.
        sendKeepalive()
    }

    /**
     * Stores the cookie from an under-load challenge.
     *
     * Layout is type(4) ‖ receiver(4) ‖ nonce(24) ‖ sealed cookie(32). The
     * cookie is sealed with XChaCha20-Poly1305 under HASH(LABEL_COOKIE ‖ the
     * peer's public key), with the mac1 of the message being answered as the
     * additional data — so a reply cannot be replayed onto a different
     * initiation, and the raw bytes are ciphertext, not the cookie.
     */
    private fun handleCookie(message: ByteArray) {
        if (message.size < COOKIE_REPLY_SIZE) return
        val mac1 = lastSentMac1 ?: return

        val key = WireGuardCrypto.hash(WireGuardHandshake.LABEL_COOKIE, config.peer.publicKey)
        val plaintext = WireGuardCrypto.xopen(
            key,
            message.copyOfRange(8, 32),
            message.copyOfRange(32, COOKIE_REPLY_SIZE),
            mac1
        )
        if (plaintext == null || plaintext.size != WireGuardCrypto.MAC_SIZE) {
            logger.debug("[WG] Cookie reply did not authenticate")
            return
        }

        cookie = plaintext
        cookieExpiresAt = System.currentTimeMillis() + COOKIE_LIFETIME_MS
        logger.debug("[WG] Cookie challenge answered")

        // The peer refused the initiation it challenged, so retry at once with
        // mac2 filled in rather than waiting out the retry timer.
        lastHandshakeAttempt = 0L
    }

    // MARK: - Pumps

    private fun runUplink() {
        val buffer = ByteArray(config.mtu + HEADROOM)
        val input = tunInput ?: return

        while (running) {
            val length = try {
                input.read(buffer)
            } catch (e: Exception) {
                if (running) logger.warning("[WG] TUN read failed: ${e.message}")
                break
            }
            if (length <= 0) continue

            val target = endpoint ?: continue
            val active = session
            if (active == null) {
                // Nothing to send under yet. The packet is dropped rather than
                // queued: TCP will resend, and a queue here would only add
                // latency to whatever the handshake eventually carries.
                continue
            }

            val packet = buffer.copyOf(length)
            val wrapped = try {
                active.encapsulate(packet)
            } catch (e: Exception) {
                logger.warning("[WG] Encapsulation failed: ${e.message}")
                continue
            }
            send(wrapped, target)
            bytesOutCounter.addAndGet(length.toLong())
        }
    }

    private fun runDownlink() {
        val buffer = ByteArray(config.mtu + HEADROOM)
        val datagram = DatagramPacket(buffer, buffer.size)

        while (running) {
            val current = socket ?: break
            try {
                datagram.setData(buffer, 0, buffer.size)
                current.receive(datagram)
            } catch (e: java.net.SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                if (running) logger.warning("[WG] Socket read failed: ${e.message}")
                break
            }

            val length = datagram.length
            if (length < 4) continue
            val message = buffer.copyOf(length)

            when (classify(message)) {
                Kind.RESPONSE -> completeHandshake(message)
                Kind.COOKIE -> handleCookie(message)
                Kind.TRANSPORT -> deliver(message)
                // An initiation arriving at a client is the peer trying to be
                // the initiator; this side does not answer those.
                Kind.UNKNOWN -> Unit
            }
        }
    }

    /** Decrypts one transport message and writes the packet inside it to the TUN. */
    private fun deliver(message: ByteArray) {
        val index = WireGuardHandshake.readLe32(message, 4)
        val active = session
        val older = previousSession

        val packet = when {
            active != null -> active.decapsulate(message) ?: older?.decapsulate(message)
            else -> older?.decapsulate(message)
        } ?: return

        // A keepalive is an empty packet; there is nothing to write.
        if (packet.isEmpty()) return

        // The plaintext is padded to a multiple of 16, so the IP header's own
        // length field is what says where the packet actually ends.
        val length = ipPacketLength(packet) ?: return
        if (length > packet.size) return

        val out = tunOutput ?: return
        try {
            out.write(packet, 0, length)
            bytesInCounter.addAndGet(length.toLong())
        } catch (e: Exception) {
            if (running) logger.warning("[WG] TUN write failed for index $index: ${e.message}")
        }
    }

    private fun runTimer() {
        while (running) {
            try {
                Thread.sleep(TIMER_TICK_MS)
            } catch (_: InterruptedException) {
                break
            }
            if (!running) break

            val now = System.currentTimeMillis()
            val active = session

            if (active == null || needsRekey(active, now)) {
                if (now - lastHandshakeAttempt >= REKEY_TIMEOUT_MS) {
                    if (pending != null && now - lastHandshakeAttempt >= HANDSHAKE_GIVE_UP_MS) {
                        // The endpoint may have moved; look it up again before
                        // spending another 90 seconds on the same address.
                        resolveEndpoint()
                    }
                    beginHandshake()
                }
                continue
            }

            val keepalive = config.peer.persistentKeepalive
            if (keepalive > 0 && now - lastSendAt >= keepalive * 1000L) {
                sendKeepalive()
            }
        }
    }

    private fun needsRekey(active: WireGuardTransport, now: Long): Boolean =
        active.needsRekey ||
            active.isExhausted ||
            now - sessionStartedAt >= REKEY_AFTER_TIME_MS

    private fun sendKeepalive() {
        val target = endpoint ?: return
        val active = session ?: return
        val wrapped = try {
            active.encapsulate(ByteArray(0))
        } catch (e: Exception) {
            return
        }
        send(wrapped, target)
    }

    private fun send(payload: ByteArray, target: InetSocketAddress) {
        val current = socket ?: return
        try {
            current.send(DatagramPacket(payload, payload.size, target))
            lastSendAt = System.currentTimeMillis()
        } catch (e: Exception) {
            if (running) logger.warning("[WG] Send failed: ${e.message}")
        }
    }

    /** What kind of message a received datagram is. */
    enum class Kind { RESPONSE, COOKIE, TRANSPORT, UNKNOWN }

    /**
     * Sorts a received datagram by kind.
     *
     * The type word is normally at offset 0, but AmneziaWG prepends S2 random
     * bytes to the handshake response — and only to that message — so for a
     * datagram of exactly the junked length the type is read past the junk
     * instead. Reading offset 0 unconditionally would see random bytes and
     * throw every response away, which is a handshake that never completes.
     */
    fun classify(message: ByteArray): Kind {
        if (message.size < 4) return Kind.UNKNOWN

        val junk = amnezia.responsePacketJunkSize
        if (junk > 0 &&
            message.size == WireGuardHandshake.RESPONSE_SIZE + junk &&
            WireGuardHandshake.readLe32(message, junk) == responseType
        ) {
            return Kind.RESPONSE
        }

        return when (WireGuardHandshake.readLe32(message, 0)) {
            responseType -> Kind.RESPONSE
            cookieType -> Kind.COOKIE
            transportType -> Kind.TRANSPORT
            else -> Kind.UNKNOWN
        }
    }

    companion object {
        /** Room for the transport header and AEAD tag on top of the MTU. */
        private const val HEADROOM = 128

        private const val SOCKET_POLL_MS = 1000
        private const val TIMER_TICK_MS = 1000L

        /** WireGuard's own timers, in milliseconds. */
        private const val REKEY_AFTER_TIME_MS = 120_000L
        private const val REKEY_TIMEOUT_MS = 5_000L
        private const val HANDSHAKE_GIVE_UP_MS = 90_000L
        private const val COOKIE_LIFETIME_MS = 120_000L

        /** type(4) + receiver(4) + nonce(24) + sealed cookie(16 + tag 16). */
        private const val COOKIE_REPLY_SIZE = 64

        /**
         * The length an IP packet declares for itself, or null when the header
         * is not one this tunnel carries.
         */
        fun ipPacketLength(packet: ByteArray): Int? {
            if (packet.isEmpty()) return null
            return when (packet[0].toInt() ushr 4 and 0x0F) {
                4 -> {
                    if (packet.size < 20) return null
                    ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
                }
                6 -> {
                    if (packet.size < 40) return null
                    // IPv6 length covers the payload only; the header is fixed.
                    40 + (((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF))
                }
                else -> null
            }
        }
    }
}
