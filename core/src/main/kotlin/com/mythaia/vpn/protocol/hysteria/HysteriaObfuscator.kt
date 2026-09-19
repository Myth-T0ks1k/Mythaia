package com.mythaia.vpn.protocol.hysteria

import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * The datagram-level disguise applied under Hysteria2's QUIC connection.
 *
 * Both modes exist to defeat the same thing: a censor that recognises a QUIC
 * Initial packet by its cleartext header and drops it. Salamander XORs a
 * password-derived keystream over the whole datagram, which destroys the
 * header's shape but preserves its size. Gecko goes further and also breaks a
 * handshake packet into several padded pieces, so neither the byte pattern nor
 * the characteristic size of a QUIC handshake survives.
 *
 * `seal` returns a list rather than one datagram precisely because gecko turns
 * one packet into several; a caller sends every element as its own UDP
 * datagram. `open` handles one received datagram and returns null when it
 * yields nothing to deliver — which for gecko is the ordinary case, since all
 * but the final fragment of a message produce no packet at all.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
interface HysteriaObfuscator {

    /** Disguises one outbound packet as one or more datagrams to send. */
    fun seal(packet: ByteArray): List<ByteArray>

    /** Recovers a packet from one inbound datagram, or null if there is none yet. */
    fun open(datagram: ByteArray): ByteArray?

    companion object {
        /**
         * Builds the obfuscator a config asks for.
         *
         * Throws [IllegalArgumentException] for a password below
         * [SalamanderObfuscator.MIN_PSK_LENGTH], which is worth failing loudly
         * at setup: a server built on the reference would refuse the same
         * password, so a node configured that way can never connect and saying
         * so now is better than a silent timeout later.
         */
        fun of(config: HysteriaObfuscation): HysteriaObfuscator = when (config) {
            is HysteriaObfuscation.Salamander -> SalamanderPacketObfuscator(config.password)
            is HysteriaObfuscation.Gecko ->
                GeckoObfuscator(config.password, config.minPacketSize, config.maxPacketSize)
        }
    }
}

/**
 * Salamander as a packet obfuscator: one packet in, one datagram out.
 *
 * The XOR itself lives in [SalamanderObfuscator]; this only adapts its shape to
 * the interface gecko also implements, so a caller can hold either without
 * caring which was configured.
 */
class SalamanderPacketObfuscator(password: String) : HysteriaObfuscator {

    private val inner = SalamanderObfuscator(password)

    override fun seal(packet: ByteArray): List<ByteArray> = listOf(inner.seal(packet))

    override fun open(datagram: ByteArray): ByteArray? = inner.open(datagram)
}

/**
 * Gecko: salamander, plus fragmentation of the handshake.
 *
 * Only long-header packets are split. That is the whole point — a QUIC long
 * header carries the version and connection IDs in the clear and appears only
 * during the handshake, so it is both the packet a censor can fingerprint and a
 * rare enough one that the cost of splitting it does not matter. Once the
 * connection is up, 1-RTT traffic has a short header that reveals almost
 * nothing, and fragmenting every data packet would multiply per-datagram
 * overhead for no gain.
 *
 * Each fragment carries a five-byte header — flag, message id, index and count
 * packed into one byte, then the pad length — followed by random padding and
 * then the slice of the original packet. Padding comes first so the payload
 * does not begin at a fixed offset. The receiver holds fragments keyed by
 * message id until the set is complete.
 *
 * Reassembly state is bounded in both directions: entries expire after
 * [REASSEMBLY_TTL_NANOS] and the table never holds more than
 * [MAX_REASSEMBLY] messages, because the fragments come off an unauthenticated
 * UDP socket and anyone can send a first fragment whose remainder never
 * arrives.
 */
class GeckoObfuscator(
    password: String,
    rawMinPacketSize: Int,
    rawMaxPacketSize: Int
) : HysteriaObfuscator {

    private val inner = SalamanderObfuscator(password)
    private val random = SecureRandom()

    /**
     * Normalized again here rather than trusted from the config, because a
     * caller can construct this directly and an inverted or absurd window would
     * otherwise make [randomPadLength] ask for a negative amount of padding.
     */
    private val sizes = HysteriaObfuscation.normalizedGeckoSizes(rawMinPacketSize, rawMaxPacketSize)
    private val minPacketSize = sizes.first
    private val maxPacketSize = sizes.second

    /**
     * Labels the fragments of one packet. A single wrapping byte is all the
     * header has room for, and it is enough: a message is complete or expired
     * long before 256 more have been sent.
     */
    private val msgIdCounter = AtomicInteger(0)

    private val lock = Any()
    private val table = HashMap<Int, Reassembly>()
    private var lastSweep = System.nanoTime()

    override fun seal(packet: ByteArray): List<ByteArray> {
        if (packet.isEmpty()) return emptyList()
        // Short-header (1-RTT) data rides salamander alone.
        if ((packet[0].toInt() and FRAGMENT_FLAG) != FRAGMENT_FLAG) return listOf(inner.seal(packet))

        val chunks = MIN_CHUNKS + random.nextInt(MAX_CHUNKS - MIN_CHUNKS + 1)
        val chunkSize = packet.size / chunks
        val msgId = msgIdCounter.incrementAndGet() and 0xFF

        return (0 until chunks).map { index ->
            val start = index * chunkSize
            // The last chunk absorbs the remainder of an uneven division.
            val end = if (index < chunks - 1) start + chunkSize else packet.size
            val padLength = randomPadLength(end - start)

            val frame = ByteArray(HEADER_LENGTH + padLength + (end - start))
            frame[0] = FRAGMENT_FLAG.toByte()
            frame[1] = msgId.toByte()
            frame[2] = ((index shl 4) or (chunks and 0x0F)).toByte()
            frame[3] = (padLength ushr 8).toByte()
            frame[4] = padLength.toByte()
            if (padLength > 0) {
                val pad = ByteArray(padLength)
                random.nextBytes(pad)
                pad.copyInto(frame, HEADER_LENGTH)
            }
            packet.copyInto(frame, HEADER_LENGTH + padLength, start, end)

            inner.seal(frame)
        }
    }

    /**
     * How much padding this fragment needs to land inside the size window.
     *
     * The sealed datagram ends up `salt + header + pad + chunk` bytes long, so
     * the padding is whatever lifts that to at least the minimum, plus a random
     * amount of headroom up to the maximum. A chunk already larger than the
     * maximum gets none: the alternative would be to split further, and the
     * reference chooses to let an oversized fragment through rather than
     * complicate reassembly.
     */
    private fun randomPadLength(chunkLength: Int): Int {
        val base = SalamanderObfuscator.SALT_LENGTH + HEADER_LENGTH + chunkLength
        val lo = maxOf(minPacketSize, base)
        if (lo > maxPacketSize) return 0
        return (lo - base) + random.nextInt(maxPacketSize - lo + 1)
    }

    override fun open(datagram: ByteArray): ByteArray? {
        val opened = inner.open(datagram) ?: return null
        if (opened.isEmpty()) return null
        // A short header means this was never fragmented.
        if ((opened[0].toInt() and FRAGMENT_FLAG) != FRAGMENT_FLAG) return opened

        if (opened.size < HEADER_LENGTH) return null
        val msgId = opened[1].toInt() and 0xFF
        val chunkIndex = (opened[2].toInt() and 0xFF) ushr 4
        val totalChunks = opened[2].toInt() and 0x0F
        val padLength = ((opened[3].toInt() and 0xFF) shl 8) or (opened[4].toInt() and 0xFF)

        if (totalChunks < MIN_CHUNKS || totalChunks > MAX_CHUNKS) return null
        if (chunkIndex >= totalChunks) return null
        val payloadStart = HEADER_LENGTH + padLength
        if (payloadStart > opened.size) return null

        val payload = opened.copyOfRange(payloadStart, opened.size)
        return acceptChunk(msgId, chunkIndex, totalChunks, payload)
    }

    /**
     * Files one fragment, returning the whole packet once the last one lands.
     *
     * A fragment that contradicts what is already held for its message id — a
     * different chunk count, or an index already filled — discards the partial
     * message rather than trying to reconcile it. Both cases mean the id has
     * been reused or the sender is confused, and a merged packet from two
     * different messages would be handed to QUIC as if it were genuine.
     */
    private fun acceptChunk(
        msgId: Int,
        chunkIndex: Int,
        totalChunks: Int,
        payload: ByteArray
    ): ByteArray? = synchronized(lock) {
        val now = System.nanoTime()
        if (now - lastSweep >= SWEEP_INTERVAL_NANOS) {
            table.entries.removeAll { it.value.deadline < now }
            lastSweep = now
        }

        var entry = table[msgId]
        if (entry != null && entry.total != totalChunks) {
            table.remove(msgId)
            entry = null
        }

        val active = entry ?: run {
            if (table.size >= MAX_REASSEMBLY) {
                // Evict the message closest to expiry, so a flood of first
                // fragments cannot starve one that is nearly complete.
                table.entries.minByOrNull { it.value.deadline }?.let { table.remove(it.key) }
            }
            Reassembly(totalChunks, now + REASSEMBLY_TTL_NANOS).also { table[msgId] = it }
        }

        if (chunkIndex >= active.chunks.size || active.chunks[chunkIndex] != null) {
            return@synchronized null
        }
        active.chunks[chunkIndex] = payload
        active.received++
        if (active.received < active.total) return@synchronized null

        table.remove(msgId)
        val out = ByteArray(active.chunks.sumOf { it?.size ?: 0 })
        var at = 0
        for (chunk in active.chunks) {
            if (chunk == null) continue
            chunk.copyInto(out, at)
            at += chunk.size
        }
        out
    }

    /** The fragments of one in-flight message, and when to give up on them. */
    private class Reassembly(val total: Int, val deadline: Long) {
        val chunks = arrayOfNulls<ByteArray>(total)
        var received = 0
    }

    companion object {
        /**
         * QUIC's own long-header bit, reused as the fragment marker.
         *
         * The two never collide: a fragment frame is only ever produced from a
         * packet that already had the bit set, and the receiver reads the bit
         * back off the deobfuscated frame to tell a fragment from a 1-RTT
         * packet that was passed through whole.
         */
        const val FRAGMENT_FLAG = 0x80

        /** flag(1) + msgId(1) + index/count(1) + padLength(2). */
        const val HEADER_LENGTH = 5

        /** The count lives in a nibble, so eight is the ceiling the format allows. */
        const val MIN_CHUNKS = 2
        const val MAX_CHUNKS = 8

        private const val REASSEMBLY_TTL_NANOS = 8_000_000_000L
        private const val SWEEP_INTERVAL_NANOS = 4_000_000_000L
        private const val MAX_REASSEMBLY = 64
    }
}
