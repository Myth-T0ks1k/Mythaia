package com.mythaia.vpn.protocol.wireguard

import java.util.concurrent.atomic.AtomicLong

/**
 * The data phase: one IP packet per message, each with its own counter.
 *
 * Layout is type(4, LE) ‖ receiver index(4, LE) ‖ counter(8, LE) ‖ sealed
 * packet. The counter is the AEAD nonce, so it must never repeat under one
 * key — which is what the rekey limits below are about.
 *
 * The paper writes the first field as type(1) ‖ reserved(3), which is the same
 * four bytes: type 4 little-endian is `04 00 00 00`. AmneziaWG replaces the
 * whole word with H4, a value normally well above 255, so it has to be read
 * and written as one 32-bit field rather than a byte.
 */
class WireGuardTransport(
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray,
    private val peerIndex: Int,
    private val localIndex: Int,
    /** AmneziaWG renumbers the message types; plain WireGuard leaves them. */
    private val transportType: Int = WireGuardHandshake.MESSAGE_TRANSPORT
) {

    private val sendCounter = AtomicLong(0)
    private val replay = ReplayWindow()

    /** How many packets this session has carried, for the rekey decision. */
    val packetsSent: Long get() = sendCounter.get()

    /**
     * Whether the session should be replaced.
     *
     * WireGuard rekeys well before the counter could wrap; past the hard limit
     * a peer must stop sending entirely rather than reuse a nonce.
     */
    val needsRekey: Boolean get() = sendCounter.get() >= REKEY_AFTER_MESSAGES
    val isExhausted: Boolean get() = sendCounter.get() >= REJECT_AFTER_MESSAGES

    /**
     * Wraps one IP packet.
     *
     * The plaintext is padded to a multiple of 16 so the ciphertext length says
     * less about the packet inside it. The padding is zeroes, and the far side
     * drops it by reading the IP header's own length.
     */
    fun encapsulate(packet: ByteArray): ByteArray {
        if (isExhausted) throw WireGuardError("session has sent too many packets; rekey required")

        val counter = sendCounter.getAndIncrement()

        val padded = if (packet.isEmpty()) {
            packet
        } else {
            val remainder = packet.size % PADDING_MULTIPLE
            if (remainder == 0) packet else packet + ByteArray(PADDING_MULTIPLE - remainder)
        }

        val sealed = WireGuardCrypto.seal(sendKey, counter, padded, ByteArray(0))

        val out = ByteArray(HEADER_SIZE + sealed.size)
        WireGuardHandshake.writeLe32(out, 0, transportType)
        WireGuardHandshake.writeLe32(out, 4, peerIndex)
        WireGuardHandshake.writeLe64(out, 8, counter)
        sealed.copyInto(out, HEADER_SIZE)
        return out
    }

    /**
     * Unwraps one transport message.
     *
     * Null when it is not for us, is a replay, or does not authenticate — all
     * three are things a network can produce on its own, so none of them is an
     * error worth tearing the session down for.
     *
     * A keepalive arrives as an empty packet and comes back as an empty array,
     * which the caller drops rather than writing to the interface.
     */
    fun decapsulate(message: ByteArray): ByteArray? {
        if (message.size < HEADER_SIZE + WireGuardCrypto.TAG_SIZE) return null
        if (WireGuardHandshake.readLe32(message, 0) != transportType) return null
        if (WireGuardHandshake.readLe32(message, 4) != localIndex) return null

        val counter = WireGuardHandshake.readLe64(message, 8)
        // Checked before the AEAD so a flood of replays costs nothing.
        if (!replay.mayAccept(counter)) return null

        val plaintext = WireGuardCrypto.open(
            receiveKey, counter, message.copyOfRange(HEADER_SIZE, message.size), ByteArray(0)
        ) ?: return null

        // Only a message that authenticated advances the window; otherwise
        // anyone could burn counter space by sending garbage.
        replay.accept(counter)
        return plaintext
    }

    /**
     * The sliding window that stops a packet being accepted twice.
     *
     * A counter far enough behind the highest one seen is refused outright; one
     * inside the window is refused if its bit is already set. This is the same
     * shape as the kernel implementation's, at the same width.
     */
    private class ReplayWindow {
        private var highest = -1L
        private val bits = LongArray(WINDOW_WORDS)

        @Synchronized
        fun mayAccept(counter: Long): Boolean {
            if (counter < 0 || counter >= REJECT_AFTER_MESSAGES) return false
            if (counter > highest) return true
            if (highest - counter >= WINDOW_SIZE) return false
            return !isSet(counter)
        }

        @Synchronized
        fun accept(counter: Long) {
            if (counter > highest) {
                val shift = counter - highest
                if (shift >= WINDOW_SIZE) {
                    bits.fill(0)
                } else {
                    // Clear the range the window has just moved over, so a
                    // counter that comes round again is not mistaken for one
                    // already seen.
                    var c = highest + 1
                    while (c <= counter) {
                        clear(c)
                        c++
                    }
                }
                highest = counter
            }
            set(counter)
        }

        private fun index(counter: Long): Int =
            ((counter % WINDOW_SIZE) / 64).toInt()

        private fun mask(counter: Long): Long =
            1L shl ((counter % WINDOW_SIZE) % 64).toInt()

        private fun isSet(counter: Long) = bits[index(counter)] and mask(counter) != 0L
        private fun set(counter: Long) { bits[index(counter)] = bits[index(counter)] or mask(counter) }
        private fun clear(counter: Long) { bits[index(counter)] = bits[index(counter)] and mask(counter).inv() }
    }

    companion object {
        const val HEADER_SIZE = 16
        private const val PADDING_MULTIPLE = 16

        /** The kernel's window, in packets. */
        const val WINDOW_SIZE = 2048L
        private const val WINDOW_WORDS = (WINDOW_SIZE / 64).toInt()

        /**
         * Rekey well before the counter could wrap.
         *
         * The protocol's own limit is 2^64 - 2^13 - 1, which does not fit a
         * signed Long. It does not need to: a session is replaced at
         * REKEY_AFTER_MESSAGES, which is reached first by a factor of eight,
         * and even that is more packets than a link could carry in years.
         */
        const val REKEY_AFTER_MESSAGES = 1L shl 60
        const val REJECT_AFTER_MESSAGES = Long.MAX_VALUE - (1L shl 13)
    }
}
