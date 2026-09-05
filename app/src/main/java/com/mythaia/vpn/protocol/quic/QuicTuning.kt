package com.mythaia.vpn.protocol.quic

/**
 * The transport settings a QUIC connection is opened with, and the reasoning
 * behind each set of numbers.
 *
 * Nearly everything that decides how a QUIC connection behaves is fixed before
 * its first packet leaves: the congestion controller bounds how fast it may
 * send, the flow-control windows bound how much may be outstanding before the
 * receiver has to acknowledge, and the transport parameters tell the peer what
 * it is allowed to do to us. None of it can be renegotiated afterwards, so each
 * protocol gets a preset here rather than having the numbers spread across
 * whichever code path happens to build the connection.
 *
 * Values are [Long] rather than an unsigned type because QUIC writes every one
 * of them as a variable-length integer capped at 2^62 - 1 (RFC 9000 §16), which
 * fits a positive Long with room to spare.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
data class QuicTuning(

    /** How fast the connection is allowed to send. */
    val congestionControl: QuicCongestionControl,

    /**
     * The ceiling ngtcp2's per-stream flow-control auto-tuning may raise a
     * stream's receive window to.
     *
     * Local only, and deliberately so: there is no transport parameter for a
     * ceiling, because the peer never learns anything except the window that
     * has actually been granted so far.
     */
    val maxStreamWindow: Long,

    /** The same auto-tuning ceiling for the connection-wide receive window. */
    val maxWindow: Long,

    /** How much the peer may send us across the whole connection before it must wait. */
    val initialMaxData: Long,

    /** Our receive window on bidirectional streams we open ourselves. */
    val initialMaxStreamDataBidiLocal: Long,

    /** Our receive window on bidirectional streams the peer opens. */
    val initialMaxStreamDataBidiRemote: Long,

    /** Our receive window on unidirectional streams the peer opens. */
    val initialMaxStreamDataUni: Long,

    /** How many bidirectional streams the peer may have open at once. */
    val initialMaxStreamsBidi: Long,

    /** How many unidirectional streams the peer may have open at once. */
    val initialMaxStreamsUni: Long,

    /**
     * How long a silent connection stays alive. Advertised; the effective
     * timeout is the smaller of the two endpoints' values (RFC 9000 §10.1).
     */
    val maxIdleTimeoutNanos: Long,

    /** How long the handshake may take before ngtcp2 abandons it. Local only. */
    val handshakeTimeoutNanos: Long,

    /**
     * The idle period after which ngtcp2 emits a PING to keep the path alive.
     * Local only, and always shorter than [maxIdleTimeoutNanos] — a keepalive
     * that fired after the peer had already timed out would be pointless.
     */
    val keepAliveTimeoutNanos: Long,

    /**
     * Whether we forbid ourselves changing local address.
     *
     * Left false throughout. Being permitted to move is the prerequisite for
     * connection migration, which is what lets a tunnel survive a handover
     * between Wi-Fi and cellular instead of dying with the old socket.
     */
    val disableActiveMigration: Boolean
) {

    init {
        val byteCounts = listOf(
            maxStreamWindow, maxWindow, initialMaxData,
            initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote, initialMaxStreamDataUni
        )
        require(byteCounts.all { it in 0..QuicVarInt.MAX }) {
            "flow-control values must fit a QUIC varint: $byteCounts"
        }
        require(initialMaxStreamsBidi in 0..MAX_STREAMS && initialMaxStreamsUni in 0..MAX_STREAMS) {
            "stream counts must not exceed 2^60 (RFC 9000 §18.2)"
        }
        require(maxIdleTimeoutNanos >= 0 && handshakeTimeoutNanos >= 0 && keepAliveTimeoutNanos >= 0) {
            "timeouts cannot be negative"
        }
    }

    /**
     * [maxIdleTimeoutNanos] in the unit RFC 9000 §18.2 puts on the wire.
     *
     * ngtcp2 keeps every duration in nanoseconds, which is what the fields
     * above hold; the transport parameter itself is milliseconds, so the two
     * are not interchangeable and the conversion belongs somewhere named.
     */
    val maxIdleTimeoutMillis: Long get() = maxIdleTimeoutNanos / 1_000_000

    /**
     * What this tuning actually puts in the transport parameters extension,
     * paired with the identifiers RFC 9000 §18.2 assigns.
     *
     * The order is ascending by identifier, which is merely tidy: RFC 9000 §18
     * attaches no meaning to the order parameters appear in. `disable_active_
     * migration` is present only when it is set, because it is a zero-length
     * parameter whose whole meaning is its presence — hence the null value.
     *
     * The list stops at identifier and value. Writing them out as the
     * `quic_transport_parameters` extension belongs to whatever builds the
     * ClientHello, since that is where the extension lives; what this settles,
     * in one place, is which field goes under which number.
     */
    /**
     * The seven limits the JNI bridge sets on the connection, in its order.
     *
     * A flat array rather than seven parameters: the bridge reads them by
     * index, and adding one in the wrong place there is a mistake that shows up
     * as a connection whose limits are quietly not what was asked for.
     */
    fun toNativeArray(): LongArray = longArrayOf(
        initialMaxData,
        initialMaxStreamDataBidiLocal,
        initialMaxStreamDataBidiRemote,
        initialMaxStreamDataUni,
        initialMaxStreamsBidi,
        initialMaxStreamsUni,
        maxIdleTimeoutNanos
    )

    val advertisedParameters: List<TransportParameter>
        get() = buildList {
            add(TransportParameter(QuicTransportParameterId.MAX_IDLE_TIMEOUT, maxIdleTimeoutMillis))
            add(TransportParameter(QuicTransportParameterId.INITIAL_MAX_DATA, initialMaxData))
            add(
                TransportParameter(
                    QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                    initialMaxStreamDataBidiLocal
                )
            )
            add(
                TransportParameter(
                    QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                    initialMaxStreamDataBidiRemote
                )
            )
            add(
                TransportParameter(
                    QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_UNI,
                    initialMaxStreamDataUni
                )
            )
            add(TransportParameter(QuicTransportParameterId.INITIAL_MAX_STREAMS_BIDI, initialMaxStreamsBidi))
            add(TransportParameter(QuicTransportParameterId.INITIAL_MAX_STREAMS_UNI, initialMaxStreamsUni))
            if (disableActiveMigration) {
                add(TransportParameter(QuicTransportParameterId.DISABLE_ACTIVE_MIGRATION, null))
            }
        }

    /**
     * One transport parameter: its RFC 9000 §18.2 identifier and its value, or
     * null for the zero-length forms that mean something by existing at all.
     */
    data class TransportParameter(val id: Int, val value: Long?)

    companion object {

        /**
         * The largest stream count a transport parameter may carry.
         *
         * RFC 9000 §18.2 caps `initial_max_streams_bidi` and `_uni` at 2^60
         * rather than at the varint maximum, because a larger count could not
         * be turned into a stream ID: the ID is the count shifted left twice
         * plus two type bits, and that has to stay inside 2^62 - 1.
         */
        const val MAX_STREAMS = 1L shl 60

        private const val SECOND_NANOS = 1_000_000_000L
        private const val MIB = 1024L * 1024L

        /**
         * NaiveProxy, which is Chromium's QUIC stack wearing a proxy.
         *
         * The windows are the largest of any preset because one connection
         * carries an entire browsing session: dozens of concurrent requests
         * multiplexed over streams that all draw on the same connection-level
         * credit, so being window-limited here would throttle every tab at
         * once. The stream counts are generous for the same reason — a client
         * that runs out has to wait a round trip for a MAX_STREAMS frame
         * before it can fetch the next subresource.
         *
         * CUBIC rather than BBR, and that is the interesting choice: Naive's
         * whole purpose is to be indistinguishable from ordinary Chrome
         * traffic, and Chrome sends CUBIC. A more aggressive controller would
         * perform better and look wrong.
         */
        val NAIVE = QuicTuning(
            congestionControl = QuicCongestionControl.Cubic,
            maxStreamWindow = 64 * MIB,
            maxWindow = 128 * MIB,
            initialMaxData = 64 * MIB,
            initialMaxStreamDataBidiLocal = 16 * MIB,
            initialMaxStreamDataBidiRemote = 16 * MIB,
            initialMaxStreamDataUni = 16 * MIB,
            initialMaxStreamsBidi = 1024,
            initialMaxStreamsUni = 100,
            maxIdleTimeoutNanos = 30 * SECOND_NANOS,
            handshakeTimeoutNanos = 10 * SECOND_NANOS,
            keepAliveTimeoutNanos = 15 * SECOND_NANOS,
            disableActiveMigration = false
        )

        /**
         * A tunnel where every stream is ours: the server answers, it never
         * calls.
         *
         * That is what the zeroes say. Granting the peer no bidirectional and
         * no unidirectional streams means the two per-peer-stream windows can
         * be zero as well, since no stream will ever exist to spend them, and
         * a nonzero allowance would only be an invitation. Only
         * [initialMaxStreamDataBidiLocal] is funded, because it governs the
         * streams the client opens.
         *
         * BBR because the path is a long-lived bulk tunnel rather than a
         * browser: it should find the available bandwidth and hold it, not
         * back off on every isolated loss the way a loss-based controller does
         * on a lossy mobile link.
         */
        val NOWHERE = QuicTuning(
            congestionControl = QuicCongestionControl.Bbr,
            maxStreamWindow = 16 * MIB,
            maxWindow = 32 * MIB,
            initialMaxData = 8 * MIB,
            initialMaxStreamDataBidiLocal = 4 * MIB,
            initialMaxStreamDataBidiRemote = 0,
            initialMaxStreamDataUni = 0,
            initialMaxStreamsBidi = 0,
            initialMaxStreamsUni = 0,
            maxIdleTimeoutNanos = 30 * SECOND_NANOS,
            handshakeTimeoutNanos = 10 * SECOND_NANOS,
            keepAliveTimeoutNanos = 10 * SECOND_NANOS,
            disableActiveMigration = false
        )

        /**
         * Hysteria2, whose two controllers want opposite window sizes.
         *
         * Under Brutal the windows are deliberately small. Brutal does not
         * search for a rate — it is told one, and paces to it — so a large
         * window buys nothing and costs something: it would let the sender
         * burst well past the rate it declared, which is the one thing a
         * controller that ignores loss must not do, and it would hold that
         * burst in memory on a phone. Under BBR the window has to be able to
         * grow, because BBR's whole method is to probe upward until the
         * delivery rate stops improving, and a small ceiling would cap it
         * before it found the path's capacity.
         *
         * [uploadMbps] is the client's declared upstream in megabits per
         * second; Brutal is paced in bytes per second, so it is divided by
         * eight. A negative or missing value clamps to zero rather than
         * wrapping, and the rate is only a starting point in any case: the
         * server's `Hysteria-CC-RX` response replaces it once authentication
         * has completed.
         */
        fun hysteria(congestionControl: HysteriaCongestionControl, uploadMbps: Int): QuicTuning =
            when (congestionControl) {
                HysteriaCongestionControl.BRUTAL -> QuicTuning(
                    congestionControl = QuicCongestionControl.Brutal(
                        initialBytesPerSecond = maxOf(0, uploadMbps).toLong() * 1_000_000L / 8L
                    ),
                    maxStreamWindow = 2 * MIB,
                    maxWindow = 4 * MIB,
                    initialMaxData = 4 * MIB,
                    initialMaxStreamDataBidiLocal = 2 * MIB,
                    initialMaxStreamDataBidiRemote = 2 * MIB,
                    initialMaxStreamDataUni = 2 * MIB,
                    initialMaxStreamsBidi = 1024,
                    initialMaxStreamsUni = 16,
                    maxIdleTimeoutNanos = 30 * SECOND_NANOS,
                    handshakeTimeoutNanos = 10 * SECOND_NANOS,
                    keepAliveTimeoutNanos = 10 * SECOND_NANOS,
                    disableActiveMigration = false
                )

                HysteriaCongestionControl.BBR -> QuicTuning(
                    congestionControl = QuicCongestionControl.Bbr,
                    maxStreamWindow = 16 * MIB,
                    maxWindow = 32 * MIB,
                    initialMaxData = 8 * MIB,
                    initialMaxStreamDataBidiLocal = 2 * MIB,
                    initialMaxStreamDataBidiRemote = 2 * MIB,
                    initialMaxStreamDataUni = 2 * MIB,
                    initialMaxStreamsBidi = 1024,
                    initialMaxStreamsUni = 16,
                    maxIdleTimeoutNanos = 30 * SECOND_NANOS,
                    handshakeTimeoutNanos = 10 * SECOND_NANOS,
                    keepAliveTimeoutNanos = 10 * SECOND_NANOS,
                    disableActiveMigration = false
                )
            }
    }
}

/**
 * Which controller decides the send rate.
 *
 * The first three are ngtcp2's own and are chosen by handing it the matching
 * algorithm number. Brutal is not ngtcp2's: Hysteria's controller ignores loss
 * and paces to a declared rate, so a connection is initialised with CUBIC and
 * then has its controller callbacks replaced once the connection object exists.
 * Reporting CUBIC for [Brutal] is therefore the truth about what ngtcp2 is
 * started with, not a fallback.
 */
sealed class QuicCongestionControl {

    /** The `ngtcp2_cc_algo` a connection is created with. */
    abstract val ngtcp2Algorithm: Int

    data object Reno : QuicCongestionControl() {
        override val ngtcp2Algorithm = NGTCP2_CC_ALGO_RENO
    }

    data object Cubic : QuicCongestionControl() {
        override val ngtcp2Algorithm = NGTCP2_CC_ALGO_CUBIC
    }

    data object Bbr : QuicCongestionControl() {
        override val ngtcp2Algorithm = NGTCP2_CC_ALGO_BBR
    }

    /**
     * Hysteria's Brutal controller, opening at [initialBytesPerSecond] and
     * normally corrected upward or downward by the server once it has seen the
     * client's declared bandwidth.
     */
    data class Brutal(val initialBytesPerSecond: Long) : QuicCongestionControl() {
        override val ngtcp2Algorithm = NGTCP2_CC_ALGO_CUBIC
    }

    companion object {
        /** `ngtcp2_cc_algo`, as the vendored `ngtcp2.h` numbers it. */
        const val NGTCP2_CC_ALGO_RENO = 0x00
        const val NGTCP2_CC_ALGO_CUBIC = 0x01
        const val NGTCP2_CC_ALGO_BBR = 0x02
    }
}

/**
 * The controller a Hysteria2 endpoint is configured for.
 *
 * Brutal needs a declared bandwidth to pace to, so the absence of one in a
 * server's link is what selects BBR — see `ProxyConfiguration.hysteriaUpMbps`,
 * which is left null rather than defaulted for exactly that reason.
 */
enum class HysteriaCongestionControl { BRUTAL, BBR }

/**
 * Transport parameter identifiers, from the registry in RFC 9000 §18.2.
 *
 * Only the ones this client sends are listed. They are fixed by the RFC and
 * never negotiated, which is what makes them worth naming: a wrong number here
 * would not fail loudly, it would make a peer silently ignore a limit and then
 * violate it.
 */
object QuicTransportParameterId {
    const val MAX_IDLE_TIMEOUT = 0x01
    const val INITIAL_MAX_DATA = 0x04
    const val INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05
    const val INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06
    const val INITIAL_MAX_STREAM_DATA_UNI = 0x07
    const val INITIAL_MAX_STREAMS_BIDI = 0x08
    const val INITIAL_MAX_STREAMS_UNI = 0x09
    const val DISABLE_ACTIVE_MIGRATION = 0x0c
}
