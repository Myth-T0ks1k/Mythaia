import CQuic
import Foundation

/// The transport settings a QUIC connection is opened with, and the reasoning
/// behind each set of numbers.
///
/// Nearly everything that decides how a QUIC connection behaves is fixed before
/// its first packet leaves: the congestion controller bounds how fast it may
/// send, the flow-control windows bound how much may be outstanding before the
/// receiver has to acknowledge, and the transport parameters tell the peer what
/// it is allowed to do to us. None of it can be renegotiated afterwards, so each
/// protocol gets a preset here rather than having the numbers spread across
/// whichever code path happens to build the connection.
///
/// Values are `Int64` because QUIC writes every one of them as a
/// variable-length integer capped at 2^62 - 1 (RFC 9000 §16), which fits a
/// positive Int64 with room to spare.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
struct QuicTuning: Equatable {
    /// How fast the connection is allowed to send.
    let congestionControl: QuicCongestionControl

    /// The ceiling ngtcp2's per-stream flow-control auto-tuning may raise a
    /// stream's receive window to. Local only: there is no transport parameter
    /// for a ceiling, because the peer never learns anything except the window
    /// that has actually been granted so far.
    let maxStreamWindow: Int64

    /// The same auto-tuning ceiling for the connection-wide receive window.
    let maxWindow: Int64

    /// How much the peer may send us across the whole connection before it must wait.
    let initialMaxData: Int64

    /// Our receive window on bidirectional streams we open ourselves.
    let initialMaxStreamDataBidiLocal: Int64

    /// Our receive window on bidirectional streams the peer opens.
    let initialMaxStreamDataBidiRemote: Int64

    /// Our receive window on unidirectional streams the peer opens.
    let initialMaxStreamDataUni: Int64

    /// How many bidirectional streams the peer may have open at once.
    let initialMaxStreamsBidi: Int64

    /// How many unidirectional streams the peer may have open at once.
    let initialMaxStreamsUni: Int64

    /// How long a silent connection stays alive. Advertised; the effective
    /// timeout is the smaller of the two endpoints' values (RFC 9000 §10.1).
    let maxIdleTimeoutNanos: Int64

    /// How long the handshake may take before ngtcp2 abandons it. Local only.
    let handshakeTimeoutNanos: Int64

    /// The idle period after which ngtcp2 emits a PING to keep the path alive.
    /// Local only, and always shorter than `maxIdleTimeoutNanos`: a keepalive
    /// that fired after the peer had already timed out would be pointless.
    let keepAliveTimeoutNanos: Int64

    /// Whether we forbid ourselves changing local address. Left false
    /// throughout: being permitted to move is the prerequisite for connection
    /// migration, which is what lets a tunnel survive a handover between
    /// Wi-Fi and cellular instead of dying with the old socket.
    let disableActiveMigration: Bool

    /// Throws when a value cannot go on the wire as the parameter it is.
    init(
        congestionControl: QuicCongestionControl,
        maxStreamWindow: Int64,
        maxWindow: Int64,
        initialMaxData: Int64,
        initialMaxStreamDataBidiLocal: Int64,
        initialMaxStreamDataBidiRemote: Int64,
        initialMaxStreamDataUni: Int64,
        initialMaxStreamsBidi: Int64,
        initialMaxStreamsUni: Int64,
        maxIdleTimeoutNanos: Int64,
        handshakeTimeoutNanos: Int64,
        keepAliveTimeoutNanos: Int64,
        disableActiveMigration: Bool
    ) throws {
        let byteCounts = [
            maxStreamWindow, maxWindow, initialMaxData,
            initialMaxStreamDataBidiLocal, initialMaxStreamDataBidiRemote, initialMaxStreamDataUni,
        ]
        guard byteCounts.allSatisfy({ QuicVarInt.isEncodable($0) }) else {
            throw MythaiaError.invalidConfiguration("flow-control values must fit a QUIC varint: \(byteCounts)")
        }
        guard (0...QuicTuning.maxStreams).contains(initialMaxStreamsBidi),
              (0...QuicTuning.maxStreams).contains(initialMaxStreamsUni) else {
            throw MythaiaError.invalidConfiguration("stream counts must not exceed 2^60 (RFC 9000 §18.2)")
        }
        guard maxIdleTimeoutNanos >= 0, handshakeTimeoutNanos >= 0, keepAliveTimeoutNanos >= 0 else {
            throw MythaiaError.invalidConfiguration("timeouts cannot be negative")
        }
        self.congestionControl = congestionControl
        self.maxStreamWindow = maxStreamWindow
        self.maxWindow = maxWindow
        self.initialMaxData = initialMaxData
        self.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal
        self.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote
        self.initialMaxStreamDataUni = initialMaxStreamDataUni
        self.initialMaxStreamsBidi = initialMaxStreamsBidi
        self.initialMaxStreamsUni = initialMaxStreamsUni
        self.maxIdleTimeoutNanos = maxIdleTimeoutNanos
        self.handshakeTimeoutNanos = handshakeTimeoutNanos
        self.keepAliveTimeoutNanos = keepAliveTimeoutNanos
        self.disableActiveMigration = disableActiveMigration
    }

    /// `maxIdleTimeoutNanos` in the unit RFC 9000 §18.2 puts on the wire.
    ///
    /// ngtcp2 keeps every duration in nanoseconds, which is what the fields
    /// above hold; the transport parameter itself is milliseconds, so the two
    /// are not interchangeable and the conversion belongs somewhere named.
    var maxIdleTimeoutMillis: Int64 { maxIdleTimeoutNanos / 1_000_000 }

    /// Everything the bridge sets on the connection, in its order.
    ///
    /// The first seven are transport parameters the peer is told. The last
    /// five are local engine settings the peer never sees: the congestion
    /// controller, the two flow-control auto-tuning ceilings, and the
    /// handshake and keep-alive timeouts — without them a large download
    /// could not grow its window and a Hysteria session idled out at 30
    /// seconds with no keep-alive.
    ///
    /// Brutal is not an ngtcp2 algorithm, so what ngtcp2 is started on is
    /// BBR, the closest rate-probing match.
    func toNativeArray() -> [Int64] {
        return [
            initialMaxData,
            initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni,
            initialMaxStreamsBidi,
            initialMaxStreamsUni,
            maxIdleTimeoutNanos,
            Int64(nativeCongestionAlgorithm),
            maxWindow,
            maxStreamWindow,
            handshakeTimeoutNanos,
            keepAliveTimeoutNanos,
        ]
    }

    /// The same values as the C bridge takes them.
    var nativeSettings: cquic_settings {
        var settings = cquic_settings()
        settings.initial_max_data = UInt64(initialMaxData)
        settings.initial_max_stream_data_bidi_local = UInt64(initialMaxStreamDataBidiLocal)
        settings.initial_max_stream_data_bidi_remote = UInt64(initialMaxStreamDataBidiRemote)
        settings.initial_max_stream_data_uni = UInt64(initialMaxStreamDataUni)
        settings.initial_max_streams_bidi = UInt64(initialMaxStreamsBidi)
        settings.initial_max_streams_uni = UInt64(initialMaxStreamsUni)
        settings.max_idle_timeout_ns = UInt64(maxIdleTimeoutNanos)
        settings.cc_algo = Int32(nativeCongestionAlgorithm)
        settings.max_window = UInt64(maxWindow)
        settings.max_stream_window = UInt64(maxStreamWindow)
        settings.handshake_timeout_ns = UInt64(handshakeTimeoutNanos)
        settings.keep_alive_timeout_ns = UInt64(keepAliveTimeoutNanos)
        return settings
    }

    /// The algorithm ngtcp2 is created with; Brutal maps to BBR.
    var nativeCongestionAlgorithm: Int {
        if case .brutal = congestionControl {
            return QuicCongestionControl.ngtcp2CcAlgoBbr
        }
        return congestionControl.ngtcp2Algorithm
    }

    /// What this tuning puts in the transport parameters extension, paired
    /// with the identifiers RFC 9000 §18.2 assigns.
    ///
    /// The order is ascending by identifier, which is merely tidy: RFC 9000
    /// §18 attaches no meaning to the order parameters appear in.
    /// `disable_active_migration` is present only when it is set, because it
    /// is a zero-length parameter whose whole meaning is its presence — hence
    /// the nil value.
    var advertisedParameters: [TransportParameter] {
        var out: [TransportParameter] = [
            TransportParameter(id: QuicTransportParameterId.maxIdleTimeout, value: maxIdleTimeoutMillis),
            TransportParameter(id: QuicTransportParameterId.initialMaxData, value: initialMaxData),
            TransportParameter(id: QuicTransportParameterId.initialMaxStreamDataBidiLocal, value: initialMaxStreamDataBidiLocal),
            TransportParameter(id: QuicTransportParameterId.initialMaxStreamDataBidiRemote, value: initialMaxStreamDataBidiRemote),
            TransportParameter(id: QuicTransportParameterId.initialMaxStreamDataUni, value: initialMaxStreamDataUni),
            TransportParameter(id: QuicTransportParameterId.initialMaxStreamsBidi, value: initialMaxStreamsBidi),
            TransportParameter(id: QuicTransportParameterId.initialMaxStreamsUni, value: initialMaxStreamsUni),
        ]
        if disableActiveMigration {
            out.append(TransportParameter(id: QuicTransportParameterId.disableActiveMigration, value: nil))
        }
        return out
    }

    /// One transport parameter: its RFC 9000 §18.2 identifier and its value,
    /// or nil for the zero-length forms that mean something by existing at all.
    struct TransportParameter: Equatable {
        let id: Int
        let value: Int64?
    }

    /// The largest stream count a transport parameter may carry.
    ///
    /// RFC 9000 §18.2 caps `initial_max_streams_bidi` and `_uni` at 2^60
    /// rather than at the varint maximum, because a larger count could not be
    /// turned into a stream ID: the ID is the count shifted left twice plus
    /// two type bits, and that has to stay inside 2^62 - 1.
    static let maxStreams: Int64 = 1 << 60

    private static let secondNanos: Int64 = 1_000_000_000
    private static let mib: Int64 = 1024 * 1024

    /// NaiveProxy, which is Chromium's QUIC stack wearing a proxy.
    ///
    /// The windows are the largest of any preset because one connection
    /// carries an entire browsing session: dozens of concurrent requests
    /// multiplexed over streams that all draw on the same connection-level
    /// credit. The stream counts are generous for the same reason. CUBIC
    /// rather than BBR, because Chrome sends CUBIC. Hysteria2 and TUIC use
    /// this preset too: it grants the unidirectional credit HTTP/3 needs for
    /// the server's control stream.
    static let naive = try! QuicTuning(
        congestionControl: .cubic,
        maxStreamWindow: 64 * mib,
        maxWindow: 128 * mib,
        initialMaxData: 64 * mib,
        initialMaxStreamDataBidiLocal: 16 * mib,
        initialMaxStreamDataBidiRemote: 16 * mib,
        initialMaxStreamDataUni: 16 * mib,
        initialMaxStreamsBidi: 1024,
        initialMaxStreamsUni: 100,
        maxIdleTimeoutNanos: 30 * secondNanos,
        handshakeTimeoutNanos: 10 * secondNanos,
        keepAliveTimeoutNanos: 15 * secondNanos,
        disableActiveMigration: false
    )

    /// A tunnel where every stream is ours: the server answers, it never
    /// calls. Granting the peer no streams means the two per-peer-stream
    /// windows can be zero as well; only `initialMaxStreamDataBidiLocal` is
    /// funded, because it governs the streams the client opens. BBR because
    /// the path is a long-lived bulk tunnel rather than a browser.
    static let nowhere = try! QuicTuning(
        congestionControl: .bbr,
        maxStreamWindow: 16 * mib,
        maxWindow: 32 * mib,
        initialMaxData: 8 * mib,
        initialMaxStreamDataBidiLocal: 4 * mib,
        initialMaxStreamDataBidiRemote: 0,
        initialMaxStreamDataUni: 0,
        initialMaxStreamsBidi: 0,
        initialMaxStreamsUni: 0,
        maxIdleTimeoutNanos: 30 * secondNanos,
        handshakeTimeoutNanos: 10 * secondNanos,
        keepAliveTimeoutNanos: 10 * secondNanos,
        disableActiveMigration: false
    )

    /// Hysteria2, whose two controllers want opposite window sizes.
    ///
    /// Under Brutal the windows are deliberately small: Brutal does not search
    /// for a rate — it is told one, and paces to it — so a large window would
    /// only let the sender burst past the rate it declared. Under BBR the
    /// window has to be able to grow, because BBR probes upward until the
    /// delivery rate stops improving.
    ///
    /// `uploadMbps` is the client's declared upstream in megabits per second;
    /// Brutal is paced in bytes per second, so it is divided by eight. A
    /// negative value clamps to zero rather than wrapping, and a huge one to
    /// Int32.max, so the conversion to bytes cannot overflow.
    static func hysteria(_ congestionControl: HysteriaCongestionControl, uploadMbps: Int) -> QuicTuning {
        switch congestionControl {
        case .brutal:
            return try! QuicTuning(
                congestionControl: .brutal(initialBytesPerSecond: Int64(min(max(0, uploadMbps), Int(Int32.max))) * 1_000_000 / 8),
                maxStreamWindow: 2 * mib,
                maxWindow: 4 * mib,
                initialMaxData: 4 * mib,
                initialMaxStreamDataBidiLocal: 2 * mib,
                initialMaxStreamDataBidiRemote: 2 * mib,
                initialMaxStreamDataUni: 2 * mib,
                initialMaxStreamsBidi: 1024,
                initialMaxStreamsUni: 16,
                maxIdleTimeoutNanos: 30 * secondNanos,
                handshakeTimeoutNanos: 10 * secondNanos,
                keepAliveTimeoutNanos: 10 * secondNanos,
                disableActiveMigration: false
            )
        case .bbr:
            return try! QuicTuning(
                congestionControl: .bbr,
                maxStreamWindow: 16 * mib,
                maxWindow: 32 * mib,
                initialMaxData: 8 * mib,
                initialMaxStreamDataBidiLocal: 2 * mib,
                initialMaxStreamDataBidiRemote: 2 * mib,
                initialMaxStreamDataUni: 2 * mib,
                initialMaxStreamsBidi: 1024,
                initialMaxStreamsUni: 16,
                maxIdleTimeoutNanos: 30 * secondNanos,
                handshakeTimeoutNanos: 10 * secondNanos,
                keepAliveTimeoutNanos: 10 * secondNanos,
                disableActiveMigration: false
            )
        }
    }
}

/// Which controller decides the send rate.
///
/// The first three are ngtcp2's own and are chosen by handing it the matching
/// algorithm number. Brutal is not ngtcp2's: Hysteria's controller ignores
/// loss and paces to a declared rate. It reports CUBIC as its own algorithm
/// and is started on BBR (see `QuicTuning.nativeCongestionAlgorithm`).
enum QuicCongestionControl: Equatable {
    case reno
    case cubic
    case bbr
    /// Hysteria's Brutal controller, opening at `initialBytesPerSecond` and
    /// normally corrected by the server once it has seen the client's
    /// declared bandwidth.
    case brutal(initialBytesPerSecond: Int64)

    /// `ngtcp2_cc_algo`, as the vendored `ngtcp2.h` numbers it.
    static let ngtcp2CcAlgoReno = 0x00
    static let ngtcp2CcAlgoCubic = 0x01
    static let ngtcp2CcAlgoBbr = 0x02

    /// The `ngtcp2_cc_algo` a connection is created with.
    var ngtcp2Algorithm: Int {
        switch self {
        case .reno: return QuicCongestionControl.ngtcp2CcAlgoReno
        case .cubic: return QuicCongestionControl.ngtcp2CcAlgoCubic
        case .bbr: return QuicCongestionControl.ngtcp2CcAlgoBbr
        case .brutal: return QuicCongestionControl.ngtcp2CcAlgoCubic
        }
    }
}

/// The controller a Hysteria2 endpoint is configured for.
///
/// Brutal needs a declared bandwidth to pace to, so the absence of one in a
/// server's link is what selects BBR — see `ProxyConfiguration.hysteriaUpMbps`,
/// which is left nil rather than defaulted for exactly that reason.
enum HysteriaCongestionControl {
    case brutal
    case bbr
}

/// Transport parameter identifiers, from the registry in RFC 9000 §18.2.
///
/// Only the ones this client sends are listed. They are fixed by the RFC and
/// never negotiated: a wrong number here would not fail loudly, it would make
/// a peer silently ignore a limit and then violate it.
enum QuicTransportParameterId {
    static let maxIdleTimeout = 0x01
    static let initialMaxData = 0x04
    static let initialMaxStreamDataBidiLocal = 0x05
    static let initialMaxStreamDataBidiRemote = 0x06
    static let initialMaxStreamDataUni = 0x07
    static let initialMaxStreamsBidi = 0x08
    static let initialMaxStreamsUni = 0x09
    static let disableActiveMigration = 0x0c
}
