import Foundation

/// How a Hysteria2 node asks for its UDP datagrams to be disguised.
///
/// This is the configuration, not the transformation: it is what a
/// `hysteria2://` link or a stored profile can say, and it is what
/// `HysteriaObfuscators.make` turns into something that touches bytes. The two
/// are kept apart because the configuration has to survive storage and
/// comparison, while an obfuscator owns randomness and, for gecko, live
/// reassembly state.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
enum HysteriaObfuscation: Equatable {
    /// Plain XOR obfuscation.
    case salamander(password: String)
    /// Salamander plus handshake fragmentation. The bounds are the size
    /// window each emitted datagram is padded into, held exactly as given so
    /// a stored configuration compares equal to the one written; they are
    /// normalized where they are used.
    case gecko(password: String, minPacketSize: Int, maxPacketSize: Int)

    /// Gecko packet-size bounds, in bytes.
    static let geckoMinPacketSizeDefault = 512
    static let geckoMaxPacketSizeDefault = 1200
    /// Anything outside this is clamped; the upper end is a safe MTU ceiling.
    static let geckoPacketSizeRange = 0...2048

    /// The shared secret both ends derive the keystream from.
    var password: String {
        switch self {
        case .salamander(let password): return password
        case .gecko(let password, _, _): return password
        }
    }

    /// The tag used on the wire, in links and in stored JSON.
    var typeTag: String {
        switch self {
        case .salamander: return "salamander"
        case .gecko: return "gecko"
        }
    }

    /// Settles gecko's bounds into a usable pair: absent or non-positive
    /// values fall back to the defaults, both ends are clamped, and a maximum
    /// below the minimum is raised to meet it rather than rejected — the
    /// bounds only shape padding, so nonsense costs traffic-analysis
    /// resistance, not correctness.
    static func normalizedGeckoSizes(_ minimum: Int?, _ maximum: Int?) -> (Int, Int) {
        func clamp(_ value: Int) -> Int {
            return Swift.min(Swift.max(value, geckoPacketSizeRange.lowerBound), geckoPacketSizeRange.upperBound)
        }
        let low = clamp((minimum ?? 0) > 0 ? minimum! : geckoMinPacketSizeDefault)
        let high = clamp((maximum ?? 0) > 0 ? maximum! : geckoMaxPacketSizeDefault)
        return high >= low ? (low, high) : (low, low)
    }

    /// A configuration from a wire `type`, or nil for an empty or unknown
    /// type — which leaves the caller to decide whether that means "no
    /// obfuscation" or "a node this build cannot speak to".
    static func make(type: String?, password: String?, geckoMinPacketSize: Int? = nil,
                     geckoMaxPacketSize: Int? = nil) -> HysteriaObfuscation? {
        guard let type = type, !type.isEmpty else { return nil }
        let secret = password ?? ""
        switch type.lowercased() {
        case "salamander":
            return .salamander(password: secret)
        case "gecko":
            let (low, high) = normalizedGeckoSizes(geckoMinPacketSize, geckoMaxPacketSize)
            return .gecko(password: secret, minPacketSize: low, maxPacketSize: high)
        default:
            return nil
        }
    }
}
