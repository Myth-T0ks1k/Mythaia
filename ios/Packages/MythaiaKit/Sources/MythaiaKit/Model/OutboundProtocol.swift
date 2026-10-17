import Foundation

public enum OutboundProtocol: String, Codable, CaseIterable, Hashable {
    case vless = "vless"
    case trojan = "trojan"
    case shadowsocks = "shadowsocks"
    case socks5 = "socks5"
    case naiveHttp11 = "http11"
    case naiveHttp2 = "http2"
    case hysteria2 = "hysteria2"
    case anytls = "anytls"
    case vmess = "vmess"
    case tuic = "tuic"
    case wireguard = "wireguard"
    case sudoku = "sudoku"
    case nowhere = "nowhere"

    public var raw: String { rawValue }

    public var isNaive: Bool { self == .naiveHttp11 || self == .naiveHttp2 }

    /**
     * Whether an outbound can actually be dialled yet.
     *
     * Links for every protocol parse, round-trip and survive a subscription
     * refresh, so a subscription carrying them is not silently truncated. The
     * property stays because a subscription may carry something a future
     * build adds, and failing at the dial with the name in the message beats
     * a silent timeout.
     */
    public var isImplemented: Bool { true }

    /**
     * Whether this outbound is a layer-3 interface rather than a stream proxy.
     *
     * WireGuard carries whole IP packets, so it replaces the packet stack
     * instead of being dialled per flow. Domain routing rules do not apply to
     * it — its own AllowedIPs decide what enters the tunnel.
     */
    public var isLayer3: Bool { self == .wireguard }

    public var displayName: String {
        switch self {
        case .vless: return "VLESS"
        case .trojan: return "Trojan"
        case .shadowsocks: return "Shadowsocks"
        case .socks5: return "SOCKS5"
        case .naiveHttp11: return "HTTPS"
        case .naiveHttp2: return "HTTP/2"
        case .hysteria2: return "Hysteria2"
        case .anytls: return "AnyTLS"
        case .vmess: return "VMess"
        case .tuic: return "TUIC"
        case .wireguard: return "WireGuard"
        case .sudoku: return "Sudoku"
        case .nowhere: return "Nowhere"
        }
    }

    /**
     * Whether the tunnel layer should wait briefly for the app's first bytes
     * and hand them to the connect, so the protocol writes its request header
     * and those bytes together (and, with nothing to wait for, the header
     * alone). VLESS and VMess embed them in the handshake; Trojan and
     * Shadowsocks write a lazy header that otherwise never left the client
     * when the server speaks first (SSH, SMTP, IMAP).
     */
    public var handshakeCarriesInitialData: Bool {
        self == .vless || self == .vmess || self == .trojan || self == .shadowsocks
    }

    /// The stored spelling, older aliases included; nil for one this build does not know.
    public static func fromStoredName(_ raw: String) -> OutboundProtocol? {
        switch raw {
        case "vless": return .vless
        case "trojan": return .trojan
        case "shadowsocks": return .shadowsocks
        case "socks5": return .socks5
        case "http11", "naive_http11": return .naiveHttp11
        case "http2", "naive_http2": return .naiveHttp2
        case "hysteria2", "hy2": return .hysteria2
        case "anytls": return .anytls
        case "vmess": return .vmess
        case "tuic": return .tuic
        case "wireguard", "wg", "awg", "amneziawg": return .wireguard
        case "sudoku": return .sudoku
        case "nowhere": return .nowhere
        default: return nil
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let value = OutboundProtocol.fromStoredName(raw) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown outbound protocol: \(raw)")
        }
        self = value
    }
}

public enum NaiveProtocol: String, Codable, CaseIterable, Hashable {
    case http11 = "http11"
    case http2 = "http2"
}
