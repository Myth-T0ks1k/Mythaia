import Foundation

/**
 * The `wg-quick` INI a WireGuard profile is stored as, written from the fields
 * a share link or a JSON outbound spreads the same settings over.
 *
 * Every importer goes through here instead of filling a `ProxyConfiguration`
 * itself: a server from a `wireguard://` link, an Xray outbound or a sing-box
 * endpoint becomes exactly the text a user could have pasted, is validated by
 * the one INI parser, and exports back as an INI like any other.
 */
enum WireGuardIni {

    struct Peer {
        var publicKey: String
        var endpointHost: String
        var endpointPort: Int
        var presharedKey: String? = nil
        var allowedIps: [String] = []
        var keepalive: Int = 0
    }

    static func build(
        privateKey: String,
        addresses: [String],
        peer: Peer,
        mtu: Int? = nil,
        reserved: Data? = nil,
        dns: [String] = []
    ) -> String {
        var lines: [String] = []
        lines.append("[Interface]")
        lines.append("PrivateKey = " + normalizeKey(privateKey))
        let cleanAddresses = addresses.map { LinkText.trim($0) }.filter { !$0.isEmpty }.map { withPrefix($0) }
        if !cleanAddresses.isEmpty { lines.append("Address = " + cleanAddresses.joined(separator: ", ")) }
        let cleanDns = dns.map { LinkText.trim($0) }.filter { !$0.isEmpty }
        if !cleanDns.isEmpty { lines.append("DNS = " + cleanDns.joined(separator: ", ")) }
        if let mtu = mtu, mtu > 0 { lines.append("MTU = \(mtu)") }
        // All zeroes is what Xray writes when there is nothing to say.
        if let reserved = reserved, reserved.count == 3, reserved.contains(where: { $0 != 0 }) {
            lines.append("Reserved = " + reserved.map { String($0) }.joined(separator: ","))
        }
        lines.append("")
        lines.append("[Peer]")
        lines.append("PublicKey = " + normalizeKey(peer.publicKey))
        if let psk = peer.presharedKey, !LinkText.isBlank(psk) {
            lines.append("PresharedKey = " + normalizeKey(psk))
        }
        var allowed = peer.allowedIps.map { LinkText.trim($0) }.filter { !$0.isEmpty }
        if allowed.isEmpty { allowed = ["0.0.0.0/0", "::/0"] }
        lines.append("AllowedIPs = " + allowed.joined(separator: ", "))
        lines.append("Endpoint = " + endpoint(peer.endpointHost, peer.endpointPort))
        if peer.keepalive > 0 { lines.append("PersistentKeepalive = \(peer.keepalive)") }
        return lines.joined(separator: "\n") + "\n"
    }

    /**
     * A key as the INI parser takes it: standard, padded base64.
     *
     * Links carry keys in whatever shape survived the trip — the URL-safe
     * alphabet, padding stripped, or hex as Xray also accepts — and each of
     * those is the same 32 bytes. Anything else is passed through untouched,
     * so the parser's refusal names the key that was actually there.
     */
    static func normalizeKey(_ text: String) -> String {
        let trimmed = LinkText.trim(text)
        if trimmed.utf8.count == 64, let bytes = LinkText.hexDecode(trimmed), bytes.count == 32 {
            return bytes.base64EncodedString()
        }
        let standard = trimmed.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return LinkText.padBase64(standard)
    }

    /// `10.0.0.2` as `10.0.0.2/32`: the INI wants a prefix, JSON outbounds often omit it.
    private static func withPrefix(_ address: String) -> String {
        if address.utf8.contains(UInt8(ascii: "/")) { return address }
        if address.utf8.contains(UInt8(ascii: ":")) {
            let bare = LinkText.removeSuffix(LinkText.removePrefix(address, "["), "]")
            return bare + "/128"
        }
        return address + "/32"
    }

    /// `host:port`, an IPv6 literal bracketed as the INI's Endpoint requires.
    static func endpoint(_ host: String, _ port: Int) -> String {
        let bare = LinkText.removeSuffix(LinkText.removePrefix(LinkText.trim(host), "["), "]")
        return bare.utf8.contains(UInt8(ascii: ":")) ? "[\(bare)]:\(port)" : "\(bare):\(port)"
    }

    /// `host:port` or `[v6]:port` as host and port; nil when there is no usable port.
    static func splitEndpoint(_ text: String) -> (host: String, port: Int)? {
        let trimmed = LinkText.trim(text)
        let bytes = Array(trimmed.utf8)
        var colon: Int? = nil
        if bytes.first == UInt8(ascii: "[") {
            if let close = LinkText.indexOf(bytes, Array("]:".utf8)), close > 0 { colon = close + 1 }
        } else {
            colon = bytes.lastIndex(of: UInt8(ascii: ":"))
        }
        guard let at = colon, at > 0 else { return nil }
        let host = LinkText.removeSuffix(LinkText.removePrefix(LinkText.string(bytes[..<at]), "["), "]")
        guard let port = Int(LinkText.string(bytes[(at + 1)...])), port >= 1 && port <= 65535 else { return nil }
        return host.isEmpty ? nil : (host, port)
    }

    /**
     * Reserved bytes from a JSON value: an array of three numbers (Xray,
     * sing-box) or a string in either form `WireGuardConfig.parseReserved`
     * reads. Nil when absent or not three bytes.
     */
    static func reservedFromJson(_ value: ImportJSON?) -> Data? {
        guard let value = value else { return nil }
        switch value {
        case .array(let items):
            let values = items.map { $0.intValue ?? -1 }
            guard values.count == 3, values.allSatisfy({ $0 >= 0 && $0 <= 255 }) else { return nil }
            return Data(values.map { UInt8($0) })
        case .string(let text):
            return WireGuardConfig.parseReserved(text)
        default:
            return nil
        }
    }
}
