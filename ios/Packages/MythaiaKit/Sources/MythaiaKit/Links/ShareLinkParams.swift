import Foundation

/// The query-string readers every share-link scheme shares.
enum ShareLinkParams {

    /// `value` when it is neither nil nor empty.
    static func nonEmpty(_ value: String?) -> String? {
        guard let value = value, !value.isEmpty else { return nil }
        return value
    }

    /// `alpn=h2,%20http/1.1` — entries trimmed, empties dropped.
    static func parseAlpn(_ raw: String?) -> [String]? {
        guard let raw = raw else { return nil }
        let entries = LinkText.split(raw, UInt8(ascii: ",")).map { LinkText.trim($0) }.filter { !$0.isEmpty }
        return entries.isEmpty ? nil : entries
    }

    /**
     * The Host a link's transport sends (WebSocket, HTTPUpgrade, XHTTP) or its
     * gRPC authority: the first name of a comma list, or nil.
     *
     * v2rayN and v2rayNG use it as the TLS server name when a link has no `sni`,
     * and the subscriptions written for them rely on that: a CDN server given by
     * IP with only `host=` set got no usable name and answered 421 Misdirected
     * Request.
     */
    static func transportHostParam(_ params: [String: String]) -> String? {
        let raw: String?
        switch params["type"] {
        case "ws", "httpupgrade", "xhttp", "splithttp":
            raw = params["host"]
        case "grpc":
            raw = params["authority"]
        default:
            raw = nil
        }
        guard let text = raw else { return nil }
        return firstName(text)
    }

    /// The first non-empty entry of a comma list.
    static func firstName(_ text: String) -> String? {
        for part in LinkText.split(text, UInt8(ascii: ",")) {
            let trimmed = LinkText.trim(part)
            if !trimmed.isEmpty { return trimmed }
        }
        return nil
    }

    /// A literal IPv4 or IPv6 address, which is never sent as a TLS server name (RFC 6066).
    static func isIpLiteralHost(_ name: String) -> Bool {
        if name.isEmpty { return false }
        let allDigitsOrDots = name.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || $0 == 46 }
        return allDigitsOrDots || name.utf8.contains(58)
    }

    /**
     * `pcs=` / `pinnedPeerCertSha256=` / `pinSHA256=` as lower-case hex SHA-256
     * fingerprints. Hex may carry colons; a 32-byte base64 value is accepted too.
     * Nil when absent or nothing in it is a fingerprint.
     */
    static func parsePinnedCerts(_ params: [String: String]) -> [String]? {
        guard let raw = params["pcs"] ?? params["pinnedPeerCertSha256"] ?? params["pinSHA256"] ?? params["pinsha256"] else {
            return nil
        }
        var pins: [String] = []
        let separators: Set<UInt8> = [UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: " ")]
        for item in LinkText.split(raw, anyOf: separators) {
            let text = LinkText.trim(item)
            let hex = text.replacingOccurrences(of: ":", with: "").lowercased()
            let isHex = hex.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
            if hex.utf8.count == 64 && isHex {
                pins.append(hex)
            } else if !text.isEmpty {
                let standard = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                if let bytes = LinkText.base64Decode(LinkText.padBase64(standard), urlSafe: false), bytes.count == 32 {
                    pins.append(LinkText.hex(bytes))
                }
            }
        }
        return pins.isEmpty ? nil : pins
    }

    /**
     * The ClientHello fragmentation a link asks for, in either spelling:
     * `fragment=`/`frg=` (`length,interval,packets[,maxSplit]`) or the FinalMask
     * document in `fm=`, which says the same per piece.
     */
    static func parseFragmentParams(_ params: [String: String]) -> FragmentSettings? {
        if let value = params["fragment"] ?? params["frg"], let parsed = FragmentSettings.fromShareLink(value) {
            return parsed
        }
        if let fm = params["fm"] {
            return FragmentSettings.fromFinalMask(fm)
        }
        return nil
    }

    /// The spellings of "yes" that share links use for boolean flags.
    static func isTruthy(_ raw: String?) -> Bool {
        guard let raw = raw else { return false }
        let lower = raw.lowercased()
        return raw == "1" || lower == "true" || lower == "yes"
    }

    /// `a=1&b=2`, keys and values percent-decoded; a bare flag (`?insecure`) reads as set.
    static func parseQueryParams(_ queryString: String?) -> [String: String] {
        guard let queryString = queryString else { return [:] }
        var params: [String: String] = [:]
        for param in LinkText.split(queryString, UInt8(ascii: "&")) {
            let bytes = Array(param.utf8)
            if let eq = bytes.firstIndex(of: UInt8(ascii: "=")) {
                let key = percentDecode(LinkText.string(bytes[..<eq]))
                let value = percentDecode(LinkText.string(bytes[(eq + 1)...]))
                params[key] = value
            } else if !bytes.isEmpty {
                params[percentDecode(param)] = "1"
            }
        }
        return params
    }

    /// `host:port` or `[v6]:port`; `defaultPort` when the authority carries none.
    static func parseHostPort(_ hostPort: String, defaultPort: UInt16? = nil) throws -> (host: String, port: UInt16) {
        let bytes = Array(hostPort.utf8)
        let host: String
        let portString: String
        if bytes.first == UInt8(ascii: "[") {
            guard let close = bytes.firstIndex(of: UInt8(ascii: "]")) else {
                throw MythaiaError.parse("Missing closing bracket for IPv6 address")
            }
            host = LinkText.string(bytes[1..<close])
            let after = bytes[(close + 1)...]
            if after.isEmpty {
                guard let port = defaultPort else { throw MythaiaError.parse("Missing port after IPv6 address") }
                return (host, port)
            }
            guard after.first == UInt8(ascii: ":") else {
                throw MythaiaError.parse("Missing port after IPv6 address")
            }
            portString = LinkText.string(after.dropFirst())
        } else {
            guard let colon = bytes.lastIndex(of: UInt8(ascii: ":")) else {
                guard let port = defaultPort else { throw MythaiaError.parse("Missing port in server address") }
                return (hostPort, port)
            }
            host = LinkText.string(bytes[..<colon])
            // An unbracketed IPv6 literal has colons of its own, so this
            // split would take all but the last group as the host and the
            // last as a port. RFC 3986 §3.2.2 requires the brackets;
            // without them the address is not addressable and guessing at
            // it would connect somewhere else entirely.
            if host.utf8.contains(UInt8(ascii: ":")) {
                throw MythaiaError.parse("IPv6 address must be bracketed: \(hostPort)")
            }
            portString = LinkText.string(bytes[(colon + 1)...])
        }
        guard let port = UInt16(portString) else {
            throw MythaiaError.parse("Invalid port: \(portString)")
        }
        return (host, port)
    }

    /// The message a link error carries, without the error's own prefix.
    static func message(_ error: Error) -> String {
        if let mythaia = error as? MythaiaError {
            switch mythaia {
            case .parse(let why): return why
            case .invalidConfiguration(let why): return why
            case .protocolError(let why): return why
            default: return mythaia.errorDescription ?? "\(mythaia)"
            }
        }
        return error.localizedDescription
    }
}
