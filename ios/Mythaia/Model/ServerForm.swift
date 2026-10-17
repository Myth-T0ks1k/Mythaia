import Foundation
import MythaiaKit

/// The fields of the server editor and the server they make, as the
/// Android editor has them. Sub-configurations are built on what is stored,
/// so a setting the form does not show (ECH, early data, headers, XHTTP
/// padding) survives a save instead of being dropped.
struct ServerForm {
    /// Every protocol this build dials and the editor knows field by field.
    static let editableProtocols: [OutboundProtocol] = [
        .vless, .vmess, .trojan, .shadowsocks, .socks5,
        .hysteria2, .tuic, .anytls, .naiveHttp11, .naiveHttp2,
    ]

    static let shadowsocksMethods: [String] = [
        "none",
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ]

    static let vmessCiphers: [String] = ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]

    static let transports: [String] = ["tcp", "ws", "httpupgrade", "xhttp", "grpc"]

    var protocolKind: OutboundProtocol
    var name = ""
    var address = ""
    var port = ""
    var uuid = ""
    var encryption = "none"
    var flow = ""
    var security = "none"
    var transport = "tcp"
    /// Host and path of the WebSocket, HTTPUpgrade or XHTTP transport.
    var host = ""
    var path = "/"
    var xhttpMode: XHttpMode = .auto
    var grpcServiceName = ""
    var grpcAuthority = ""
    var grpcMultiMode = false
    var grpcUserAgent = ""
    var sni = ""
    var alpn = ""
    var allowInsecure = false
    var fingerprint: TlsFingerprint = .chrome133
    var minVersion: TlsVersion?
    var maxVersion: TlsVersion?
    var pins = ""
    var verifyName = ""
    var realitySni = ""
    var publicKey = ""
    var shortId = ""
    var mux = true
    var xudp = true
    var username = ""
    var password = ""
    var ssMethod = "aes-128-gcm"
    var vmessSecurity = "auto"
    var upMbps = ""
    var downMbps = ""
    var obfuscation = "none"
    var obfuscationPassword = ""

    /// A new server of `kind`.
    init(protocolKind kind: OutboundProtocol) {
        protocolKind = kind
        security = ServerForm.defaultSecurity(for: kind)
        uuid = UUID().uuidString.lowercased()
    }

    /// The fields of a stored server.
    init(_ c: ProxyConfiguration) {
        protocolKind = c.outboundProtocol
        name = c.name
        address = c.serverAddress
        port = String(c.serverPort)
        uuid = c.uuid.uuidString.lowercased()
        encryption = c.encryption.isEmpty ? "none" : c.encryption
        flow = c.flow ?? ""
        security = c.security
        transport = c.transport
        switch c.transport {
        case "ws":
            host = c.websocket?.host ?? ""
            path = c.websocket?.path ?? "/"
        case "httpupgrade":
            host = c.httpUpgrade?.host ?? ""
            path = c.httpUpgrade?.path ?? "/"
        case "xhttp":
            host = c.xhttp?.host ?? ""
            path = c.xhttp?.path ?? "/"
            xhttpMode = c.xhttp?.mode ?? .auto
        default:
            break
        }
        if let grpc = c.grpc {
            grpcServiceName = grpc.serviceName
            grpcAuthority = grpc.authority
            grpcMultiMode = grpc.multiMode
            grpcUserAgent = grpc.userAgent
        }
        // Trojan keeps its TLS apart; the shared fields read whichever is set.
        let tls = c.trojanTls ?? c.tls
        sni = tls?.serverName ?? ""
        alpn = tls?.alpn?.joined(separator: ",") ?? ""
        allowInsecure = tls?.allowInsecure ?? false
        fingerprint = c.reality?.fingerprint ?? tls?.fingerprint ?? .chrome133
        minVersion = tls?.minVersion
        maxVersion = tls?.maxVersion
        pins = tls?.pinnedCertSha256?.joined(separator: ", ") ?? ""
        verifyName = tls?.verifyName ?? ""
        if let reality = c.reality {
            realitySni = reality.serverName
            publicKey = KeyText.base64UrlEncode(reality.publicKey)
            shortId = KeyText.hex(reality.shortId)
        }
        mux = c.muxEnabled
        xudp = c.xudpEnabled
        switch c.outboundProtocol {
        case .naiveHttp11, .naiveHttp2:
            username = c.naiveUsername ?? ""
            password = c.naivePassword ?? ""
        case .socks5:
            username = c.socks5Username ?? ""
            password = c.socks5Password ?? ""
        case .shadowsocks:
            password = c.ssPassword ?? ""
            ssMethod = c.ssMethod ?? "aes-128-gcm"
        case .trojan:
            password = c.trojanPassword ?? ""
        default:
            password = c.password ?? ""
        }
        vmessSecurity = c.vmessSecurity ?? "auto"
        upMbps = c.hysteriaUpMbps.map { String($0) } ?? ""
        downMbps = c.hysteriaDownMbps.map { String($0) } ?? ""
        obfuscation = c.obfuscation ?? "none"
        obfuscationPassword = c.obfuscationPassword ?? ""
    }

    static func defaultSecurity(for kind: OutboundProtocol) -> String {
        switch kind {
        case .trojan, .hysteria2, .tuic, .anytls, .nowhere:
            return "tls"
        case .vless:
            // A new VLESS server is far more often REALITY or TLS than bare.
            return "reality"
        default:
            return "none"
        }
    }

    // MARK: What the protocol needs

    var isFullEditor: Bool { ServerForm.editableProtocols.contains(protocolKind) }
    var isVless: Bool { protocolKind == .vless }
    var isVmess: Bool { protocolKind == .vmess }
    var isTrojan: Bool { protocolKind == .trojan }
    var isShadowsocks: Bool { protocolKind == .shadowsocks }
    var isSocks: Bool { protocolKind == .socks5 }
    var isHysteria: Bool { protocolKind == .hysteria2 }
    var isTuic: Bool { protocolKind == .tuic }
    var isAnyTls: Bool { protocolKind == .anytls }
    var isNaive: Bool { protocolKind.isNaive }

    /// Protocols where TLS is the protocol itself, not an option.
    var tlsMandatory: Bool { isTrojan || isHysteria || isTuic || isAnyTls }
    /// Protocols that pick TLS on or off.
    var tlsOptional: Bool { isVless || isVmess }
    /// Whether the TLS section is shown at all.
    var showsTls: Bool { tlsMandatory || tlsOptional || isNaive }
    /// The TLS fields apply: TLS chosen, or TLS built in.
    var usesTlsFields: Bool { tlsMandatory || isNaive || (tlsOptional && security == "tls") }
    var usesReality: Bool { isVless && security == "reality" }
    /// VLESS, VMess and Trojan share the stream transports.
    var usesStreamTransport: Bool { isVless || isVmess || isTrojan }
    var usesUuid: Bool { isVless || isVmess || isTuic }
    var usesUsername: Bool { isNaive || isSocks }
    /// Vision rides on TLS or REALITY over plain TCP.
    var showsFlow: Bool { isVless && transport == "tcp" && (security == "tls" || security == "reality") }

    /// Switches the protocol, resetting what the new one cannot use.
    mutating func changeProtocol(to next: OutboundProtocol) {
        protocolKind = next
        if next != .vless {
            flow = ""
            if next != .vmess && next != .trojan { transport = "tcp" }
            switch next {
            case .trojan, .hysteria2, .tuic, .anytls:
                security = "tls"
            case .vmess:
                if security == "reality" { security = "none" }
            default:
                security = "none"
            }
        }
    }

    // MARK: Validation

    var trimmedAddress: String {
        let typed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if typed.hasPrefix("[") && typed.hasSuffix("]") && typed.count > 2 {
            return String(typed.dropFirst().dropLast())
        }
        return typed
    }

    var portValue: UInt16? {
        guard let value = Int(port.trimmingCharacters(in: .whitespaces)), value >= 1, value <= 65535 else { return nil }
        return UInt16(value)
    }

    var uuidValue: UUID? {
        UUID(uuidString: uuid.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    var publicKeyData: Data? {
        guard let data = KeyText.base64UrlDecode(publicKey), data.count == 32 else { return nil }
        return data
    }

    var shortIdData: Data? {
        guard let data = KeyText.hexDecode(shortId), data.count <= 8 else { return nil }
        return data
    }

    var pinList: [String] {
        pins.components(separatedBy: CharacterSet(charactersIn: ", ;\n"))
            .map { $0.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: ":", with: "").lowercased() }
            .filter { !$0.isEmpty }
    }

    var pinsValid: Bool {
        let digits = Set("0123456789abcdef")
        return pinList.allSatisfy { $0.count == 64 && $0.allSatisfy { digits.contains($0) } }
    }

    /// Brutal needs both directions; BBR neither.
    var bandwidthValid: Bool {
        let up = upMbps.trimmingCharacters(in: .whitespaces)
        let down = downMbps.trimmingCharacters(in: .whitespaces)
        let upOk = up.isEmpty || (Int(up) ?? 0) > 0
        let downOk = down.isEmpty || (Int(down) ?? 0) > 0
        return upOk && downOk && (up.isEmpty == down.isEmpty)
    }

    var isValid: Bool {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty,
              !trimmedAddress.isEmpty,
              portValue != nil else { return false }
        guard isFullEditor else { return true }
        if showsTls && usesTlsFields && !pinsValid { return false }
        if isNaive { return !username.isEmpty && !password.isEmpty }
        if isShadowsocks { return !password.isEmpty }
        if isSocks { return true }
        if isTrojan { return !password.isEmpty }
        if isHysteria { return !password.isEmpty && bandwidthValid && (obfuscation == "none" || !obfuscationPassword.isEmpty) }
        if isAnyTls { return !password.isEmpty }
        if isTuic { return uuidValue != nil && !password.isEmpty }
        if isVmess { return uuidValue != nil }
        // VLESS
        guard uuidValue != nil else { return false }
        if usesReality {
            return !realitySni.trimmingCharacters(in: .whitespaces).isEmpty && publicKeyData != nil && shortIdData != nil
        }
        return true
    }

    // MARK: Building

    /// The server the fields describe, built on `base` (the stored server
    /// when editing); nil while a field is not valid.
    func build(base: ProxyConfiguration?) -> ProxyConfiguration? {
        guard isValid, let port = portValue else { return nil }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let bareAddress = trimmedAddress

        guard isFullEditor else {
            guard var limited = base else { return nil }
            limited.name = trimmedName
            limited.serverAddress = bareAddress
            limited.serverPort = port
            limited.resolvedIP = nil
            return limited
        }

        let parsedUuid: UUID
        if usesUuid {
            guard let value = uuidValue else { return nil }
            parsedUuid = value
        } else {
            parsedUuid = base?.uuid ?? UUID()
        }

        let alpnList = alpn.components(separatedBy: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let sniOrAddress = sni.trimmingCharacters(in: .whitespaces).isEmpty
            ? bareAddress : sni.trimmingCharacters(in: .whitespaces)
        let pinsOrNil: [String]? = pinList.isEmpty ? nil : pinList
        let verify = verifyName.trimmingCharacters(in: .whitespaces)

        // The TLS layer, for every protocol that has one.
        var tls: TlsConfiguration?
        if (tlsOptional && security == "tls") || isHysteria || isTuic || isAnyTls {
            var value = base?.tls ?? TlsConfiguration(serverName: bareAddress)
            value.serverName = sniOrAddress
            value.alpn = alpnList.isEmpty ? nil : alpnList
            value.allowInsecure = allowInsecure
            value.fingerprint = fingerprint
            if isVless {
                value.minVersion = minVersion
                value.maxVersion = maxVersion
            }
            value.pinnedCertSha256 = pinsOrNil
            value.verifyName = verify.isEmpty ? nil : verify
            tls = value
        }
        if isNaive {
            // The ALPN follows the scheme (h2 or http/1.1), so none is kept.
            var value = base?.tls ?? TlsConfiguration(serverName: bareAddress)
            value.serverName = sniOrAddress
            value.allowInsecure = allowInsecure
            value.pinnedCertSha256 = pinsOrNil
            value.verifyName = verify.isEmpty ? nil : verify
            tls = value
        }
        var trojanTls: TlsConfiguration?
        if isTrojan {
            var value = base?.trojanTls ?? base?.tls ?? TlsConfiguration(serverName: bareAddress)
            value.serverName = sniOrAddress
            value.alpn = alpnList.isEmpty ? nil : alpnList
            value.allowInsecure = allowInsecure
            value.fingerprint = fingerprint
            value.pinnedCertSha256 = pinsOrNil
            value.verifyName = verify.isEmpty ? nil : verify
            trojanTls = value
            tls = value
        }

        var reality: RealityConfiguration?
        if usesReality {
            guard let key = publicKeyData, let sid = shortIdData else { return nil }
            reality = RealityConfiguration(
                serverName: realitySni.trimmingCharacters(in: .whitespaces),
                publicKey: key,
                shortId: sid,
                fingerprint: fingerprint
            )
        }

        let effectiveTransport: String
        if usesStreamTransport {
            effectiveTransport = transport
        } else if isTuic {
            effectiveTransport = "quic"
        } else {
            effectiveTransport = "tcp"
        }
        let transportHost = host.trimmingCharacters(in: .whitespaces).isEmpty
            ? bareAddress : host.trimmingCharacters(in: .whitespaces)
        let transportPath = path.trimmingCharacters(in: .whitespaces).isEmpty
            ? "/" : path.trimmingCharacters(in: .whitespaces)

        var websocket: WebSocketConfiguration?
        if usesStreamTransport && transport == "ws" {
            var value = base?.websocket ?? WebSocketConfiguration(host: transportHost)
            value.host = transportHost
            value.path = transportPath
            websocket = value
        }
        var httpUpgrade: HttpUpgradeConfiguration?
        if usesStreamTransport && transport == "httpupgrade" {
            var value = base?.httpUpgrade ?? HttpUpgradeConfiguration(host: transportHost)
            value.host = transportHost
            value.path = transportPath.hasPrefix("/") ? transportPath : "/" + transportPath
            httpUpgrade = value
        }
        var xhttp: XHttpConfiguration?
        if usesStreamTransport && transport == "xhttp" {
            var value = base?.xhttp ?? XHttpConfiguration(host: transportHost)
            value.host = transportHost
            value.path = transportPath
            value.mode = xhttpMode
            xhttp = value
        }
        var grpc: GrpcConfiguration?
        if usesStreamTransport && transport == "grpc" {
            var value = base?.grpc ?? GrpcConfiguration()
            value.serviceName = grpcServiceName.trimmingCharacters(in: .whitespaces)
            value.authority = grpcAuthority.trimmingCharacters(in: .whitespaces)
            value.multiMode = grpcMultiMode
            value.userAgent = grpcUserAgent.trimmingCharacters(in: .whitespaces)
            grpc = value
        }

        let effectiveSecurity: String
        if tlsMandatory {
            effectiveSecurity = "tls"
        } else if tlsOptional {
            effectiveSecurity = security
        } else {
            effectiveSecurity = "none"
        }
        let usesPassword = isHysteria || isTuic || isAnyTls
        let trimmedUser = username.trimmingCharacters(in: .whitespaces)

        var c = base ?? ProxyConfiguration(
            name: trimmedName,
            serverAddress: bareAddress,
            serverPort: port,
            uuid: parsedUuid,
            encryption: "none"
        )
        c.name = trimmedName
        c.serverAddress = bareAddress
        c.serverPort = port
        c.resolvedIP = nil
        c.uuid = parsedUuid
        let typedEncryption = encryption.trimmingCharacters(in: .whitespaces)
        c.encryption = isVless ? (typedEncryption.isEmpty ? "none" : typedEncryption) : "none"
        c.transport = effectiveTransport
        c.flow = (isVless && effectiveSecurity != "none" && transport == "tcp" && !flow.isEmpty) ? flow : nil
        c.security = effectiveSecurity
        c.tls = tls
        c.reality = isVless ? reality : nil
        c.websocket = websocket
        c.httpUpgrade = httpUpgrade
        c.xhttp = xhttp
        c.grpc = grpc
        c.muxEnabled = isVless ? mux : false
        c.xudpEnabled = isVless ? xudp : false
        c.outboundProtocol = protocolKind
        c.ssPassword = isShadowsocks ? password : nil
        c.ssMethod = isShadowsocks ? ssMethod : nil
        c.socks5Username = isSocks && !trimmedUser.isEmpty ? trimmedUser : nil
        c.socks5Password = isSocks && !password.isEmpty ? password : nil
        c.naiveUsername = isNaive ? trimmedUser : nil
        c.naivePassword = isNaive ? password : nil
        if protocolKind == .naiveHttp11 {
            c.naiveProtocol = .http11
        } else if protocolKind == .naiveHttp2 {
            c.naiveProtocol = .http2
        } else {
            c.naiveProtocol = nil
        }
        c.trojanPassword = isTrojan ? password : nil
        c.trojanTls = isTrojan ? trojanTls : nil
        c.password = usesPassword ? password : nil
        c.vmessSecurity = (isVmess && vmessSecurity != "auto") ? vmessSecurity : nil
        c.hysteriaUpMbps = isHysteria ? Int(upMbps.trimmingCharacters(in: .whitespaces)) : nil
        c.hysteriaDownMbps = isHysteria ? Int(downMbps.trimmingCharacters(in: .whitespaces)) : nil
        c.obfuscation = (isHysteria && obfuscation != "none") ? obfuscation : nil
        c.obfuscationPassword = (isHysteria && obfuscation != "none") ? obfuscationPassword : nil
        return c
    }
}

/// Key text as share links write it: URL-safe base64 for REALITY public
/// keys, hex for short ids.
enum KeyText {
    static func base64UrlDecode(_ text: String) -> Data? {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "=", with: "")
        guard !s.isEmpty else { return nil }
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func hexDecode(_ text: String) -> Data? {
        let s = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard s.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(s.count / 2)
        var index = s.startIndex
        while index < s.endIndex {
            let next = s.index(index, offsetBy: 2)
            guard let byte = UInt8(s[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        return Data(bytes)
    }

    static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
