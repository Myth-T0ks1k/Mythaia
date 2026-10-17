import Foundation

/**
 * Imports sing-box JSON: a whole config (`{"outbounds": [...], "endpoints":
 * [...]}`, what Hiddify, NekoBox and sing-box subscriptions hand out), one
 * outbound object, or an array of outbounds.
 *
 * sing-box names an outbound's kind in `type` where Xray says `protocol`,
 * which is how the two are told apart (`isSingBox`). As with
 * `XrayJsonImporter`, each outbound becomes the share link it is equivalent
 * to and goes through the same link parser as a pasted one; WireGuard, which
 * has no link worth the name, becomes the INI it is stored as. The routing
 * outbounds (`selector`, `urltest`, `direct`, `block`, `dns`) are skipped,
 * and a `detour` to another proxy becomes the entry hop of a chain.
 */
public enum SingBoxJsonImporter {

    private static let proxyTypes: Set<String> = [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http",
        "hysteria2", "tuic", "anytls", "naive", "wireguard",
    ]

    /// Outbounds that route or terminate rather than reach a server.
    private static let routingTypes: Set<String> = ["selector", "urltest", "direct", "block", "dns"]

    /// Whether `text` is sing-box JSON rather than Xray's.
    public static func looksLikeSingBox(_ text: String) -> Bool {
        looksLikeSingBox(text) { try? XrayJsonImporter.parseJson(text) }
    }

    /**
     * `looksLikeSingBox` with the parsing left to `tree`, so a caller that
     * goes on to import the JSON builds the tree once rather than again for
     * each step: for a body of thousands of outbounds that was three parses.
     */
    static func looksLikeSingBox(_ text: String, tree: () -> ImportJSON?) -> Bool {
        if !XrayJsonImporter.startsLikeJson(text) { return false }
        if !LinkText.contains(text, "\"type\"") { return false }
        guard let root = tree() else { return false }
        return isSingBox(root)
    }

    /**
     * Whether parsed JSON is sing-box's: its outbounds (or endpoints) say
     * `type` and none of them says `protocol`. Route rules may well mention
     * `"protocol"`, which is why the text alone cannot decide this.
     */
    static func isSingBox(_ root: ImportJSON) -> Bool {
        let all = items(root)
        let anyTyped = all.contains { $0.has("type") && !$0.has("protocol") }
        let anyXray = all.contains { $0.has("protocol") }
        return anyTyped && !anyXray
    }

    /// One config per usable outbound. Throws `MythaiaError.parse` when nothing usable is there.
    public static func parse(_ text: String) throws -> [ProxyConfiguration] {
        try parse(root: XrayJsonImporter.parseJson(text))
    }

    static func parse(root: ImportJSON) throws -> [ProxyConfiguration] {
        let all = items(root)
        if all.isEmpty { throw MythaiaError.parse("No outbounds found in the JSON") }

        var byTag: [String: ImportJSONObject] = [:]
        for item in all {
            let tag = item.optString("tag")
            if !tag.isEmpty { byTag[tag] = item }
        }
        // An outbound only there to carry another is imported as that one's
        // chain, not listed as a server of its own.
        var detourTargets = Set<String>()
        for item in all {
            let detour = item.optString("detour")
            if !detour.isEmpty { detourTargets.insert(detour) }
        }

        var errors: [String] = []
        var configurations: [ProxyConfiguration] = []
        for item in all {
            let type = item.optString("type").lowercased()
            if routingTypes.contains(type) { continue }
            let tag = item.optString("tag")
            if !tag.isEmpty && detourTargets.contains(tag) { continue }
            do {
                if !proxyTypes.contains(type) { throw MythaiaError.parse("\(type) outbounds are not supported") }
                configurations.append(try convert(item, byTag: byTag, depth: 0))
            } catch {
                errors.append("\(tag.isEmpty ? type : tag): \(ShareLinkParams.message(error))")
            }
        }
        if configurations.isEmpty {
            throw MythaiaError.parse(
                errors.isEmpty ? "No proxy outbound in the JSON (only selector/urltest/direct/block/dns)" : errors.joined(separator: "; ")
            )
        }
        return configurations
    }

    /// The outbound-shaped objects in a config, a bare array, or one outbound.
    private static func items(_ root: ImportJSON) -> [ImportJSONObject] {
        switch root {
        case .object(let object):
            if object.has("outbounds") || object.has("endpoints") {
                let outbounds = object.optArray("outbounds")?.objectElements ?? []
                let endpoints = object.optArray("endpoints")?.objectElements ?? []
                return outbounds + endpoints
            }
            return [object]
        case .array(let elements):
            return elements.objectElements
        default:
            return []
        }
    }

    // MARK: - Conversion

    private static func convert(_ item: ImportJSONObject, byTag: [String: ImportJSONObject], depth: Int) throws -> ProxyConfiguration {
        if depth > 8 { throw MythaiaError.parse("detour chain is too deep or circular") }
        let type = item.optString("type").lowercased()
        let name = item.optString("tag")

        var chain: [ProxyConfiguration]? = nil
        if let tag = ShareLinkParams.nonEmpty(item.optString("detour")) {
            guard let hop = byTag[tag] else { throw MythaiaError.parse("detour '\(tag)' is not defined") }
            // A detour to `direct` (or a selector, which cannot be resolved
            // here) dials the server directly, which is what it would do anyway.
            if proxyTypes.contains(hop.optString("type").lowercased()) {
                let entry = try convert(hop, byTag: byTag, depth: depth + 1)
                if entry.outboundProtocol.isLayer3 {
                    throw MythaiaError.parse("detour '\(tag)' is WireGuard, which cannot carry another proxy")
                }
                chain = (entry.chain ?? []) + [entry.withChain(nil)]
            }
        }

        let config: ProxyConfiguration
        switch type {
        case "wireguard":
            config = try wireGuardConfig(item, name: name)
        case "http":
            config = try ProxyConfiguration.fromUrl(try httpLink(item, name: name, type: "http"), naiveProtocol: .naiveHttp11)
        case "naive":
            config = try ProxyConfiguration.fromUrl(try httpLink(item, name: name, type: "naive"), naiveProtocol: .naiveHttp2)
        default:
            let link: String
            switch type {
            case "vless": link = try vlessLink(item, name: name)
            case "vmess": link = try vmessLink(item, name: name)
            case "trojan": link = try trojanLink(item, name: name)
            case "shadowsocks": link = try shadowsocksLink(item, name: name)
            case "socks": link = try socksLink(item, name: name)
            case "hysteria2": link = try hysteria2Link(item, name: name)
            case "tuic": link = try tuicLink(item, name: name)
            case "anytls": link = try anyTlsLink(item, name: name)
            default: throw MythaiaError.parse("\(type) outbounds are not supported")
            }
            config = try ProxyConfiguration.fromUrl(link)
        }
        guard let hops = chain, !hops.isEmpty else { return config }
        if config.outboundProtocol.isLayer3 {
            throw MythaiaError.parse("WireGuard is a whole interface and cannot be dialled through another proxy")
        }
        return config.withChain(hops)
    }

    // MARK: - Pieces

    /// The port of the first `server_ports` range: `"20000:30000"` or `"20000-30000"`.
    private static func firstRangePort(_ item: ImportJSONObject) -> Int? {
        guard let first = XrayJsonImporter.stringList(item.opt("server_ports")).first else { return nil }
        var bytes = Array(first.utf8)
        if let colon = bytes.firstIndex(of: UInt8(ascii: ":")) { bytes = Array(bytes[..<colon]) }
        if let dash = bytes.firstIndex(of: UInt8(ascii: "-")) { bytes = Array(bytes[..<dash]) }
        guard let port = Int(LinkText.trim(LinkText.string(bytes))), port >= 1 && port <= 65535 else { return nil }
        return port
    }

    /**
     * `server:server_port`, IPv6 bracketed. Hysteria2's port hopping
     * (`server_ports: ["20000:30000"]`) is not dialled as such; the first
     * port of the range is, which the server answers on like any other.
     */
    private static func hostPort(_ item: ImportJSONObject) throws -> String {
        let type = item.optString("type")
        let address = item.optString("server")
        if address.isEmpty { throw MythaiaError.parse("\(type): server is missing") }
        let declared = item.optInt("server_port", 0)
        let port: Int
        if declared >= 1 && declared <= 65535 {
            port = declared
        } else if let ranged = firstRangePort(item) {
            port = ranged
        } else {
            throw MythaiaError.parse("\(type): server_port is missing")
        }
        let host = (address.utf8.contains(UInt8(ascii: ":")) && !LinkText.hasPrefix(address, "[")) ? "[\(address)]" : address
        return "\(host):\(port)"
    }

    private static func label(_ item: ImportJSONObject, _ name: String) throws -> String {
        if name.isEmpty {
            let endpoint = try hostPort(item)
            return encode(endpoint)
        }
        return encode(name)
    }

    /// An ordered query, keys in the order first set.
    private struct Params {
        private(set) var keys: [String] = []
        private var values: [String: String] = [:]

        init() {}

        subscript(key: String) -> String? {
            get { values[key] }
            set {
                guard let value = newValue else { return }
                if values.updateValue(value, forKey: key) == nil { keys.append(key) }
            }
        }

        var isEmpty: Bool { keys.isEmpty }

        func query() -> String {
            keys.map { "\($0)=" + LinkText.urlEncode(values[$0] ?? "") }.joined(separator: "&")
        }
    }

    /**
     * The TLS block as link parameters, and the `security` it amounts to.
     *
     * sing-box only uses TLS when `enabled` is true; for the protocols that
     * cannot run without it (`mandatory`) the block is read either way, since
     * their links imply TLS regardless.
     */
    private static func tlsParams(_ item: ImportJSONObject, _ params: inout Params, insecureKey: String, mandatory: Bool = false) -> String {
        guard let tls = item.optObject("tls") else { return "none" }
        if !tls.optBoolean("enabled", false) && !mandatory { return "none" }
        if let v = ShareLinkParams.nonEmpty(tls.optString("server_name")) { params["sni"] = v }
        let alpn = XrayJsonImporter.stringList(tls.opt("alpn"))
        if !alpn.isEmpty { params["alpn"] = alpn.joined(separator: ",") }
        if tls.optBoolean("insecure", false) { params[insecureKey] = "1" }
        if let utls = tls.optObject("utls"), utls.optBoolean("enabled", false),
           let fp = ShareLinkParams.nonEmpty(utls.optString("fingerprint")) {
            params["fp"] = fp
        }
        if let ech = tls.optObject("ech"), ech.optBoolean("enabled", false), let config = echConfig(ech.opt("config")) {
            params["ech"] = config
        }
        if let reality = tls.optObject("reality"), reality.optBoolean("enabled", false) {
            if let v = ShareLinkParams.nonEmpty(reality.optString("public_key")) { params["pbk"] = v }
            if let v = ShareLinkParams.nonEmpty(reality.optString("short_id")) { params["sid"] = v }
            return "reality"
        }
        // Hiddify's sing-box carries ClientHello fragmentation on the
        // outbound; it is the same thing a link's `fragment=` asks for.
        if let f = item.optObject("tls_fragment"), f.optBoolean("enabled", false) {
            let size = f.opt("size").map { $0.text }.flatMap { ShareLinkParams.nonEmpty($0) } ?? "10-30"
            let sleep = f.opt("sleep").map { $0.text }.flatMap { ShareLinkParams.nonEmpty($0) } ?? "2-8"
            params["fragment"] = "\(size),\(sleep),tlshello"
        }
        return "tls"
    }

    /**
     * sing-box's `ech.config`: the PEM block `sing-box generate ech-keypair`
     * prints, as an array of its lines or one string. Its body is the base64
     * ECHConfigList a link's `ech=` carries.
     */
    private static func echConfig(_ value: ImportJSON?) -> String? {
        guard let value = value else { return nil }
        let lines: [String]
        switch value {
        case .array:
            lines = XrayJsonImporter.stringList(value)
        case .string(let text):
            lines = LinkText.lines(text)
        default:
            return nil
        }
        let body = lines.map { LinkText.trim($0) }
            .filter { !$0.isEmpty && !LinkText.hasPrefix($0, "-----") }
            .joined()
        return body.isEmpty ? nil : body
    }

    /// The V2Ray transport block as link parameters.
    private static func transportParams(_ item: ImportJSONObject, _ params: inout Params) throws {
        let transport = item.optObject("transport")
        let type = transport?.optString("type").lowercased() ?? ""
        switch type {
        case "", "tcp":
            params["type"] = "tcp"
        case "ws":
            params["type"] = "ws"
            let t = transport ?? ImportJSONObject()
            if let path = ShareLinkParams.nonEmpty(t.optString("path")) { params["path"] = path }
            if let host = headerValue(t.optObject("headers"), "Host") { params["host"] = host }
            // sing-box sends early data in the path unless a header is
            // named; only the header form is something this client
            // speaks, and leaving early data off is always accepted.
            let earlyData = t.optInt("max_early_data", 0)
            let header = t.optString("early_data_header_name")
            if earlyData > 0 && !header.isEmpty {
                params["ed"] = String(earlyData)
                params["eh"] = header
            }
        case "httpupgrade":
            params["type"] = "httpupgrade"
            let t = transport ?? ImportJSONObject()
            if let path = ShareLinkParams.nonEmpty(t.optString("path")) { params["path"] = path }
            if let host = ShareLinkParams.nonEmpty(t.optString("host")) ?? headerValue(t.optObject("headers"), "Host") {
                params["host"] = host
            }
        case "grpc":
            params["type"] = "grpc"
            let t = transport ?? ImportJSONObject()
            if let serviceName = ShareLinkParams.nonEmpty(t.optString("service_name")) { params["serviceName"] = serviceName }
        // HTTP/2 and QUIC carriers have no dialer here; importing them
        // as plain TCP would give a server that never connects.
        case "http":
            throw MythaiaError.parse("the http (HTTP/2) transport is not supported")
        default:
            throw MythaiaError.parse("the \(type) transport is not supported")
        }
    }

    /// A header from sing-box's map, whose values may be a string or a list of them.
    private static func headerValue(_ headers: ImportJSONObject?, _ name: String) -> String? {
        guard let headers = headers else { return nil }
        let lower = name.lowercased()
        guard let key = headers.keys.first(where: { $0.lowercased() == lower }) else { return nil }
        return XrayJsonImporter.stringList(headers.opt(key)).first
    }

    private static func encode(_ value: String) -> String {
        LinkText.urlEncode(value)
    }

    private static func required(_ item: ImportJSONObject, _ key: String) throws -> String {
        let value = item.optString(key)
        if value.isEmpty { throw MythaiaError.parse("\(item.optString("type")): \(key) is missing") }
        return value
    }

    // MARK: - Protocols

    private static func vlessLink(_ item: ImportJSONObject, name: String) throws -> String {
        let uuid = try required(item, "uuid")
        var params = Params()
        try transportParams(item, &params)
        params["security"] = tlsParams(item, &params, insecureKey: "allowInsecure")
        params["encryption"] = "none"
        if let flow = ShareLinkParams.nonEmpty(item.optString("flow")) { params["flow"] = flow }
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "vless://\(encode(uuid))@\(endpoint)?\(params.query())#\(fragment)"
    }

    private static func vmessLink(_ item: ImportJSONObject, name: String) throws -> String {
        var params = Params()
        try transportParams(item, &params)
        let security = tlsParams(item, &params, insecureKey: "allowInsecure")
        if security == "reality" { throw MythaiaError.parse("vmess: Reality is not supported") }
        let endpoint = try hostPort(item)
        let endpointBytes = Array(endpoint.utf8)
        var portText = endpoint
        if let colon = endpointBytes.lastIndex(of: UInt8(ascii: ":")) {
            portText = LinkText.string(endpointBytes[(colon + 1)...])
        }
        let id = try required(item, "uuid")
        var json = ImportJSONObject()
        json.put("v", "2")
        json.put("ps", name.isEmpty ? endpoint : name)
        json.put("add", item.optString("server"))
        json.put("port", portText)
        json.put("id", id)
        json.put("aid", item.optInt("alter_id", 0))
        json.put("scy", ShareLinkParams.nonEmpty(item.optString("security")) ?? "auto")
        json.put("net", params["type"] ?? "tcp")
        json.put("type", "none")
        json.put("host", params["host"] ?? "")
        json.put("path", params["path"] ?? params["serviceName"] ?? "")
        json.put("tls", security == "tls" ? "tls" : "")
        json.put("sni", params["sni"] ?? "")
        json.put("fp", params["fp"] ?? "")
        json.put("alpn", params["alpn"] ?? "")
        if params["allowInsecure"] == "1" { json.put("allowInsecure", "1") }
        return "vmess://" + LinkText.base64Encode(Array(json.serialized().utf8))
    }

    private static func trojanLink(_ item: ImportJSONObject, name: String) throws -> String {
        let password = try required(item, "password")
        var params = Params()
        try transportParams(item, &params)
        params["security"] = tlsParams(item, &params, insecureKey: "allowInsecure", mandatory: true)
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "trojan://\(encode(password))@\(endpoint)?\(params.query())#\(fragment)"
    }

    private static func shadowsocksLink(_ item: ImportJSONObject, name: String) throws -> String {
        if let plugin = ShareLinkParams.nonEmpty(item.optString("plugin")) {
            throw MythaiaError.parse("shadowsocks: plugins are not supported (\(plugin))")
        }
        let method = try required(item, "method")
        let password = item.optString("password")
        let userInfo = LinkText.base64UrlEncode(Array("\(method):\(password)".utf8))
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "ss://\(userInfo)@\(endpoint)#\(fragment)"
    }

    private static func socksLink(_ item: ImportJSONObject, name: String) throws -> String {
        let version = ShareLinkParams.nonEmpty(item.optString("version")) ?? "5"
        if version != "5" { throw MythaiaError.parse("socks: only SOCKS5 is supported, not \(version)") }
        let user = item.optString("username")
        let auth = user.isEmpty ? "" : encode(user) + ":" + encode(item.optString("password")) + "@"
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "socks5://\(auth)\(endpoint)#\(fragment)"
    }

    /**
     * An HTTPS proxy (`http` with TLS) or a NaïveProxy server (`naive`), both
     * as the `https://user:pass@host:port` link the naive parser reads.
     *
     * That link has nowhere to put a server name, so the name has to be the
     * host itself; one that differs is refused rather than silently dropped,
     * which would present the wrong name to the server.
     */
    private static func httpLink(_ item: ImportJSONObject, name: String, type: String) throws -> String {
        guard let tls = item.optObject("tls"), tls.optBoolean("enabled", false) else {
            throw MythaiaError.parse("\(type): only a proxy over TLS is supported")
        }
        if type == "naive" && item.optBoolean("quic", false) {
            throw MythaiaError.parse("naive: the QUIC variant is not supported")
        }
        let server = item.optString("server")
        if let serverName = ShareLinkParams.nonEmpty(tls.optString("server_name")),
           serverName.lowercased() != server.lowercased() {
            throw MythaiaError.parse("\(type): a server name (\(serverName)) different from the server address is not supported")
        }
        let user = item.optString("username")
        if user.isEmpty { throw MythaiaError.parse("\(type): a username and password are required") }
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "https://\(encode(user)):\(encode(item.optString("password")))@\(endpoint)#\(fragment)"
    }

    private static func hysteria2Link(_ item: ImportJSONObject, name: String) throws -> String {
        let password = item.optString("password")
        var params = Params()
        _ = tlsParams(item, &params, insecureKey: "insecure", mandatory: true)
        if let obfs = item.optObject("obfs") {
            let type = obfs.optString("type").lowercased()
            if !type.isEmpty && type != "salamander" {
                throw MythaiaError.parse("hysteria2: \(type) obfuscation is not supported")
            }
            if let obfsPassword = ShareLinkParams.nonEmpty(obfs.optString("password")) {
                params["obfs"] = "salamander"
                params["obfs-password"] = obfsPassword
            }
        }
        if let up = XrayJsonImporter.bandwidthMbps(item.opt("up_mbps")) ?? XrayJsonImporter.bandwidthMbps(item.opt("up")) {
            params["upmbps"] = String(up)
        }
        if let down = XrayJsonImporter.bandwidthMbps(item.opt("down_mbps")) ?? XrayJsonImporter.bandwidthMbps(item.opt("down")) {
            params["downmbps"] = String(down)
        }
        let q = params.isEmpty ? "" : "?" + params.query()
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "hysteria2://\(encode(password))@\(endpoint)\(q)#\(fragment)"
    }

    private static func tuicLink(_ item: ImportJSONObject, name: String) throws -> String {
        let uuid = try required(item, "uuid")
        var params = Params()
        _ = tlsParams(item, &params, insecureKey: "insecure", mandatory: true)
        // The usual TUIC link parameters; which of them a profile keeps is
        // the link parser's business, as it is for a pasted link.
        if let v = ShareLinkParams.nonEmpty(item.optString("congestion_control")) { params["congestion_control"] = v }
        if let v = ShareLinkParams.nonEmpty(item.optString("udp_relay_mode")) { params["udp_relay_mode"] = v }
        let q = params.isEmpty ? "" : "?" + params.query()
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "tuic://\(encode(uuid)):\(encode(item.optString("password")))@\(endpoint)\(q)#\(fragment)"
    }

    private static func anyTlsLink(_ item: ImportJSONObject, name: String) throws -> String {
        let password = try required(item, "password")
        var params = Params()
        _ = tlsParams(item, &params, insecureKey: "insecure", mandatory: true)
        let q = params.isEmpty ? "" : "?" + params.query()
        let endpoint = try hostPort(item)
        let fragment = try label(item, name)
        return "anytls://\(encode(password))@\(endpoint)\(q)#\(fragment)"
    }

    /**
     * WireGuard in either of sing-box's shapes: the legacy `wireguard`
     * outbound (`server`, `local_address`, `peer_public_key`, or a `peers`
     * list) and the 1.11+ endpoint (`address`, `peers[{address, port, ...}]`).
     * The first peer is used, as the INI parser does with several.
     */
    private static func wireGuardConfig(_ item: ImportJSONObject, name: String) throws -> ProxyConfiguration {
        let peer = item.optArray("peers")?.optObject(0)
        let hostCandidate = ShareLinkParams.nonEmpty(peer?.optString("address"))
            ?? ShareLinkParams.nonEmpty(peer?.optString("server"))
            ?? item.optString("server")
        if hostCandidate.isEmpty { throw MythaiaError.parse("wireguard: no server address") }
        let host = hostCandidate

        var port = 0
        if let p = peer?.optInt("port", 0), p > 0 {
            port = p
        } else if let p = peer?.optInt("server_port", 0), p > 0 {
            port = p
        } else {
            port = item.optInt("server_port", 0)
        }
        if port < 1 || port > 65535 { throw MythaiaError.parse("wireguard: no server port") }

        let publicKey: String
        if let key = ShareLinkParams.nonEmpty(peer?.optString("public_key")) {
            publicKey = key
        } else {
            publicKey = item.optString("peer_public_key")
            if publicKey.isEmpty { throw MythaiaError.parse("wireguard: peer public key is missing") }
        }

        let preshared = ShareLinkParams.nonEmpty(peer?.optString("pre_shared_key"))
            ?? ShareLinkParams.nonEmpty(item.optString("pre_shared_key"))
        let mtu = item.optInt("mtu", 0)
        let ini = WireGuardIni.build(
            privateKey: item.optString("private_key"),
            addresses: XrayJsonImporter.stringList(item.opt("address") ?? item.opt("local_address")),
            peer: WireGuardIni.Peer(
                publicKey: publicKey,
                endpointHost: host,
                endpointPort: port,
                presharedKey: preshared,
                allowedIps: XrayJsonImporter.stringList(peer?.opt("allowed_ips")),
                keepalive: peer?.optInt("persistent_keepalive_interval", 0) ?? 0
            ),
            mtu: mtu > 0 ? mtu : nil,
            reserved: WireGuardIni.reservedFromJson(peer?.opt("reserved") ?? item.opt("reserved"))
        )
        let label = name.isEmpty ? WireGuardIni.endpoint(host, port) : name
        return try ProxyConfiguration.fromWireGuardConfig(ini, name: label)
    }
}
