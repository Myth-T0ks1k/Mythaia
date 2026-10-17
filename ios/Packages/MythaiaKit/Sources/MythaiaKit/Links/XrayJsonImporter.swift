import Foundation

/**
 * Imports Xray / v2ray JSON: a whole config (`{"outbounds": [...]}`, the
 * shape v2rayNG's "custom config" and every panel export use), an array of
 * whole configs (a JSON subscription: one config per server, each named by
 * its `remarks`), one outbound object, or an array of outbounds.
 *
 * Each outbound becomes the share link it is equivalent to and goes through
 * the same link parser as a pasted `vless://`, so the two paths cannot
 * disagree about what a field means. `sockopt.dialerProxy` is honoured: a
 * `freedom` outbound with `fragment` settings becomes the server's
 * ClientHello fragmentation, and another proxy outbound becomes the entry
 * hop of a chain. A sing-box config handed in here is passed on to
 * `SingBoxJsonImporter`, so a caller that only knows this importer (the
 * paste box) reads both.
 */
public enum XrayJsonImporter {

    private static let proxyProtocols: Set<String> = [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "hysteria2", "wireguard",
    ]

    /**
     * Whether `text` is worth handing to `parse`: a JSON object or array of
     * Xray or sing-box outbounds. A lone sing-box outbound has neither
     * `protocol` nor `outbounds`, only `type` and `server`.
     */
    public static func looksLikeJson(_ text: String) -> Bool {
        if !startsLikeJson(text) { return false }
        let bytes = Array(text.utf8)
        if LinkText.containsAny(bytes, ["\"protocol\"", "\"outbounds\"", "\"endpoints\""]) { return true }
        return LinkText.containsAny(bytes, ["\"type\""]) && LinkText.containsAny(bytes, ["\"server\""])
    }

    /// Whether the first thing past any white space opens an object or array.
    static func startsLikeJson(_ text: String) -> Bool {
        for b in text.utf8 {
            if LinkText.isWhitespaceByte(b) { continue }
            return b == UInt8(ascii: "{") || b == UInt8(ascii: "[")
        }
        return false
    }

    /// One config per usable outbound. Throws `MythaiaError.parse` when nothing usable is there.
    public static func parse(_ text: String) throws -> [ProxyConfiguration] {
        try parse(root: parseJson(text))
    }

    /// `parse` of a tree `parseJson` already built, for a caller that looked into it first.
    static func parse(root: ImportJSON) throws -> [ProxyConfiguration] {
        if SingBoxJsonImporter.isSingBox(root) { return try SingBoxJsonImporter.parse(root: root) }

        let documents = collectDocuments(root)
        if documents.allSatisfy({ $0.outbounds.isEmpty }) {
            throw MythaiaError.parse("No outbounds found in the JSON")
        }

        var errors: [String] = []
        var configurations: [ProxyConfiguration] = []
        for document in documents {
            let outbounds = document.outbounds
            // Tags are only unique within one config: every entry of a JSON
            // subscription calls its server "proxy".
            var byTag: [String: ImportJSONObject] = [:]
            for outbound in outbounds {
                let tag = outbound.optString("tag")
                if !tag.isEmpty { byTag[tag] = outbound }
            }
            // How many outbounds dial through each tag, counted once. Asking
            // every outbound about every other was quadratic, and a config of
            // thousands of servers froze the import.
            var dialers: [String: Int] = [:]
            for outbound in outbounds {
                if let tag = dialerProxyOf(outbound) { dialers[tag, default: 0] += 1 }
            }
            var servers: [ImportJSONObject] = []
            for outbound in outbounds {
                let tag = outbound.optString("tag")
                // One that names itself is not carrying another, and is left
                // for convert() to refuse as circular.
                let selfDial = dialerProxyOf(outbound) == tag ? 1 : 0
                let others = (dialers[tag] ?? 0) - selfDial
                // A hop that only exists to carry another outbound is imported
                // as part of that outbound's chain, not as a server of its own.
                if proxyProtocols.contains(outbound.optString("protocol").lowercased()) && others == 0 {
                    servers.append(outbound)
                }
            }
            for (index, outbound) in servers.enumerated() {
                let name = nameOf(outbound, remarks: document.remarks, index: index, count: servers.count)
                do {
                    configurations.append(try convert(outbound, byTag: byTag, name: name, depth: 0))
                } catch {
                    let label = name.isEmpty ? outbound.optString("protocol") : name
                    errors.append("\(label): \(ShareLinkParams.message(error))")
                }
            }
        }
        if configurations.isEmpty {
            throw MythaiaError.parse(
                errors.isEmpty ? "No proxy outbound in the JSON (only freedom/blackhole/dns)" : errors.joined(separator: "; ")
            )
        }
        return configurations
    }

    /**
     * What to call a server.
     *
     * A config's `remarks` is the name the panel gave it, and every outbound
     * in it is tagged something generic (`proxy`, `proxy-3`) for routing
     * rules, so the remarks win. A balancer config holds several servers
     * under one remarks; they are told apart by their place in it, which is
     * stable across refreshes where the tags are not meant to be read.
     * Without remarks the tag is used, and without a tag the link builder
     * falls back to `host:port`.
     */
    private static func nameOf(_ outbound: ImportJSONObject, remarks: String?, index: Int, count: Int) -> String {
        guard let remarks = remarks, !remarks.isEmpty else {
            let tag = outbound.optString("tag")
            return tag.isEmpty ? LinkText.trim(outbound.optString("remarks")) : tag
        }
        if count == 1 { return remarks }
        return "\(remarks) · \(index + 1)"
    }

    // MARK: - Parsing

    /// JSON as Xray reads it: comments and trailing commas allowed.
    static func parseJson(_ text: String) throws -> ImportJSON {
        let trimmed = LinkText.trim(text)
        let firstError: Error
        do {
            return try ImportJSON.parse(trimmed)
        } catch {
            firstError = error
        }
        // Xray accepts comments and trailing commas; a strict reader does not.
        let cleaned = stripComments(trimmed)
        // With nothing stripped a second parse could only fail the same way,
        // after another pass over a body that can run to megabytes.
        if cleaned == trimmed {
            throw MythaiaError.parse("Not valid JSON: \(ShareLinkParams.message(firstError))")
        }
        do {
            return try ImportJSON.parse(cleaned)
        } catch {
            throw MythaiaError.parse("Not valid JSON: \(ShareLinkParams.message(error))")
        }
    }

    /// Removes `//` and `/* */` comments outside strings and trailing commas.
    static func stripComments(_ text: String) -> String {
        let src = Array(text.utf8)
        var out: [UInt8] = []
        out.reserveCapacity(src.count)
        var i = 0
        var inString = false
        // Where the last comma outside a string landed in `out`, while only
        // white space (or comments, which are not copied) has followed it. A
        // closing bracket arriving then makes it a trailing comma. Done in
        // the walk rather than with a pattern afterwards so a `,}` inside a
        // password is left alone.
        var pendingComma = -1
        let quote = UInt8(ascii: "\"")
        let slash = UInt8(ascii: "/")
        let star = UInt8(ascii: "*")
        while i < src.count {
            let c = src[i]
            if inString {
                out.append(c)
                if c == UInt8(ascii: "\\") && i + 1 < src.count {
                    out.append(src[i + 1])
                    i += 1
                } else if c == quote {
                    inString = false
                }
            } else if c == quote {
                inString = true
                pendingComma = -1
                out.append(c)
            } else if c == slash && i + 1 < src.count && src[i + 1] == slash {
                while i < src.count && src[i] != 10 { i += 1 }
                continue
            } else if c == slash && i + 1 < src.count && src[i + 1] == star {
                if let end = LinkText.indexOf(src, [star, slash], from: i + 2) {
                    i = end + 2
                } else {
                    i = src.count
                }
                continue
            } else if c == UInt8(ascii: ",") {
                pendingComma = out.count
                out.append(c)
            } else if (c == UInt8(ascii: "}") || c == UInt8(ascii: "]")) && pendingComma >= 0 {
                out.remove(at: pendingComma)
                pendingComma = -1
                out.append(c)
            } else if LinkText.isWhitespaceByte(c) {
                out.append(c)
            } else {
                pendingComma = -1
                out.append(c)
            }
            i += 1
        }
        return LinkText.string(out)
    }

    /// The outbounds of one config, and the name its `remarks` gives them.
    private struct Document {
        var outbounds: [ImportJSONObject]
        var remarks: String?
    }

    private static func collectDocuments(_ root: ImportJSON) -> [Document] {
        switch root {
        case .array(let elements):
            let items = elements.objectElements
            let configs = items.filter { $0.has("outbounds") }.map { documentOf($0) }
            let bare = items.filter { $0.has("protocol") }
            return bare.isEmpty ? configs : configs + [Document(outbounds: bare, remarks: nil)]
        case .object(let object):
            if object.has("outbounds") { return [documentOf(object)] }
            if object.has("protocol") { return [Document(outbounds: [object], remarks: nil)] }
            // v2rayNG exports a profile as {"outbound": {...}} in some places.
            if object.has("outbound") {
                let inner = object.optObject("outbound").map { [$0] } ?? []
                return [Document(outbounds: inner, remarks: remarksOf(object))]
            }
            return []
        default:
            return []
        }
    }

    private static func documentOf(_ config: ImportJSONObject) -> Document {
        Document(outbounds: config.optArray("outbounds")?.objectElements ?? [], remarks: remarksOf(config))
    }

    private static func remarksOf(_ config: ImportJSONObject) -> String? {
        ShareLinkParams.nonEmpty(LinkText.trim(config.optString("remarks")))
    }

    private static func dialerProxyOf(_ outbound: ImportJSONObject) -> String? {
        ShareLinkParams.nonEmpty(outbound.optObject("streamSettings")?.optObject("sockopt")?.optString("dialerProxy"))
    }

    // MARK: - Conversion

    private static func convert(_ outbound: ImportJSONObject, byTag: [String: ImportJSONObject], name: String, depth: Int) throws -> ProxyConfiguration {
        if depth > 8 { throw MythaiaError.parse("dialerProxy chain is too deep or circular") }
        let proto = outbound.optString("protocol").lowercased()
        let stream = outbound.optObject("streamSettings") ?? ImportJSONObject()

        // What this outbound dials through.
        var fragment: String? = nil
        var chain: [ProxyConfiguration]? = nil
        if let tag = dialerProxyOf(outbound) {
            guard let hop = byTag[tag] else { throw MythaiaError.parse("dialerProxy '\(tag)' is not defined") }
            let hopProtocol = hop.optString("protocol").lowercased()
            if hopProtocol == "freedom" {
                fragment = fragmentParam(hop)
            } else if proxyProtocols.contains(hopProtocol) {
                let entry = try convert(hop, byTag: byTag, name: tag, depth: depth + 1)
                if entry.outboundProtocol.isLayer3 {
                    throw MythaiaError.parse("dialerProxy '\(tag)' is WireGuard, which cannot carry another proxy")
                }
                chain = (entry.chain ?? []) + [entry.withChain(nil)]
            }
        }

        let config: ProxyConfiguration
        if proto == "wireguard" {
            // WireGuard has no link of its own worth round-tripping through;
            // it is stored as the INI a link would have become anyway.
            config = try wireGuardConfig(outbound, name: name)
        } else {
            let link: String
            switch proto {
            case "vless": link = try vlessLink(outbound, stream: stream, name: name, fragment: fragment)
            case "vmess": link = try vmessLink(outbound, stream: stream, name: name)
            case "trojan": link = try trojanLink(outbound, stream: stream, name: name, fragment: fragment)
            case "shadowsocks": link = try shadowsocksLink(outbound, name: name)
            case "socks": link = try socksLink(outbound, name: name)
            case "http": link = try httpLink(outbound, stream: stream, name: name)
            case "hysteria", "hysteria2": link = try hysteriaLink(outbound, stream: stream, name: name)
            default: throw MythaiaError.parse("\(proto) outbounds are not supported")
            }
            config = try ProxyConfiguration.fromUrl(link)
        }
        guard let hops = chain, !hops.isEmpty else { return config }
        if config.outboundProtocol.isLayer3 {
            throw MythaiaError.parse("WireGuard is a whole interface and cannot be dialled through another proxy")
        }
        return config.withChain(hops)
    }

    private static func firstServer(_ outbound: ImportJSONObject, _ key: String) throws -> ImportJSONObject {
        guard let server = outbound.optObject("settings")?.optArray(key)?.optObject(0) else {
            throw MythaiaError.parse("\(outbound.optString("protocol")): settings.\(key) is empty")
        }
        return server
    }

    private static func hostPort(_ server: ImportJSONObject) throws -> String {
        let address = server.optString("address")
        if address.isEmpty { throw MythaiaError.parse("server address is missing") }
        let port = server.optInt("port", 0)
        if port < 1 || port > 65535 { throw MythaiaError.parse("server port is missing") }
        let host = (address.utf8.contains(UInt8(ascii: ":")) && !LinkText.hasPrefix(address, "[")) ? "[\(address)]" : address
        return "\(host):\(port)"
    }

    /// An ordered query: keys stay in the order they were first set in.
    private struct Params {
        private(set) var keys: [String] = []
        private var values: [String: String] = [:]

        init() {}

        subscript(key: String) -> String? {
            get { values[key] }
            set {
                if let value = newValue {
                    if values.updateValue(value, forKey: key) == nil { keys.append(key) }
                } else if values.removeValue(forKey: key) != nil {
                    keys.removeAll { $0 == key }
                }
            }
        }

        var isEmpty: Bool { keys.isEmpty }

        func query() -> String {
            keys.map { "\($0)=" + LinkText.urlEncode(values[$0] ?? "") }.joined(separator: "&")
        }
    }

    /// The query a share link would carry for these stream settings.
    private static func streamParams(_ stream: ImportJSONObject, fragment: String?) throws -> Params {
        var params = Params()
        var network = stream.optString("network", "tcp").lowercased()
        switch network {
        case "splithttp": network = "xhttp"
        case "h2", "http": network = "http"
        default: break
        }
        let security = stream.optString("security", "none").lowercased()
        params["type"] = network
        params["security"] = security

        switch network {
        case "ws":
            if let ws = stream.optObject("wsSettings") {
                if let path = ShareLinkParams.nonEmpty(ws.optString("path")) { params["path"] = path }
                let host = ShareLinkParams.nonEmpty(ws.optString("host"))
                    ?? ShareLinkParams.nonEmpty(ws.optObject("headers")?.optString("Host"))
                if let host = host { params["host"] = host }
            }
        case "httpupgrade":
            if let hu = stream.optObject("httpupgradeSettings") {
                if let path = ShareLinkParams.nonEmpty(hu.optString("path")) { params["path"] = path }
                if let host = ShareLinkParams.nonEmpty(hu.optString("host")) { params["host"] = host }
            }
        case "xhttp":
            if let x = stream.optObject("xhttpSettings") ?? stream.optObject("splithttpSettings") {
                if let path = ShareLinkParams.nonEmpty(x.optString("path")) { params["path"] = path }
                if let host = ShareLinkParams.nonEmpty(x.optString("host")) { params["host"] = host }
                if let mode = ShareLinkParams.nonEmpty(x.optString("mode")) { params["mode"] = mode }
                if let extra = x.optObject("extra") { params["extra"] = extra.serialized() }
            }
        case "grpc", "gun":
            if let g = stream.optObject("grpcSettings") {
                params["type"] = "grpc"
                if let serviceName = ShareLinkParams.nonEmpty(g.optString("serviceName")) { params["serviceName"] = serviceName }
                if let authority = ShareLinkParams.nonEmpty(g.optString("authority")) { params["authority"] = authority }
                if g.optBoolean("multiMode", false) { params["mode"] = "multi" }
                if let userAgent = ShareLinkParams.nonEmpty(g.optString("user_agent")) { params["userAgent"] = userAgent }
            }
        case "tcp", "raw":
            params["type"] = "tcp"
            let settings = stream.optObject("tcpSettings") ?? stream.optObject("rawSettings")
            if let header = settings?.optObject("header")?.optString("type"), header != "none", !header.isEmpty {
                throw MythaiaError.parse("tcp header type '\(header)' is not supported")
            }
        default:
            throw MythaiaError.parse("\(network) transport is not supported")
        }

        switch security {
        case "tls":
            if let tls = stream.optObject("tlsSettings") {
                tlsParams(tls, &params)
                if tls.optBoolean("allowInsecure", false) { params["allowInsecure"] = "1" }
            }
        case "reality":
            if let r = stream.optObject("realitySettings") {
                if let v = ShareLinkParams.nonEmpty(r.optString("serverName")) { params["sni"] = v }
                if let v = ShareLinkParams.nonEmpty(r.optString("fingerprint")) { params["fp"] = v }
                if let v = ShareLinkParams.nonEmpty(r.optString("publicKey")) { params["pbk"] = v }
                if let v = ShareLinkParams.nonEmpty(r.optString("shortId")) { params["sid"] = v }
                if let v = ShareLinkParams.nonEmpty(r.optString("spiderX")) { params["spx"] = v }
            }
        default:
            break
        }
        if let fragment = fragment, security == "tls" { params["fragment"] = fragment }
        // FinalMask travels as the link's `fm=`, the same document a share
        // link from the same panel carries, so its fragment settings land on
        // the server exactly as they would from the link.
        if let finalMask = stream.optObject("finalmask"), !finalMask.isEmpty {
            params["fm"] = finalMask.serialized()
        }
        return params
    }

    /**
     * The TLS fields every protocol's link spells the same way. Certificate
     * pinning comes from `pinnedPeerCertSha256` and `verifyPeerCertByName`,
     * which Xray 26 has instead of `allowInsecure`; the caller adds the
     * insecure flag under the name its link uses.
     */
    private static func tlsParams(_ tls: ImportJSONObject, _ params: inout Params) {
        if let v = ShareLinkParams.nonEmpty(tls.optString("serverName")) { params["sni"] = v }
        if let v = ShareLinkParams.nonEmpty(tls.optString("fingerprint")) { params["fp"] = v }
        let alpn = stringList(tls.opt("alpn"))
        if !alpn.isEmpty { params["alpn"] = alpn.joined(separator: ",") }
        let pins = stringList(tls.opt("pinnedPeerCertSha256"))
        if !pins.isEmpty { params["pcs"] = pins.joined(separator: ",") }
        if let v = ShareLinkParams.nonEmpty(tls.optString("verifyPeerCertByName")) { params["vcn"] = v }
    }

    /// A JSON string, comma-separated string or array of strings, as a list.
    static func stringList(_ value: ImportJSON?) -> [String] {
        guard let value = value else { return [] }
        switch value {
        case .array(let items):
            var out: [String] = []
            for item in items where !item.isNull {
                let text = LinkText.trim(item.text)
                if !text.isEmpty { out.append(text) }
            }
            return out
        case .string(let text):
            return LinkText.split(text, UInt8(ascii: ",")).map { LinkText.trim($0) }.filter { !$0.isEmpty }
        default:
            return []
        }
    }

    /// Xray's freedom `fragment` block as the link's `fragment=` value.
    private static func fragmentParam(_ freedom: ImportJSONObject) -> String? {
        guard let f = freedom.optObject("settings")?.optObject("fragment") else { return nil }
        let length = ShareLinkParams.nonEmpty(f.optString("length")) ?? "100-200"
        let interval = ShareLinkParams.nonEmpty(f.optString("interval")) ?? "10-20"
        return "\(length),\(interval),tlshello"
    }

    /**
     * Hysteria's bandwidth as whole Mbps.
     *
     * A number is already Mbps, as in sing-box's `up_mbps` and Clash's `up`;
     * a string may carry Hysteria's own unit (`100 mbps`, `1 gbps`,
     * `500kbps`, bits per second throughout). Nil for absent, zero or
     * unreadable: zero means "let the congestion controller decide", and
     * nil is how the model says that.
     */
    static func bandwidthMbps(_ value: ImportJSON?) -> Int? {
        guard let value = value else { return nil }
        let mbps: Double
        switch value {
        case .number:
            guard let number = value.doubleValue else { return nil }
            mbps = number
        case .string(let text):
            guard let parsed = parseBandwidthText(text) else { return nil }
            mbps = parsed
        default:
            return nil
        }
        if mbps <= 0 || !mbps.isFinite { return nil }
        return max(1, Int(min(mbps.rounded(), Double(Int32.max))))
    }

    /// `^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z/]*)\s*$`, scaled to Mbps.
    private static func parseBandwidthText(_ text: String) -> Double? {
        let bytes = Array(LinkText.trim(text).utf8)
        var i = 0
        while i < bytes.count && bytes[i] >= 48 && bytes[i] <= 57 { i += 1 }
        if i == 0 { return nil }
        if i < bytes.count && bytes[i] == 46 {
            var j = i + 1
            while j < bytes.count && bytes[j] >= 48 && bytes[j] <= 57 { j += 1 }
            if j == i + 1 { return nil }
            i = j
        }
        guard let amount = Double(LinkText.string(bytes[0..<i])) else { return nil }
        let unitBytes = Array(ClashYAML.trimmedStart(bytes[i...]))
        let isUnitByte: (UInt8) -> Bool = { b in (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b == 47 }
        guard unitBytes.allSatisfy(isUnitByte) else { return nil }
        var unit = LinkText.string(unitBytes).lowercased()
        unit = LinkText.removeSuffix(unit, "/s")
        unit = LinkText.removeSuffix(unit, "ps")
        switch unit {
        case "", "m", "mb", "mbit": return amount
        case "b", "bit": return amount / 1_000_000
        case "k", "kb", "kbit": return amount / 1_000
        case "g", "gb", "gbit": return amount * 1_000
        case "t", "tb", "tbit": return amount * 1_000_000
        default: return nil
        }
    }

    private static func encode(_ value: String) -> String {
        LinkText.urlEncode(value)
    }

    private static func vlessLink(_ outbound: ImportJSONObject, stream: ImportJSONObject, name: String, fragment: String?) throws -> String {
        let server = try firstServer(outbound, "vnext")
        guard let user = server.optArray("users")?.optObject(0) else {
            throw MythaiaError.parse("vless: no user in vnext")
        }
        let id = user.optString("id")
        if id.isEmpty { throw MythaiaError.parse("vless: user id is missing") }
        var params = try streamParams(stream, fragment: fragment)
        params["encryption"] = ShareLinkParams.nonEmpty(user.optString("encryption")) ?? "none"
        if let flow = ShareLinkParams.nonEmpty(user.optString("flow")) { params["flow"] = flow }
        if let mux = outbound.optObject("mux"), !mux.optBoolean("enabled", false) { params["mux"] = "false" }
        let endpoint = try hostPort(server)
        return "vless://\(encode(id))@\(endpoint)?\(params.query())#\(encode(name.isEmpty ? endpoint : name))"
    }

    private static func vmessLink(_ outbound: ImportJSONObject, stream: ImportJSONObject, name: String) throws -> String {
        let server = try firstServer(outbound, "vnext")
        guard let user = server.optArray("users")?.optObject(0) else {
            throw MythaiaError.parse("vmess: no user in vnext")
        }
        let params = try streamParams(stream, fragment: nil)
        // The link has no spelling for Reality; written as `tls: ""` the
        // outbound would import as plaintext VMess and never connect.
        if params["security"] == "reality" { throw MythaiaError.parse("vmess: Reality is not supported") }
        let endpoint = try hostPort(server)
        var json = ImportJSONObject()
        json.put("v", "2")
        json.put("ps", name.isEmpty ? endpoint : name)
        json.put("add", server.optString("address"))
        json.put("port", server.optInt("port"))
        json.put("id", user.optString("id"))
        json.put("aid", user.optInt("alterId", 0))
        json.put("scy", ShareLinkParams.nonEmpty(user.optString("security")) ?? "auto")
        json.put("net", params["type"] ?? "tcp")
        json.put("type", "none")
        json.put("host", params["host"] ?? "")
        json.put("path", params["path"] ?? params["serviceName"] ?? "")
        json.put("tls", params["security"] == "tls" ? "tls" : "")
        json.put("sni", params["sni"] ?? "")
        json.put("fp", params["fp"] ?? "")
        json.put("alpn", params["alpn"] ?? "")
        if params["allowInsecure"] == "1" { json.put("allowInsecure", "1") }
        if let pcs = params["pcs"] { json.put("pcs", pcs) }
        if let vcn = params["vcn"] { json.put("vcn", vcn) }
        return "vmess://" + LinkText.base64Encode(Array(json.serialized().utf8))
    }

    private static func trojanLink(_ outbound: ImportJSONObject, stream: ImportJSONObject, name: String, fragment: String?) throws -> String {
        let server = try firstServer(outbound, "servers")
        let password = server.optString("password")
        if password.isEmpty { throw MythaiaError.parse("trojan: password is missing") }
        var params = try streamParams(stream, fragment: fragment)
        if params["security"] == "none" { params["security"] = "tls" }
        let endpoint = try hostPort(server)
        return "trojan://\(encode(password))@\(endpoint)?\(params.query())#\(encode(name.isEmpty ? endpoint : name))"
    }

    private static func shadowsocksLink(_ outbound: ImportJSONObject, name: String) throws -> String {
        let server = try firstServer(outbound, "servers")
        let method = server.optString("method")
        if method.isEmpty { throw MythaiaError.parse("shadowsocks: method is missing") }
        let password = server.optString("password")
        let userInfo = LinkText.base64UrlEncode(Array("\(method):\(password)".utf8))
        let endpoint = try hostPort(server)
        return "ss://\(userInfo)@\(endpoint)#\(encode(name.isEmpty ? endpoint : name))"
    }

    private static func socksLink(_ outbound: ImportJSONObject, name: String) throws -> String {
        let server = try firstServer(outbound, "servers")
        var auth = ""
        if let user = server.optArray("users")?.optObject(0) {
            auth = encode(user.optString("user")) + ":" + encode(user.optString("pass")) + "@"
        }
        let endpoint = try hostPort(server)
        return "socks5://\(auth)\(endpoint)#\(encode(name.isEmpty ? endpoint : name))"
    }

    /**
     * An HTTPS proxy as the `https://user:pass@host:port` link the naive
     * parser reads. That link has no query — a `?sni=` would be read as part
     * of the port — so the server name has to be the host itself, and one
     * that differs is refused rather than silently dropped.
     */
    private static func httpLink(_ outbound: ImportJSONObject, stream: ImportJSONObject, name: String) throws -> String {
        let server = try firstServer(outbound, "servers")
        if stream.optString("security", "none") != "tls" {
            throw MythaiaError.parse("http: only an HTTPS proxy (security tls) is supported")
        }
        guard let user = server.optArray("users")?.optObject(0) else {
            throw MythaiaError.parse("http: a user and password are required")
        }
        if let serverName = ShareLinkParams.nonEmpty(stream.optObject("tlsSettings")?.optString("serverName")),
           serverName.lowercased() != server.optString("address").lowercased() {
            throw MythaiaError.parse("http: a server name (\(serverName)) different from the address is not supported")
        }
        let endpoint = try hostPort(server)
        return "https://\(encode(user.optString("user"))):\(encode(user.optString("pass")))@\(endpoint)#\(encode(name.isEmpty ? endpoint : name))"
    }

    /**
     * Xray's `hysteria` outbound (Hysteria2, `version: 2`) as a `hysteria2://`
     * link.
     *
     * The server sits in `settings` itself (`address`, `port`), or in
     * `settings.servers[0]` in configs written by tools that treat it like
     * Trojan. The password is `hysteriaSettings.auth` in the stream settings;
     * Salamander comes from FinalMask's `udp` list, which is where Xray moved
     * it from Hysteria's own `obfs` block.
     */
    private static func hysteriaLink(_ outbound: ImportJSONObject, stream: ImportJSONObject, name: String) throws -> String {
        let settings = outbound.optObject("settings") ?? ImportJSONObject()
        let hysteria = stream.optObject("hysteriaSettings") ?? ImportJSONObject()
        let version = hysteria.optInt("version", settings.optInt("version", 2))
        if version != 2 { throw MythaiaError.parse("hysteria: version \(version) is not supported, only Hysteria2") }

        let server: ImportJSONObject
        if !settings.optString("address").isEmpty {
            server = settings
        } else if let first = settings.optArray("servers")?.optObject(0) {
            server = first
        } else {
            throw MythaiaError.parse("hysteria: server address is missing")
        }
        let auth = ShareLinkParams.nonEmpty(hysteria.optString("auth"))
            ?? ShareLinkParams.nonEmpty(settings.optString("password"))
            ?? ShareLinkParams.nonEmpty(settings.optString("auth"))
            ?? ShareLinkParams.nonEmpty(server.optString("password"))
        guard let password = auth else { throw MythaiaError.parse("hysteria: auth is missing") }

        var params = Params()
        if let tls = stream.optObject("tlsSettings") {
            tlsParams(tls, &params)
            if tls.optBoolean("allowInsecure", false) { params["insecure"] = "1" }
        }
        if let masks = stream.optObject("finalmask")?.optArray("udp") {
            for element in masks {
                guard let mask = element.objectValue, mask.optString("type") == "salamander" else { continue }
                guard let obfsPassword = ShareLinkParams.nonEmpty(mask.optObject("settings")?.optString("password")) else { continue }
                params["obfs"] = "salamander"
                params["obfs-password"] = obfsPassword
                break
            }
        }
        if let up = bandwidthMbps(hysteria.opt("up")) { params["upmbps"] = String(up) }
        if let down = bandwidthMbps(hysteria.opt("down")) { params["downmbps"] = String(down) }

        let endpoint = try hostPort(server)
        let q = params.isEmpty ? "" : "?" + params.query()
        return "hysteria2://\(encode(password))@\(endpoint)\(q)#\(encode(name.isEmpty ? endpoint : name))"
    }

    /// Xray's `wireguard` outbound, as the wg-quick INI the profile is stored as.
    private static func wireGuardConfig(_ outbound: ImportJSONObject, name: String) throws -> ProxyConfiguration {
        guard let settings = outbound.optObject("settings") else {
            throw MythaiaError.parse("wireguard: settings are missing")
        }
        guard let peer = settings.optArray("peers")?.optObject(0) else {
            throw MythaiaError.parse("wireguard: no peer")
        }
        let endpointText = peer.optString("endpoint")
        guard let endpoint = WireGuardIni.splitEndpoint(endpointText) else {
            throw MythaiaError.parse("wireguard: peer endpoint '\(endpointText)' is not host:port")
        }
        let mtu = settings.optInt("mtu", 0)
        let ini = WireGuardIni.build(
            privateKey: settings.optString("secretKey"),
            addresses: stringList(settings.opt("address")),
            peer: WireGuardIni.Peer(
                publicKey: peer.optString("publicKey"),
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                presharedKey: ShareLinkParams.nonEmpty(peer.optString("preSharedKey")),
                allowedIps: stringList(peer.opt("allowedIPs")),
                keepalive: peer.optInt("keepAlive", 0)
            ),
            mtu: mtu > 0 ? mtu : nil,
            reserved: WireGuardIni.reservedFromJson(settings.opt("reserved"))
        )
        let label = name.isEmpty ? WireGuardIni.endpoint(endpoint.host, endpoint.port) : name
        return try ProxyConfiguration.fromWireGuardConfig(ini, name: label)
    }
}
