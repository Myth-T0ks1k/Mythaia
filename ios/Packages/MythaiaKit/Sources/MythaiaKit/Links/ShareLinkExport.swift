import Foundation

/// A server as the share link other clients read.
extension ProxyConfiguration {

    public func toUrl() -> String {
        switch outboundProtocol {
        case .vless: return toVlessUrl()
        case .trojan: return toTrojanUrl()
        case .shadowsocks: return toShadowsocksUrl()
        case .socks5: return toSocks5Url()
        case .naiveHttp11, .naiveHttp2: return toNaiveUrl()
        case .hysteria2: return toHysteria2Url()
        case .anytls: return toAnyTlsUrl()
        case .vmess: return toVmessUrl()
        case .tuic: return toTuicUrl()
        case .sudoku: return toSudokuUrl()
        case .nowhere: return toNowhereUrl()
        // WireGuard has no share-link scheme; peers hand out the INI itself,
        // so exporting one gives back exactly what was imported.
        case .wireguard: return wireGuardConfig ?? ""
        }
    }

    private func urlEncode(_ value: String) -> String {
        LinkText.urlEncode(value)
    }

    private func query(_ params: [String]) -> String {
        params.isEmpty ? "" : "?" + params.joined(separator: "&")
    }

    /**
     * `hysteria2://password@host:port?…#name`.
     *
     * Always the long spelling: `hy2://` is an accepted alias on the way in,
     * and emitting the canonical scheme keeps a round trip stable.
     */
    private func toHysteria2Url() -> String {
        var params: [String] = []
        if let tls = tls { appendPasswordProtocolTlsParams(&params, tls) }
        if let up = hysteriaUpMbps { params.append("upmbps=\(up)") }
        if let down = hysteriaDownMbps { params.append("downmbps=\(down)") }
        if let obfs = obfuscation { params.append("obfs=\(obfs)") }
        if let obfsPassword = obfuscationPassword { params.append("obfs-password=" + urlEncode(obfsPassword)) }
        return "hysteria2://\(urlEncode(password ?? ""))@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    /**
     * `vmess://` + base64 of the v2rayN JSON object.
     *
     * `v` is the object's own format version and is always 2; `aid` is always
     * 0, because that is the only header this client speaks.
     */
    private func toVmessUrl() -> String {
        var json = ImportJSONObject()
        json.put("v", "2")
        json.put("ps", name)
        json.put("add", serverAddress)
        json.put("port", String(serverPort))
        json.put("id", uuid.uuidString.lowercased())
        json.put("aid", "0")
        json.put("scy", vmessSecurity ?? "auto")
        json.put("net", transport)
        json.put("type", grpc?.multiMode == true ? "multi" : "none")
        if let ws = websocket {
            json.put("path", ws.path)
            json.put("host", ws.host)
        }
        if let hu = httpUpgrade {
            json.put("path", hu.path)
            json.put("host", hu.host)
        }
        if let g = grpc {
            json.put("path", g.serviceName)
            if !g.authority.isEmpty { json.put("authority", g.authority) }
        }
        if let x = xhttp {
            json.put("path", x.path)
            json.put("host", x.host)
            json.put("mode", x.mode.raw)
            let extra = x.toExtraJson()
            if !LinkText.isBlank(extra) { json.put("extra", extra) }
        }
        if let tls = tls {
            json.put("tls", "tls")
            json.put("sni", tls.serverName)
            if let alpn = tls.alpn, !alpn.isEmpty {
                json.put("alpn", alpn.joined(separator: ","))
            }
            json.put("fp", tls.fingerprint.raw)
            // Without this a shared link silently turns certificate checking
            // back on, and the server the user could reach stops working.
            if tls.allowInsecure { json.put("allowInsecure", "true") }
            if let pins = tls.pinnedCertSha256, !pins.isEmpty { json.put("pcs", pins.joined(separator: ",")) }
            if let verifyName = tls.verifyName { json.put("vcn", verifyName) }
        } else {
            json.put("tls", "")
        }
        return "vmess://" + LinkText.base64Encode(Array(json.serialized().utf8))
    }

    /// `tuic://uuid:password@host:port?sni=…#name`, the shape clients emit.
    private func toTuicUrl() -> String {
        var params: [String] = []
        if let tls = tls { appendPasswordProtocolTlsParams(&params, tls) }
        return "tuic://\(uuid.uuidString.lowercased()):\(urlEncode(password ?? ""))@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    /**
     * `nowhere://key@host:port?up=…&down=…&mux=1&sni=…&alpn=…#name`.
     *
     * The key rides in the userinfo the way the password-authenticated schemes
     * carry theirs, and the carriers are always spelled out — `up`/`down` are
     * emitted unconditionally so a link is self-describing even when both sides
     * are the reference default `udp`. `mux=1` appears only when a stream
     * carrier is present to honour it, matching the reference exporter; and, as
     * there, the fingerprint and ECH are not carried — Nowhere pins neither.
     */
    private func toNowhereUrl() -> String {
        guard let tls = tls else { return "" }
        let up = nowhereUplink ?? NowhereNetwork.udp.wireName
        let down = nowhereDownlink ?? NowhereNetwork.udp.wireName
        var params = ["up=\(up)", "down=\(down)"]
        let tcp = NowhereNetwork.tcp.wireName
        if (up == tcp || down == tcp) && nowhereMultiplex {
            params.append("mux=1")
        }
        if tls.serverName != serverAddress { params.append("sni=" + urlEncode(tls.serverName)) }
        if let first = tls.alpn?.first, !first.isEmpty { params.append("alpn=" + urlEncode(first)) }
        // Not in the reference exporter, which never skips verification;
        // other clients ignore what they do not know.
        if tls.allowInsecure { params.append("insecure=1") }
        appendPinParams(&params, tls)
        return "nowhere://\(urlEncode(password ?? ""))@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    /**
     * `sudoku://` + base64url of a compact JSON object — the reference's short
     * link, not a query-string scheme.
     *
     * The payload is built from the resolved `SudokuConfiguration` so that what
     * a link carries is exactly what the dial would use (normalised tables, the
     * ascii mode's short token, the padding pair left implicit). Keys are sorted
     * so the encoding is byte-stable across runs and matches the reference's
     * sorted-key serialisation; only the fields that differ from a default are
     * written, which is what keeps `toUrl(fromUrl(x))` a fixed point. A profile
     * that somehow lost its key exports the bare scheme rather than throwing,
     * mirroring the reference's own fallback.
     */
    private func toSudokuUrl() -> String {
        guard let sudoku = try? toSudokuConfiguration() else { return "sudoku://" }
        var fields: [String: ImportJSON] = [
            "h": .string(serverAddress),
            "p": .number(String(serverPort)),
            "k": .string(sudoku.key),
            "a": .string(sudoku.asciiMode.shortLinkToken),
            "e": .string(sudoku.aeadMethod.id),
            "x": .bool(!sudoku.enablePureDownlink),
        ]
        let trimmedName = LinkText.trim(name)
        if !trimmedName.isEmpty { fields["n"] = .string(trimmedName) }
        if !sudoku.customTables.isEmpty { fields["ts"] = .array(sudoku.customTables.map { ImportJSON.string($0) }) }
        if sudoku.httpMask.disable { fields["hd"] = .bool(true) }
        if sudoku.httpMask.mode != .legacy { fields["hm"] = .string(sudoku.httpMask.mode.id) }
        if sudoku.httpMask.tls { fields["ht"] = .bool(true) }
        if !sudoku.httpMask.host.isEmpty { fields["hh"] = .string(sudoku.httpMask.host) }
        if sudoku.multiplex != .off { fields["hx"] = .string(sudoku.multiplex.id) }
        if !sudoku.httpMask.pathRoot.isEmpty { fields["hy"] = .string(sudoku.httpMask.pathRoot) }

        // Written by hand with the keys sorted and plain RFC 8259 escaping, so
        // one config always yields one link, byte-identical to the reference's.
        var object = ImportJSONObject()
        for key in fields.keys.sorted() {
            if let value = fields[key] { object.put(key, value) }
        }
        return "sudoku://" + LinkText.base64UrlEncode(Array(object.serialized().utf8))
    }

    /// `anytls://password@host:port?sni=…&alpn=…&fp=…#name`.
    private func toAnyTlsUrl() -> String {
        var params: [String] = []
        if let tls = tls { appendPasswordProtocolTlsParams(&params, tls) }
        return "anytls://\(urlEncode(password ?? ""))@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    /**
     * The TLS query shared by the password-authenticated schemes.
     *
     * Separate from `appendTlsParams` because these links spell "do not verify"
     * `insecure=1`, not `allowInsecure=1`, and carry no version bounds.
     */
    private func appendPasswordProtocolTlsParams(_ params: inout [String], _ tls: TlsConfiguration) {
        if tls.serverName != serverAddress { params.append("sni=\(tls.serverName)") }
        if let alpn = tls.alpn, !alpn.isEmpty {
            params.append("alpn=" + urlEncode(alpn.joined(separator: ",")))
        }
        if tls.fingerprint != .chrome133 { params.append("fp=\(tls.fingerprint.raw)") }
        if tls.allowInsecure { params.append("insecure=1") }
        if let ech = tls.echConfig { params.append("ech=" + urlEncode(ech)) }
        appendPinParams(&params, tls)
    }

    /// `pcs=` and `vcn=`, Xray 26's replacements for `allowInsecure`.
    private func appendPinParams(_ params: inout [String], _ tls: TlsConfiguration) {
        if let pins = tls.pinnedCertSha256, !pins.isEmpty { params.append("pcs=" + pins.joined(separator: ",")) }
        if let verifyName = tls.verifyName { params.append("vcn=" + urlEncode(verifyName)) }
    }

    private func toTrojanUrl() -> String {
        // Password in userinfo (whole chunk, no user:pass split), TLS
        // sni/alpn/fp optional in query.
        let encodedPassword = urlEncode(trojanPassword ?? "")
        var params: [String] = []
        if let tls = trojanTls {
            if tls.serverName != impliedServerName { params.append("sni=\(tls.serverName)") }
            if let alpn = tls.alpn, !alpn.isEmpty {
                params.append("alpn=" + urlEncode(alpn.joined(separator: ",")))
            }
            if tls.fingerprint != .chrome133 { params.append("fp=\(tls.fingerprint.raw)") }
            if tls.allowInsecure { params.append("allowInsecure=1") }
            if let ech = tls.echConfig { params.append("ech=" + urlEncode(ech)) }
            appendPinParams(&params, tls)
            if let fragment = tls.fragment { params.append("fragment=" + urlEncode(fragment.toShareLinkValue())) }
        }
        if transport != "tcp" {
            params.append("type=\(transport)")
            appendTransportParams(&params)
        }
        return "trojan://\(encodedPassword)@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    private func toVlessUrl() -> String {
        var params: [String] = []
        if encryption != "none" { params.append("encryption=\(encryption)") }
        if let flow = flow, !flow.isEmpty { params.append("flow=\(flow)") }
        params.append("security=\(security)")
        if transport != "tcp" { params.append("type=\(transport)") }

        if security == "tls", let tls = tls {
            appendTlsParams(&params, tls)
        }

        if security == "reality", let reality = reality {
            params.append("sni=\(reality.serverName)")
            params.append("pbk=" + LinkText.base64UrlEncode(reality.publicKey))
            if !reality.shortId.isEmpty { params.append("sid=" + LinkText.hex(reality.shortId)) }
            // The importers default a missing fp to chrome_133, so that is the
            // one value safe to leave out.
            if reality.fingerprint != .chrome133 { params.append("fp=\(reality.fingerprint.raw)") }
        }

        appendTransportParams(&params)
        if !muxEnabled { params.append("mux=false") }
        if !xudpEnabled { params.append("xudp=false") }
        // testseed is a local override and not exported: round-trip parity
        // with other clients' links matters more.

        return "vless://\(uuid.uuidString.lowercased())@\(bracketedServerAddress):\(serverPort)/\(query(params))#\(urlEncode(name))"
    }

    private func toShadowsocksUrl() -> String {
        // Plain `ss://base64(method:password)@host:port/#name` — no
        // transport/security params. Shadowsocks runs over bare TCP.
        guard let method = ssMethod, let ssPassword = ssPassword else { return "ss://invalid" }
        let userInfo = "\(method):\(ssPassword)"
        // SIP002 wants the URL-safe alphabet: a "/" from the standard one
        // ends the authority for any client that parses the link as a URL.
        let encoded = LinkText.base64UrlEncode(Array(userInfo.utf8))
        return "ss://\(encoded)@\(bracketedServerAddress):\(serverPort)/#\(urlEncode(name))"
    }

    /**
     * Emits TLS query params (sni, alpn, fp, allowInsecure, minVersion,
     * maxVersion, fragment).
     */
    private func appendTlsParams(_ params: inout [String], _ tls: TlsConfiguration) {
        if tls.serverName != impliedServerName { params.append("sni=\(tls.serverName)") }
        if let alpn = tls.alpn, !alpn.isEmpty {
            params.append("alpn=" + urlEncode(alpn.joined(separator: ",")))
        }
        if tls.fingerprint != .chrome133 { params.append("fp=\(tls.fingerprint.raw)") }
        if tls.allowInsecure { params.append("allowInsecure=1") }
        // The config's exact bytes are what the server matches on, so it goes
        // out as it came in rather than re-encoded.
        if let ech = tls.echConfig { params.append("ech=" + urlEncode(ech)) }
        if let minVersion = tls.minVersion { params.append("minVersion=\(minVersion.urlValue)") }
        if let maxVersion = tls.maxVersion { params.append("maxVersion=\(maxVersion.urlValue)") }
        appendPinParams(&params, tls)
        // Only a per-server override is exported; a server following the
        // tunnel-wide default carries no `fragment=`, which is what the
        // default means.
        if let fragment = tls.fragment, fragment.isEnabled {
            params.append("fragment=" + urlEncode(fragment.toShareLinkValue()))
        }
    }

    private func toNaiveUrl() -> String {
        let user = urlEncode(naiveUsername ?? "")
        let pass = urlEncode(naivePassword ?? "")
        var params: [String] = []
        // The bare scheme reads back as HTTP/2, so an HTTPS (HTTP/1.1) proxy
        // has to say so or it changes protocol on the way round.
        if outboundProtocol == .naiveHttp11 { params.append("http=1.1") }
        if let tls = tls {
            if tls.serverName != serverAddress { params.append("sni=" + urlEncode(tls.serverName)) }
            if tls.allowInsecure { params.append("insecure=1") }
            appendPinParams(&params, tls)
        }
        return "https://\(user):\(pass)@\(bracketedServerAddress):\(serverPort)\(query(params))#\(urlEncode(name))"
    }

    private func toSocks5Url() -> String {
        var userInfo = ""
        if let username = socks5Username, !username.isEmpty {
            userInfo = urlEncode(username) + ":" + urlEncode(socks5Password ?? "") + "@"
        }
        return "socks5://\(userInfo)\(bracketedServerAddress):\(serverPort)#\(urlEncode(name))"
    }

    private func appendTransportParams(_ params: inout [String]) {
        if transport == "ws", let ws = websocket {
            if ws.host != serverAddress { params.append("host=\(ws.host)") }
            if ws.path != "/" { params.append("path=" + urlEncode(ws.path)) }
            if ws.maxEarlyData > 0 {
                params.append("ed=\(ws.maxEarlyData)")
                if ws.earlyDataHeaderName != "Sec-WebSocket-Protocol" {
                    params.append("eh=" + urlEncode(ws.earlyDataHeaderName))
                }
            }
        }
        if transport == "httpupgrade", let hu = httpUpgrade {
            if hu.host != serverAddress { params.append("host=\(hu.host)") }
            if hu.path != "/" { params.append("path=" + urlEncode(hu.path)) }
        }
        if transport == "xhttp", let x = xhttp {
            if x.host != serverAddress { params.append("host=\(x.host)") }
            if x.path != "/" { params.append("path=" + urlEncode(x.path)) }
            if x.mode != .auto { params.append("mode=\(x.mode.raw)") }
            let extra = x.toExtraJson()
            if !extra.isEmpty { params.append("extra=" + urlEncode(extra)) }
        }
        if transport == "grpc", let g = grpc {
            if !g.serviceName.isEmpty { params.append("serviceName=" + urlEncode(g.serviceName)) }
            if !g.authority.isEmpty { params.append("authority=" + urlEncode(g.authority)) }
            if g.multiMode { params.append("mode=multi") }
        }
    }
}
