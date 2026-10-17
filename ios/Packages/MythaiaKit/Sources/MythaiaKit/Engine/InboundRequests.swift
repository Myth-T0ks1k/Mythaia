import Foundation

/// The result of parsing a request from the bytes received so far.
enum InboundParse<Value> {
    /// More bytes are needed.
    case incomplete
    /// Not a request this proxy accepts.
    case invalid(String)
    /// The request and how many bytes of the input it took.
    case complete(Value, consumed: Int)
}

/// The SOCKS5 side of the local proxy (RFC 1928): no authentication,
/// CONNECT only. Pure functions over the bytes received so far, so they are
/// tested without sockets.
enum SocksInbound {
    static let version: UInt8 = 0x05
    static let methodNoAuth: UInt8 = 0x00
    static let methodNoneAcceptable: UInt8 = 0xFF

    static let commandConnect: UInt8 = 0x01
    static let commandBind: UInt8 = 0x02
    static let commandUdpAssociate: UInt8 = 0x03

    static let addressIPv4: UInt8 = 0x01
    static let addressDomain: UInt8 = 0x03
    static let addressIPv6: UInt8 = 0x04

    static let replySuccess: UInt8 = 0x00
    static let replyNotAllowed: UInt8 = 0x02
    static let replyHostUnreachable: UInt8 = 0x04
    static let replyCommandNotSupported: UInt8 = 0x07

    struct Greeting: Equatable {
        var methods: [UInt8]
    }

    struct Request: Equatable {
        var command: UInt8
        var host: String
        var port: UInt16
    }

    /// VER, NMETHODS, METHODS.
    static func parseGreeting(_ data: Data) -> InboundParse<Greeting> {
        let bytes = [UInt8](data)
        guard let first = bytes.first else { return .incomplete }
        guard first == version else { return .invalid("not SOCKS5") }
        guard bytes.count >= 2 else { return .incomplete }
        let count = Int(bytes[1])
        guard bytes.count >= 2 + count else { return .incomplete }
        let methods = Array(bytes[2..<(2 + count)])
        return .complete(Greeting(methods: methods), consumed: 2 + count)
    }

    /// VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    static func parseRequest(_ data: Data) -> InboundParse<Request> {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else {
            if let first = bytes.first, first != version { return .invalid("not SOCKS5") }
            return .incomplete
        }
        guard bytes[0] == version else { return .invalid("not SOCKS5") }
        let command = bytes[1]
        let addressType = bytes[3]
        var offset = 4
        let host: String
        switch addressType {
        case addressIPv4:
            guard bytes.count >= offset + 4 + 2 else { return .incomplete }
            guard let text = RouterAddress.text(Array(bytes[offset..<(offset + 4)])) else {
                return .invalid("bad IPv4 address")
            }
            host = text
            offset += 4
        case addressDomain:
            guard bytes.count >= offset + 1 else { return .incomplete }
            let length = Int(bytes[offset])
            guard length > 0 else { return .invalid("empty domain name") }
            guard bytes.count >= offset + 1 + length + 2 else { return .incomplete }
            let name = Array(bytes[(offset + 1)..<(offset + 1 + length)])
            host = String(decoding: name, as: UTF8.self)
            offset += 1 + length
        case addressIPv6:
            guard bytes.count >= offset + 16 + 2 else { return .incomplete }
            guard let text = RouterAddress.text(Array(bytes[offset..<(offset + 16)])) else {
                return .invalid("bad IPv6 address")
            }
            host = text
            offset += 16
        default:
            return .invalid("address type \(addressType)")
        }
        let port = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
        offset += 2
        return .complete(Request(command: command, host: host, port: port), consumed: offset)
    }

    static let noAuthSelected = Data([version, methodNoAuth])
    static let noAcceptableMethods = Data([version, methodNoneAcceptable])

    /// A reply with the bound address left as 0.0.0.0:0, which every client
    /// accepts for CONNECT.
    static func reply(_ code: UInt8) -> Data {
        Data([version, code, 0x00, addressIPv4, 0, 0, 0, 0, 0, 0])
    }
}

/// The HTTP side of the local proxy: CONNECT, and plain requests in absolute
/// form (`GET http://host/path`) or origin form with a Host header, which
/// are rewritten to origin form and sent with `Connection: close`: the
/// upstream is not re-parsed for a second request, so each connection
/// carries one.
enum HTTPInbound {
    enum Request: Equatable {
        case connect(host: String, port: UInt16, version: String)
        /// `head` is the rewritten request head, ready to send.
        case forward(host: String, port: UInt16, head: Data)
    }

    static let headTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])

    /// Hop-by-hop headers the proxy consumes instead of passing on.
    private static let droppedHeaders: Set<String> = [
        "proxy-connection",
        "proxy-authorization",
        "connection",
        "keep-alive",
    ]

    /// Parses a request head (through the blank line); nil means 400.
    static func parse(head: Data) -> Request? {
        guard let text = String(data: head, encoding: .isoLatin1) else { return nil }
        let lines = text.components(separatedBy: "\r\n").filter { !$0.isEmpty }
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 3 else { return nil }
        let method = parts[0].uppercased()
        let target = parts[1]
        let version = parts[2]
        let headers = Array(lines.dropFirst())

        if method == "CONNECT" {
            guard let authority = splitHostPort(target, defaultPort: 443) else { return nil }
            return .connect(host: authority.host, port: authority.port, version: version)
        }

        var hostHeader: String?
        for header in headers where headerName(header) == "host" {
            hostHeader = headerValue(header)
            break
        }

        let host: String
        let port: UInt16
        let path: String
        if target.lowercased().hasPrefix("http://") {
            let rest = String(target.dropFirst(7))
            let authorityText: String
            if let slash = rest.firstIndex(of: "/") {
                authorityText = String(rest[..<slash])
                path = String(rest[slash...])
            } else if let query = rest.firstIndex(of: "?") {
                authorityText = String(rest[..<query])
                path = "/" + String(rest[query...])
            } else {
                authorityText = rest
                path = "/"
            }
            guard let authority = splitHostPort(authorityText, defaultPort: 80) else { return nil }
            host = authority.host
            port = authority.port
        } else if let hostHeader {
            guard let authority = splitHostPort(hostHeader, defaultPort: 80) else { return nil }
            host = authority.host
            port = authority.port
            path = target
        } else {
            return nil
        }

        var forwarded = method + " " + path + " " + version + "\r\n"
        var hasHost = false
        for header in headers {
            let name = headerName(header)
            if droppedHeaders.contains(name) { continue }
            if name == "host" { hasHost = true }
            forwarded += header + "\r\n"
        }
        if !hasHost {
            let shown = host.contains(":") ? "[" + host + "]" : host
            let authority = port == 80 ? shown : shown + ":" + String(port)
            forwarded += "Host: " + authority + "\r\n"
        }
        forwarded += "Connection: close\r\n\r\n"
        let bytes = forwarded.data(using: .isoLatin1) ?? Data(forwarded.utf8)
        return .forward(host: host, port: port, head: bytes)
    }

    /// "host", "host:port", "[v6]", "[v6]:port" or a bare IPv6 literal.
    /// Nil when the text is empty or the port is not a valid port.
    static func splitHostPort(_ authority: String, defaultPort: UInt16) -> (host: String, port: UInt16)? {
        let text = authority.trimmingCharacters(in: .whitespaces)
        if text.isEmpty { return nil }
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return nil }
            let host = String(text[text.index(after: text.startIndex)..<close])
            if host.isEmpty { return nil }
            var rest = String(text[text.index(after: close)...])
            if rest.hasPrefix(":") { rest.removeFirst() }
            if rest.isEmpty { return (host, defaultPort) }
            guard let port = parsePort(rest) else { return nil }
            return (host, port)
        }
        let colons = text.filter { $0 == ":" }.count
        if colons == 0 { return (text, defaultPort) }
        // More than one colon without brackets: an IPv6 literal, no port.
        if colons > 1 { return (text, defaultPort) }
        guard let colon = text.lastIndex(of: ":") else { return (text, defaultPort) }
        let host = String(text[..<colon])
        if host.isEmpty { return nil }
        guard let port = parsePort(String(text[text.index(after: colon)...])) else { return nil }
        return (host, port)
    }

    private static func parsePort(_ text: String) -> UInt16? {
        guard let value = Int(text), value > 0, value <= 65535 else { return nil }
        return UInt16(value)
    }

    private static func headerName(_ line: String) -> String {
        let name: Substring
        if let colon = line.firstIndex(of: ":") {
            name = line[..<colon]
        } else {
            name = Substring(line)
        }
        return name.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private static func headerValue(_ line: String) -> String {
        guard let colon = line.firstIndex(of: ":") else { return "" }
        return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    }

    static func connectEstablished(version: String) -> Data {
        let line = version + " 200 Connection established\r\n\r\n"
        return line.data(using: .isoLatin1) ?? Data(line.utf8)
    }

    static func errorResponse(_ code: Int, _ reason: String) -> Data {
        let text = "HTTP/1.1 \(code) \(reason)\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        return Data(text.utf8)
    }
}

/// What a dial that carries the client's first bytes waits for, so the
/// request and the client's opening bytes leave as one message.
///
/// Some servers read that first message as the client's TLS ClientHello and
/// close the connection when it is cut short. A browser's ClientHello with a
/// post-quantum key share is about 1.8 KB, two TCP segments, so dialling on
/// the first segment broke every HTTPS page through such a server.
enum InboundFirstData {
    /// How long each read for the first bytes waits. Nothing in that time
    /// means a server-speaks-first protocol, which is dialled without them.
    static let waitSeconds: Double = 0.1

    private static let tlsHandshake: UInt8 = 0x16
    private static let recordHeader = 5

    /// True once `data` is worth sending with the request: any bytes that
    /// are not a TLS handshake record, or a whole first TLS record.
    static func isComplete(_ data: Data) -> Bool {
        guard let first = data.first else { return false }
        if first != tlsHandshake { return true }
        if data.count < recordHeader { return false }
        let header = [UInt8](data.prefix(recordHeader))
        let length = (Int(header[3]) << 8) | Int(header[4])
        return data.count >= recordHeader + length
    }
}
