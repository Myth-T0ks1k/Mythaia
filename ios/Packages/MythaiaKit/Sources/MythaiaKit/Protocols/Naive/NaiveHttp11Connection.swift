import Foundation

/// An HTTP/1.1 CONNECT tunnel through a TLS proxy (the `http11` outbound,
/// NaiveProxy's HTTP/1.1 mode). HTTP/1.1 tunnels carry no NaiveProxy padding,
/// so once the proxy answers 200 the stream is the destination's.
enum NaiveHttp11Connection {
    static let userAgent = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

    /// The CONNECT request for `destination`, with Basic proxy credentials
    /// when both a username and a password are set.
    static func connectRequest(destination: Endpoint, username: String?, password: String?) -> Data {
        let target = destination.description
        var request = "CONNECT \(target) HTTP/1.1\r\n"
        request += "Host: \(target)\r\n"
        request += "Proxy-Connection: keep-alive\r\n"
        request += "User-Agent: \(userAgent)\r\n"
        if let auth = basicAuth(username: username, password: password) {
            request += "Proxy-Authorization: Basic \(auth)\r\n"
        }
        request += "\r\n"
        return Data(request.utf8)
    }

    /// Base64 `user:pass`, or nil without credentials.
    static func basicAuth(username: String?, password: String?) -> String? {
        guard let username = username, let password = password else { return nil }
        return Data("\(username):\(password)".utf8).base64EncodedString()
    }

    /// Sends the CONNECT over `stream` (already TLS) and reads the proxy's
    /// answer. Bytes the proxy sent right behind its 200 belong to the
    /// destination (a server-speaks-first banner) and are kept.
    static func openTunnel(over stream: ByteStream, destination: Endpoint, username: String?, password: String?) async throws -> ByteStream {
        try await stream.send(connectRequest(destination: destination, username: username, password: password))

        let reader = StreamReader(stream)
        let head: Data
        do {
            head = try await reader.readThrough(Data("\r\n\r\n".utf8), limit: 16 * 1024)
        } catch MythaiaError.closed {
            throw MythaiaError.connectFailed("the proxy closed the connection during CONNECT")
        }
        try checkResponse(head)
        return PrefixedStream(stream, prefix: reader.drain())
    }

    /// Throws unless `head` is a 200 response to CONNECT.
    static func checkResponse(_ head: Data) throws {
        // Split on bytes: in Swift "\r\n" is a single Character, so a
        // character-wise search for "\r" would never find the line end.
        let bytes = [UInt8](head)
        let lineEnd = bytes.firstIndex(where: { $0 == 0x0D || $0 == 0x0A }) ?? bytes.count
        let statusLine = String(decoding: bytes[0..<lineEnd], as: UTF8.self)
        let parts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        if parts.count < 2 {
            throw MythaiaError.protocolError("Malformed CONNECT status line")
        }
        if !parts[0].hasPrefix("HTTP/1.") {
            throw MythaiaError.protocolError("Invalid HTTP version in CONNECT response")
        }
        let status = String(parts[1])
        if status != "200" {
            Log.warning("CONNECT rejected: \(statusLine)")
            if status == "407" {
                throw MythaiaError.http(407, "Proxy authentication required")
            }
            throw MythaiaError.http(Int(status) ?? 0, "CONNECT failed with status \(status)")
        }
    }
}
