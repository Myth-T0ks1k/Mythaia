import Foundation

/// The SOCKS5 client handshake (RFC 1928, with RFC 1929 username/password):
/// greeting, optional authentication, then CONNECT or UDP ASSOCIATE.
enum SocksClient {
    static let version: UInt8 = 0x05
    static let authNone: UInt8 = 0x00
    static let authPassword: UInt8 = 0x02
    static let authNoMatch: UInt8 = 0xFF
    static let commandConnect: UInt8 = 0x01
    static let commandUdpAssociate: UInt8 = 0x03
    static let addressIPv4: UInt8 = 0x01
    static let addressDomain: UInt8 = 0x03
    static let addressIPv6: UInt8 = 0x04
    static let statusSuccess: UInt8 = 0x00

    /// The address a reply names (`BND.ADDR`, `BND.PORT`).
    struct BoundAddress: Equatable {
        let host: String
        let port: UInt16
    }

    /// Performs a TCP CONNECT over `stream`. On success the returned stream
    /// carries the tunnelled bytes, starting with any the server sent right
    /// behind its reply.
    static func connect(over stream: ByteStream, to target: Endpoint, username: String?, password: String?) async throws -> ByteStream {
        let reader = StreamReader(stream)
        do {
            try await performAuth(stream, reader, username: username, password: password)
            _ = try await sendCommand(stream, reader, command: commandConnect, host: target.host, port: target.port)
        } catch MythaiaError.closed {
            throw MythaiaError.protocolError("SOCKS5 server closed during handshake")
        }
        return PrefixedStream(stream, prefix: reader.drain())
    }

    /// Performs a UDP ASSOCIATE over `stream`. RFC 1928 has the client send
    /// 0.0.0.0:0; the reply names the relay endpoint for the datagrams.
    static func udpAssociate(over stream: ByteStream, username: String?, password: String?) async throws -> BoundAddress {
        let reader = StreamReader(stream)
        do {
            try await performAuth(stream, reader, username: username, password: password)
            return try await sendCommand(stream, reader, command: commandUdpAssociate, host: "0.0.0.0", port: 0)
        } catch MythaiaError.closed {
            throw MythaiaError.protocolError("SOCKS5 server closed during handshake")
        }
    }

    private static func performAuth(_ stream: ByteStream, _ reader: StreamReader, username: String?, password: String?) async throws {
        let hasAuth = username != nil && password != nil
        let method = hasAuth ? authPassword : authNone
        try await stream.send(Data([version, 0x01, method]))

        let response = [UInt8](try await reader.readExactly(2))
        if response[0] != version {
            throw MythaiaError.protocolError("SOCKS5 unexpected server version: \(response[0])")
        }
        if response[1] != method {
            if response[1] == authNoMatch {
                throw MythaiaError.protocolError("SOCKS5 server: no matching auth method")
            }
            throw MythaiaError.protocolError("SOCKS5 auth method mismatch: expected \(method), got \(response[1])")
        }

        if hasAuth, let username = username, let password = password {
            try await sendAuth(stream, reader, username: username, password: password)
        }
    }

    /// RFC 1929 username/password sub-negotiation.
    private static func sendAuth(_ stream: ByteStream, _ reader: StreamReader, username: String, password: String) async throws {
        let user = Array(username.utf8.prefix(255))
        let pass = Array(password.utf8.prefix(255))
        var request: [UInt8] = [0x01, UInt8(user.count)]
        request.append(contentsOf: user)
        request.append(UInt8(pass.count))
        request.append(contentsOf: pass)
        try await stream.send(Data(request))

        let response = [UInt8](try await reader.readExactly(2))
        if response[1] != 0x00 {
            throw MythaiaError.protocolError("SOCKS5 authentication failed (status \(response[1]))")
        }
    }

    private static func sendCommand(_ stream: ByteStream, _ reader: StreamReader, command: UInt8, host: String, port: UInt16) async throws -> BoundAddress {
        var request: [UInt8] = [version, command, 0x00]
        request.append(contentsOf: encodeAddress(host))
        request.append(contentsOf: ProtocolAddress.portBytes(port))
        try await stream.send(Data(request))
        return try await readCommandResponse(reader)
    }

    /// Reads `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
    private static func readCommandResponse(_ reader: StreamReader) async throws -> BoundAddress {
        let head = [UInt8](try await reader.readExactly(4))
        if head[1] != statusSuccess {
            throw MythaiaError.protocolError("SOCKS5 command failed (reply \(head[1]))")
        }
        switch head[3] {
        case addressIPv4:
            let a = [UInt8](try await reader.readExactly(4 + 2))
            let port = (UInt16(a[4]) << 8) | UInt16(a[5])
            return BoundAddress(host: ProtocolAddress.ipv4Text(Array(a[0..<4])), port: port)
        case addressIPv6:
            let a = [UInt8](try await reader.readExactly(16 + 2))
            let port = (UInt16(a[16]) << 8) | UInt16(a[17])
            return BoundAddress(host: ProtocolAddress.ipv6Text(Array(a[0..<16])), port: port)
        case addressDomain:
            let length = Int([UInt8](try await reader.readExactly(1))[0])
            let a = [UInt8](try await reader.readExactly(length + 2))
            let name = String(decoding: a[0..<length], as: UTF8.self)
            let port = (UInt16(a[length]) << 8) | UInt16(a[length + 1])
            return BoundAddress(host: name, port: port)
        default:
            throw MythaiaError.protocolError("SOCKS5 unknown address type: \(head[3])")
        }
    }

    /// A host as a SOCKS5 address: `[ATYP, ADDR...]`.
    static func encodeAddress(_ host: String) -> [UInt8] {
        return ProtocolAddress.socksAddress(host)
    }

    /// The SOCKS5 UDP request header: `RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT`.
    static func udpHeader(host: String, port: UInt16) -> [UInt8] {
        var out: [UInt8] = [0x00, 0x00, 0x00]
        out.append(contentsOf: encodeAddress(host))
        out.append(contentsOf: ProtocolAddress.portBytes(port))
        return out
    }

    /// The payload of a relayed datagram, or nil for a fragment, a malformed
    /// header or an empty payload.
    static func stripUdpHeader(_ data: [UInt8]) -> [UInt8]? {
        if data.count < 4 { return nil }
        if data[2] != 0x00 { return nil } // fragments are not supported

        let headerEnd: Int
        switch data[3] {
        case addressIPv4:
            headerEnd = 4 + 4 + 2
        case addressIPv6:
            headerEnd = 4 + 16 + 2
        case addressDomain:
            if data.count < 5 { return nil }
            headerEnd = 4 + 1 + Int(data[4]) + 2
        default:
            return nil
        }
        if data.count <= headerEnd { return nil }
        return Array(data[headerEnd...])
    }
}

/// SOCKS5 UDP ASSOCIATE: datagrams to the relay endpoint carry the SOCKS5
/// UDP header, replies have it stripped. The TCP control connection stays
/// open for the life of the association, as RFC 1928 requires: the server
/// ends the association when it closes.
final class SocksUdpConnection: DatagramStream, @unchecked Sendable {
    private let control: ByteStream
    private let socket: DatagramStream
    private let header: [UInt8]

    init(control: ByteStream, socket: DatagramStream, destinationHost: String, destinationPort: UInt16) {
        self.control = control
        self.socket = socket
        self.header = SocksClient.udpHeader(host: destinationHost, port: destinationPort)
    }

    func send(_ packet: Data) async throws {
        var out = header
        out.append(contentsOf: packet)
        try await socket.send(Data(out))
    }

    func receive() async throws -> Data? {
        while true {
            guard let datagram = try await socket.receive() else { return nil }
            if let payload = SocksClient.stripUdpHeader([UInt8](datagram)) {
                return Data(payload)
            }
        }
    }

    func close() {
        socket.close()
        control.close()
    }
}
