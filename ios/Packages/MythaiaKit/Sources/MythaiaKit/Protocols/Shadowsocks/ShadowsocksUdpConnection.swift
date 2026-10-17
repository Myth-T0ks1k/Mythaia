import Foundation

private let ssUdpMaxPaddingLength = 900
private let ssUdpMaxTimestampDifference: Int64 = 30
private let ssUdpHeaderTypeClient: UInt8 = 0
private let ssUdpHeaderTypeServer: UInt8 = 1

/// Shadowsocks UDP for one flow: every datagram to the destination is
/// encrypted on its own and sent to the server over a UDP socket, and every
/// reply is opened and stripped of its address.
///
/// Shadowsocks UDP rides real UDP, not the TCP stream: the protocol has no
/// UDP command for a stream, which is also why it goes straight to the server
/// even when the server sits behind a chain.
///
/// Replies are matched to the flow by port: the server usually answers from
/// the IP it resolved, not the name the flow asked for, so the host cannot be
/// compared, and a reply for any other port is dropped.
final class ShadowsocksUdpConnection: DatagramStream, @unchecked Sendable {
    enum Mode {
        /// Legacy SS: per-packet salt + AEAD(address ‖ payload); no session state.
        case legacy(cipher: ShadowsocksCipher, masterKey: Data)
        /// SS 2022, AES: an AES-ECB 16-byte packet header and a per-session AEAD
        /// body; multi-PSK through identity headers.
        case ss2022Aes(cipher: ShadowsocksCipher, pskList: [Data])
        /// SS 2022, ChaCha: XChaCha20-Poly1305 with a random 24-byte nonce; one PSK.
        case ss2022ChaCha(psk: Data)
    }

    /// The mode for a configured method and password.
    static func mode(method: String?, password: String?) throws -> Mode {
        guard let method = method else {
            throw MythaiaError.invalidConfiguration("Shadowsocks method not configured")
        }
        guard let password = password else {
            throw MythaiaError.invalidConfiguration("Shadowsocks password not configured")
        }
        guard let cipher = ShadowsocksCipher.fromMethod(method) else {
            throw ShadowsocksError.invalidMethod(method)
        }
        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password, keySize: cipher.keySize) else {
                throw ShadowsocksError.invalidPSK
            }
            if cipher.isChaCha {
                return .ss2022ChaCha(psk: pskList[pskList.count - 1])
            }
            return .ss2022Aes(cipher: cipher, pskList: pskList)
        }
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
        return .legacy(cipher: cipher, masterKey: masterKey)
    }

    private let socket: DatagramStream
    private let mode: Mode
    private let destinationHost: String
    private let destinationPort: UInt16

    private let sessionID: UInt64
    private let outboundCipherKey: Data?
    private let pskHashes: [Data]

    private let sendLock = NSLock()
    private var packetIDCounter: UInt64 = 0

    private let receiveLock = NSLock()
    private var remoteSessionID: UInt64 = 0
    private var remoteCipherKey: Data?

    init(socket: DatagramStream, mode: Mode, destinationHost: String, destinationPort: UInt16) {
        self.socket = socket
        self.mode = mode
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        let session = UInt64.random(in: UInt64.min...UInt64.max)
        self.sessionID = session
        switch mode {
        case .ss2022Aes(let cipher, let pskList):
            outboundCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(
                psk: pskList[pskList.count - 1],
                salt: ShadowsocksUdpConnection.bigEndian(session),
                keySize: cipher.keySize
            )
            var hashes = [Data]()
            if pskList.count >= 2 {
                for i in 1..<pskList.count {
                    hashes.append(ShadowsocksKeyDerivation.blake3Hash16(pskList[i]))
                }
            }
            pskHashes = hashes
        case .ss2022ChaCha, .legacy:
            outboundCipherKey = nil
            pskHashes = []
        }
    }

    func send(_ packet: Data) async throws {
        let encrypted = try encryptPacket(packet)
        try await socket.send(encrypted)
    }

    func receive() async throws -> Data? {
        while true {
            guard let datagram = try await socket.receive() else { return nil }
            do {
                let decoded = try decryptPacket(datagram)
                if decoded.port == destinationPort {
                    return decoded.payload
                }
                Log.debug("Shadowsocks UDP: reply from \(decoded.host):\(decoded.port) is not for this flow; dropped")
            } catch {
                // Corrupt or stale datagrams happen on the open Internet;
                // ending the flow on one bad packet would be fragile.
                Log.debug("Shadowsocks UDP: \(error.localizedDescription)")
            }
        }
    }

    func close() {
        socket.close()
    }

    // MARK: - Encryption

    private func nextPacketID() -> UInt64 {
        sendLock.lock()
        defer { sendLock.unlock() }
        packetIDCounter += 1
        return packetIDCounter
    }

    static func bigEndian(_ value: UInt64) -> Data {
        var out = [UInt8]()
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
        return Data(out)
    }

    private static func readBigEndian64(_ bytes: [UInt8], _ offset: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(bytes[offset + i])
        }
        return value
    }

    /// Padding for DNS queries, which are small and easy to fingerprint by size.
    private func paddingLength(for payload: Data) -> Int {
        if destinationPort == 53 && payload.count < ssUdpMaxPaddingLength {
            return CryptoRandom.int(below: ssUdpMaxPaddingLength - payload.count) + 1
        }
        return 0
    }

    /// `type(1) + timestamp(8) + paddingLength(2) + padding + address + payload`.
    private func clientBody(_ payload: Data) -> [UInt8] {
        let padding = paddingLength(for: payload)
        var body = [UInt8]()
        body.append(ssUdpHeaderTypeClient)
        let now = UInt64(max(0, Int64(Date().timeIntervalSince1970)))
        body.append(contentsOf: ShadowsocksUdpConnection.bigEndian(now))
        body.append(UInt8(truncatingIfNeeded: padding >> 8))
        body.append(UInt8(truncatingIfNeeded: padding))
        if padding > 0 {
            body.append(contentsOf: [UInt8](repeating: 0, count: padding))
        }
        body.append(contentsOf: ShadowsocksProtocol.buildAddressHeader(host: destinationHost, port: destinationPort))
        body.append(contentsOf: payload)
        return body
    }

    func encryptPacket(_ payload: Data) throws -> Data {
        switch mode {
        case .legacy(let cipher, let masterKey):
            let packet = ShadowsocksProtocol.encodeUDPPacket(host: destinationHost, port: destinationPort, payload: payload)
            return try ShadowsocksUDPCrypto.encrypt(cipher, masterKey: masterKey, payload: packet)

        case .ss2022Aes(let cipher, let pskList):
            guard let sessionKey = outboundCipherKey else { throw ShadowsocksError.decryptionFailed }
            // 16-byte packet header: sessionID(8) + packetID(8), big-endian.
            var header = ShadowsocksUdpConnection.bigEndian(sessionID)
            header.append(ShadowsocksUdpConnection.bigEndian(nextPacketID()))
            let headerBytes = [UInt8](header)

            var identityData = Data()
            if pskList.count >= 2 {
                for i in 0..<(pskList.count - 1) {
                    let hash = [UInt8](pskHashes[i])
                    var xored = [UInt8](repeating: 0, count: 16)
                    for j in 0..<16 {
                        xored[j] = hash[j] ^ headerBytes[j]
                    }
                    identityData.append(try AesEcb.encrypt(key: pskList[i], block: Data(xored)))
                }
            }

            // The AEAD nonce is the last 12 bytes of the 16-byte header.
            let nonce = Data(headerBytes[4..<16])
            let sealedBody = try ShadowsocksAEADCrypto.seal(cipher, key: sessionKey, nonce: nonce, plaintext: Data(clientBody(payload)))

            // The header is AES-ECB encrypted with pskList[0]: the iPSK in
            // multi-PSK setups, the user PSK when there is only one.
            var out = try AesEcb.encrypt(key: pskList[0], block: header)
            out.append(identityData)
            out.append(sealedBody)
            return out

        case .ss2022ChaCha(let psk):
            let nonce = CryptoRandom.bytes(24)
            var body = [UInt8](ShadowsocksUdpConnection.bigEndian(sessionID))
            body.append(contentsOf: ShadowsocksUdpConnection.bigEndian(nextPacketID()))
            body.append(contentsOf: clientBody(payload))
            var out = nonce
            out.append(try XChaCha20Poly1305.seal(key: psk, nonce: nonce, plaintext: Data(body)))
            return out
        }
    }

    func decryptPacket(_ datagram: Data) throws -> ShadowsocksProtocol.UdpPacket {
        let data = [UInt8](datagram)
        switch mode {
        case .legacy(let cipher, let masterKey):
            let decrypted = try ShadowsocksUDPCrypto.decrypt(cipher, masterKey: masterKey, data: datagram)
            guard let parsed = ShadowsocksProtocol.decodeUDPPacket(decrypted) else {
                throw ShadowsocksError.invalidAddress
            }
            return parsed

        case .ss2022Aes(let cipher, let pskList):
            if data.count < 16 + 16 { throw ShadowsocksError.decryptionFailed }
            // The header is decrypted with the user PSK, the last one.
            let userPsk = pskList[pskList.count - 1]
            let header = [UInt8](try AesEcb.decrypt(key: userPsk, block: Data(data[0..<16])))
            let serverSession = ShadowsocksUdpConnection.readBigEndian64(header, 0)
            let cipherKey = remoteKey(serverSession, psk: userPsk, keySize: cipher.keySize)
            let nonce = Data(header[4..<16])
            let body = try ShadowsocksAEADCrypto.open(cipher, key: cipherKey, nonce: nonce, ciphertext: Data(data[16...]))
            return try parseServerBody([UInt8](body))

        case .ss2022ChaCha(let psk):
            if data.count < 24 + 16 { throw ShadowsocksError.decryptionFailed }
            let nonce = Data(data[0..<24])
            let body = [UInt8](try XChaCha20Poly1305.open(key: psk, nonce: nonce, ciphertext: Data(data[24...])))
            // sessionID(8) + packetID(8) + the standard server body. The
            // server's packet window is not checked: the AEAD tag and the
            // timestamp already gate acceptance.
            if body.count < 16 { throw ShadowsocksError.decryptionFailed }
            return try parseServerBody(Array(body[16...]))
        }
    }

    /// The inbound key for the server's session, derived again only when the
    /// server rotates its session.
    private func remoteKey(_ serverSession: UInt64, psk: Data, keySize: Int) -> Data {
        receiveLock.lock()
        defer { receiveLock.unlock() }
        if serverSession == remoteSessionID, let cached = remoteCipherKey {
            return cached
        }
        let key = ShadowsocksKeyDerivation.deriveSessionKey(
            psk: psk,
            salt: ShadowsocksUdpConnection.bigEndian(serverSession),
            keySize: keySize
        )
        remoteSessionID = serverSession
        remoteCipherKey = key
        return key
    }

    /// `type(1) + timestamp(8) + clientSessionID(8) + paddingLength(2) + padding + address + payload`.
    private func parseServerBody(_ body: [UInt8]) throws -> ShadowsocksProtocol.UdpPacket {
        if body.count < 1 + 8 + 8 + 2 { throw ShadowsocksError.decryptionFailed }
        var offset = 0
        if body[offset] != ssUdpHeaderTypeServer { throw ShadowsocksError.badHeaderType }
        offset += 1

        let epoch = Int64(bitPattern: ShadowsocksUdpConnection.readBigEndian64(body, offset))
        offset += 8
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > ssUdpMaxTimestampDifference { throw ShadowsocksError.badTimestamp }

        let clientSession = ShadowsocksUdpConnection.readBigEndian64(body, offset)
        offset += 8
        if clientSession != sessionID { throw ShadowsocksError.decryptionFailed }

        if body.count - offset < 2 { throw ShadowsocksError.decryptionFailed }
        let padding = (Int(body[offset]) << 8) | Int(body[offset + 1])
        offset += 2 + padding
        if offset > body.count { throw ShadowsocksError.decryptionFailed }

        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(Data(body[offset...])) else {
            throw ShadowsocksError.invalidAddress
        }
        return parsed
    }
}
