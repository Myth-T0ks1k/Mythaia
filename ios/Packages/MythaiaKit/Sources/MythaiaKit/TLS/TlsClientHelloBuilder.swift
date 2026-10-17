import CryptoKit
import Foundation

/// TLS ClientHello builder with browser-specific fingerprint emulation.
///
/// Each fingerprint produces a ClientHello matching the corresponding
/// browser's real TLS implementation (cipher suites, extensions, ordering) as
/// defined by uTLS v1.8.2. Everything that looks random in a browser's hello
/// (GREASE values, Chrome's extension order, the GREASE ECH payload) is
/// derived from the hello's own random, so a given random always yields the
/// same bytes; REALITY depends on that, building the hello twice.
///
/// Not carried over: real ECH (only the GREASE stub the browsers send) and
/// the X25519MLKEM768 share, which needs ML-KEM that CryptoKit only has from
/// iOS 26 on.
enum TlsClientHelloBuilder {

    // -- GREASE --

    private static let greaseTable: [Int] = [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]

    /// A GREASE value deterministically selected by `seed`.
    private static func grease(_ seed: UInt8) -> Int {
        return greaseTable[Int(seed) % greaseTable.count]
    }

    static func isGREASE(_ value: Int) -> Bool {
        return (value & 0x0F0F) == 0x0A0A
    }

    /// GREASE ext2 must differ from ext1, or the hello carries one extension
    /// type twice and servers reject it.
    private static func secondGrease(_ random: [UInt8], first: Int) -> Int {
        let candidate = grease(random[29])
        if candidate != first { return candidate }
        return grease(random[29] &+ 1)
    }

    // -- Deterministic pseudo-random derivation --

    /// Pseudo-random bytes from the connection random and a label, for the
    /// GREASE ECH stub.
    private static func derivePRBytes(_ random: [UInt8], label: String, length: Int) -> [UInt8] {
        var result: [UInt8] = []
        var counter: UInt8 = 0
        while result.count < length {
            var input = random
            input.append(contentsOf: Array(label.utf8))
            input.append(counter)
            let hash = Array(SHA256.hash(data: input))
            let wanted = min(hash.count, length - result.count)
            result.append(contentsOf: hash[0..<wanted])
            counter = counter &+ 1
        }
        return result
    }

    // -- Generic extension helpers --

    private static func ext(_ type: Int, _ payload: [UInt8] = []) -> [UInt8] {
        var writer = TLSByteWriter()
        writer.u16(type)
        writer.u16(payload.count)
        writer.append(payload)
        return writer.bytes
    }

    private static func u16List(_ values: [Int]) -> [UInt8] {
        var writer = TLSByteWriter()
        writer.u16(values.count * 2)
        for value in values { writer.u16(value) }
        return writer.bytes
    }

    private static func protocolNameList(_ protocols: [String]) -> [UInt8] {
        var list = TLSByteWriter()
        for name in protocols {
            let bytes = Array(name.utf8)
            list.u8(bytes.count)
            list.append(bytes)
        }
        var payload = TLSByteWriter()
        payload.u16(list.bytes.count)
        payload.append(list.bytes)
        return payload.bytes
    }

    // -- Individual extension builders --

    /// 0x0000 -- Server Name Indication.
    ///
    /// RFC 6066 §3: no SNI for an IP literal (browsers send none), and a name
    /// goes out as its A-label, the form the server matches against.
    static func buildSNIExtension(_ serverName: String) -> [UInt8] {
        if serverName.isEmpty || TLSHostName.isIpLiteral(serverName) { return [] }
        let nameBytes = Array(TLSHostName.asciiName(serverName).utf8)
        var payload = TLSByteWriter()
        payload.u16(nameBytes.count + 3)
        payload.u8(0x00) // host_name
        payload.u16(nameBytes.count)
        payload.append(nameBytes)
        return ext(0x0000, payload.bytes)
    }

    /// 0x0005 -- OCSP status request.
    private static func statusRequestExt() -> [UInt8] {
        return ext(0x0005, [0x01, 0x00, 0x00, 0x00, 0x00])
    }

    /// 0x000A -- Supported groups.
    private static func supportedGroupsExt(_ groups: [Int]) -> [UInt8] {
        return ext(0x000A, u16List(groups))
    }

    /// 0x000B -- EC point formats (uncompressed only).
    private static func ecPointFormatsExt() -> [UInt8] {
        return ext(0x000B, [0x01, 0x00])
    }

    /// 0x000D -- Signature algorithms.
    private static func signatureAlgorithmsExt(_ algorithms: [Int]) -> [UInt8] {
        return ext(0x000D, u16List(algorithms))
    }

    /// 0x0010 -- ALPN.
    private static func alpnExt(_ protocols: [String]) -> [UInt8] {
        return ext(0x0010, protocolNameList(protocols))
    }

    /// 0x0012 -- Signed certificate timestamp (empty, requesting SCTs).
    private static func sctExt() -> [UInt8] {
        return ext(0x0012)
    }

    /// 0x0015 -- Padding.
    private static func paddingExt(_ length: Int) -> [UInt8] {
        return ext(0x0015, [UInt8](repeating: 0, count: max(0, length)))
    }

    /// 0x0017 -- Extended master secret.
    private static func extendedMasterSecretExt() -> [UInt8] {
        return ext(0x0017)
    }

    /// 0x001B -- Compress certificate (RFC 8879).
    private static func compressCertExt(_ algorithms: [Int]) -> [UInt8] {
        var payload = TLSByteWriter()
        payload.u8(algorithms.count * 2)
        for algorithm in algorithms { payload.u16(algorithm) }
        return ext(0x001B, payload.bytes)
    }

    /// 0x001C -- Record size limit.
    private static func recordSizeLimitExt(_ limit: Int) -> [UInt8] {
        return ext(0x001C, TLSWire.u16Bytes(limit))
    }

    /// 0x0022 -- Delegated credentials (Firefox).
    private static func delegatedCredentialsExt(_ algorithms: [Int]) -> [UInt8] {
        return ext(0x0022, u16List(algorithms))
    }

    /// 0x0023 -- Session ticket.
    private static func sessionTicketExt() -> [UInt8] {
        return ext(0x0023)
    }

    /// 0x002B -- Supported versions.
    private static func supportedVersionsExt(_ versions: [Int]) -> [UInt8] {
        var payload = TLSByteWriter()
        payload.u8(versions.count * 2)
        for version in versions { payload.u16(version) }
        return ext(0x002B, payload.bytes)
    }

    /// 0x002D -- PSK key exchange modes: psk_dhe_ke only.
    private static func pskKeyExchangeModesExt() -> [UInt8] {
        return ext(0x002D, [0x01, 0x01])
    }

    /// 0x0033 -- Key share.
    private static func keyShareExt(_ entries: [(group: Int, key: [UInt8])]) -> [UInt8] {
        var list = TLSByteWriter()
        for entry in entries {
            list.u16(entry.group)
            list.u16(entry.key.count)
            list.append(entry.key)
        }
        var payload = TLSByteWriter()
        payload.u16(list.bytes.count)
        payload.append(list.bytes)
        return ext(0x0033, payload.bytes)
    }

    /// 0x4469 -- Application settings (ALPS, legacy codepoint).
    private static func applicationSettingsExt(_ protocols: [String]) -> [UInt8] {
        return ext(0x4469, protocolNameList(protocols))
    }

    /// 0x44CD -- Application settings (ALPS, new codepoint for Chrome 133+).
    private static func applicationSettingsNewExt(_ protocols: [String]) -> [UInt8] {
        return ext(0x44CD, protocolNameList(protocols))
    }

    /// 0xFE0D -- GREASE Encrypted Client Hello:
    /// type(1) + kdf(2) + aead(2) + configId(1) + encLen(2) + enc + payloadLen(2) + payload.
    private static func greaseECHExt(_ random: [UInt8], kdfId: Int, aeadId: Int, payloadLen: Int) -> [UInt8] {
        let enc = derivePRBytes(random, label: "ech-enc", length: 32)
        let payload = derivePRBytes(random, label: "ech-payload", length: payloadLen)
        let configId = derivePRBytes(random, label: "ech-config", length: 1)[0]

        var data = TLSByteWriter()
        data.u8(0x00) // outer ClientHello
        data.u16(kdfId)
        data.u16(aeadId)
        data.u8(Int(configId))
        data.u16(enc.count)
        data.append(enc)
        data.u16(payload.count)
        data.append(payload)
        return ext(0xFE0D, data.bytes)
    }

    /// 0x3374 -- Next Protocol Negotiation (legacy, 360 Browser).
    private static func npnExt() -> [UInt8] {
        return ext(0x3374)
    }

    /// 0x754F -- Channel ID, old codepoint (360 Browser).
    private static func fakeChannelIDOldExt() -> [UInt8] {
        return ext(0x754F)
    }

    /// 0xFF01 -- Renegotiation info (empty, initial handshake).
    private static func renegotiationInfoExt() -> [UInt8] {
        return ext(0xFF01, [0x00])
    }

    /// A GREASE extension: GREASE type, no data.
    private static func greaseExt(_ value: Int) -> [UInt8] {
        return ext(value)
    }

    /// The X25519MLKEM768 share for group 0x11EC:
    /// `mlkemEncapsulationKey(1184) || x25519PublicKey(32)`.
    private static func mlkem768HybridKeyShare(_ encapsulationKey: [UInt8], _ x25519PublicKey: [UInt8]) -> [UInt8] {
        return encapsulationKey + x25519PublicKey
    }

    private static func cipherSuitesData(_ suites: [Int]) -> [UInt8] {
        var writer = TLSByteWriter()
        for suite in suites { writer.u16(suite) }
        return writer.bytes
    }

    // -- BoringSSL padding --

    /// BoringSSL pads a ClientHello of 256-511 bytes to exactly 512. Returns
    /// the padding data length (without the 4-byte extension header), or nil
    /// when no padding applies or there is no room for the header.
    private static func boringPaddingDataLength(_ clientHelloLength: Int) -> Int? {
        if clientHelloLength <= 0xFF || clientHelloLength >= 0x200 { return nil }
        let needed = 0x200 - clientHelloLength
        return needed >= 4 ? needed - 4 : nil
    }

    // -- Chrome extension shuffling --

    /// Chrome 106+ shuffles its extensions. GREASE extensions and padding keep
    /// their positions; the order is a deterministic function of random[24..<32].
    private static func shuffleChromeExtensions(_ exts: inout [[UInt8]], random: [UInt8]) {
        var fixed = Set<Int>()
        for index in 0..<exts.count {
            if exts[index].count < 2 { continue }
            let type = TLSWire.u16(exts[index], 0)
            if isGREASE(type) || type == 0x0015 {
                fixed.insert(index)
            }
        }
        let shuffleable = (0..<exts.count).filter { !fixed.contains($0) }
        if shuffleable.count <= 1 { return }

        var seed: UInt64 = 0
        if random.count >= 32 {
            for index in 0..<8 {
                let byte = UInt64(random[24 + index])
                seed |= byte << UInt64(index * 8)
            }
        }

        // Fisher-Yates over the shuffleable positions, driven by a 64-bit LCG
        // (Knuth's MMIX constants); the Android build uses the same one, so a
        // random gives the same order on both.
        var position = shuffleable.count - 1
        while position >= 1 {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            let bound = UInt64(position + 1)
            let other = Int((seed >> 33) % bound)
            if position != other {
                exts.swapAt(shuffleable[position], shuffleable[other])
            }
            position -= 1
        }
    }

    // -- Public API --

    /// `random` resolved to a concrete profile, chosen by random[0] from the
    /// pool that leaves out the three legacy profiles.
    static func resolveFingerprint(_ fingerprint: TlsFingerprint, random: [UInt8]) -> TlsFingerprint {
        if fingerprint != .random { return fingerprint }
        let options = TlsFingerprint.concreteFingerprints
        if options.isEmpty { return .chrome133 }
        return options[Int(random[0]) % options.count]
    }

    /// Builds a ClientHello handshake message (no record header).
    ///
    /// - Parameters:
    ///   - random: 32-byte TLS random; also seeds GREASE and the shuffle.
    ///   - sessionId: the legacy session id (32 bytes; REALITY's carries its auth).
    ///   - publicKey: the X25519 key_share.
    ///   - alpn: nil for the browser default, h2 then http/1.1.
    ///   - omitPQKeyShares: never offer X25519MLKEM768.
    ///   - mlkemEncapsulationKey: 1184-byte ML-KEM-768 key; with it, profiles
    ///     that offer the hybrid share do. Nil sends no PQ share.
    ///   - p256PublicKey: the uncompressed P-256 share the Firefox profiles
    ///     send next to X25519. Pass the real key so a server that picks P-256
    ///     can be answered; nil puts a throwaway key there.
    static func buildRawClientHello(
        fingerprint: TlsFingerprint,
        random: [UInt8],
        sessionId: [UInt8],
        serverName: String,
        publicKey: [UInt8],
        alpn: [String]? = nil,
        omitPQKeyShares: Bool = false,
        mlkemEncapsulationKey: [UInt8]? = nil,
        p256PublicKey: [UInt8]? = nil
    ) -> [UInt8] {
        let resolved = resolveFingerprint(fingerprint, random: random)
        let mlkem = omitPQKeyShares ? nil : mlkemEncapsulationKey
        let p256 = p256PublicKey ?? Array(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let parts = buildFingerprintedParts(
            resolved,
            random: random,
            serverName: serverName,
            publicKey: publicKey,
            alpn: alpn,
            mlkem: mlkem,
            p256: p256
        )
        return assembleClientHello(
            random: random,
            sessionId: sessionId,
            cipherSuites: parts.cipherSuites,
            extensions: parts.extensions,
            applyBoringPadding: parts.needsPadding
        )
    }

    /// The hello in a TLS record. The record version is TLS 1.0, as browsers
    /// send it, for old middleboxes.
    static func wrapInTLSRecord(_ clientHello: [UInt8]) -> [UInt8] {
        var record: [UInt8] = [0x16, 0x03, 0x01]
        record.append(contentsOf: TLSWire.u16Bytes(clientHello.count))
        record.append(contentsOf: clientHello)
        return record
    }

    private static func assembleClientHello(
        random: [UInt8],
        sessionId: [UInt8],
        cipherSuites: [UInt8],
        extensions: [UInt8],
        applyBoringPadding: Bool
    ) -> [UInt8] {
        var hello = TLSByteWriter()
        hello.u8(0x01)        // ClientHello
        hello.u24(0)          // length, filled in below
        hello.u16(0x0303)     // legacy_version: TLS 1.2
        hello.append(random)
        hello.u8(sessionId.count)
        hello.append(sessionId)
        hello.u16(cipherSuites.count)
        hello.append(cipherSuites)
        hello.u8(0x01)        // one compression method
        hello.u8(0x00)        // null

        var exts = extensions
        if applyBoringPadding {
            let unpaddedLength = hello.bytes.count + 2 + exts.count
            if let padLength = boringPaddingDataLength(unpaddedLength) {
                exts.append(contentsOf: paddingExt(padLength))
            }
        }
        hello.u16(exts.count)
        hello.append(exts)

        var bytes = hello.bytes
        let length = bytes.count - 4
        bytes[1] = UInt8(truncatingIfNeeded: length >> 16)
        bytes[2] = UInt8(truncatingIfNeeded: length >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: length)
        return bytes
    }

    // -- Per-browser fingerprint dispatch --

    private struct FingerprintParts {
        let cipherSuites: [UInt8]
        let extensions: [UInt8]
        let needsPadding: Bool
    }

    private static func buildFingerprintedParts(
        _ fingerprint: TlsFingerprint,
        random: [UInt8],
        serverName: String,
        publicKey: [UInt8],
        alpn: [String]?,
        mlkem: [UInt8]?,
        p256: [UInt8]
    ) -> FingerprintParts {
        switch fingerprint {
        case .chrome133:
            return buildChrome133(random, serverName, publicKey, alpn, mlkem)
        case .firefox148:
            return buildFirefox148(random, serverName, publicKey, alpn, mlkem, p256)
        case .safari26:
            return buildSafari26(random, serverName, publicKey, alpn, mlkem)
        case .edge85:
            return buildEdge85(random, serverName, publicKey, alpn)
        case .android11:
            return buildAndroid11(random, serverName, publicKey, alpn)
        case .qq11:
            return buildQQ11(random, serverName, publicKey, alpn)
        case .browser360:
            return buildBrowser360(random, serverName, publicKey, alpn)
        case .chrome120:
            return buildChrome120(random, serverName, publicKey, alpn)
        case .firefox120:
            return buildFirefox120(random, serverName, publicKey, alpn, p256)
        case .safari16:
            return buildSafari16(random, serverName, publicKey, alpn)
        case .ios14:
            return buildIOS14(random, serverName, publicKey, alpn)
        case .edge106:
            return buildEdge106(random, serverName, publicKey, alpn)
        case .random:
            // Resolved by the caller; Chrome is the safe answer if it is not.
            return buildChrome133(random, serverName, publicKey, alpn, mlkem)
        }
    }

    private static let chromeCipherSuites: [Int] = [
        0x1301, 0x1302, 0x1303,             // TLS 1.3
        0xC02B, 0xC02F, 0xC02C, 0xC030,     // ECDHE AES-GCM
        0xCCA9, 0xCCA8,                     // ECDHE ChaCha20
        0xC013, 0xC014,                     // ECDHE AES-CBC
        0x009C, 0x009D,                     // RSA AES-GCM
        0x002F, 0x0035,                     // RSA AES-CBC
    ]

    private static let chromeSignatureAlgorithms: [Int] = [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601,
    ]

    private static let firefoxCipherSuites: [Int] = [
        0x1301, 0x1303, 0x1302,             // TLS 1.3 (ChaCha20 before AES-256)
        0xC02B, 0xC02F,                     // ECDHE AES-128-GCM
        0xCCA9, 0xCCA8,                     // ECDHE ChaCha20
        0xC02C, 0xC030,                     // ECDHE AES-256-GCM
        0xC00A, 0xC009,                     // ECDHE ECDSA CBC
        0xC013, 0xC014,                     // ECDHE RSA CBC
        0x009C, 0x009D,                     // RSA AES-GCM
        0x002F, 0x0035,                     // RSA AES-CBC
    ]

    private static let firefoxSignatureAlgorithms: [Int] = [
        0x0403, 0x0503, 0x0603,             // ECDSA P256/P384/P521
        0x0804, 0x0805, 0x0806,             // PSS SHA256/384/512
        0x0401, 0x0501, 0x0601,             // PKCS1 SHA256/384/512
        0x0203, 0x0201,                     // ECDSA-SHA1, PKCS1-SHA1
    ]

    private static let defaultALPN = ["h2", "http/1.1"]

    // -- Chrome 133 --

    private static func buildChrome133(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?, _ mlkem: [UInt8]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suites = cipherSuitesData([gCipher] + chromeCipherSuites)
        let protocols = alpn ?? defaultALPN

        let echPayloadLens = [144, 176, 208, 240]
        let echPayloadLen = echPayloadLens[Int(random[30]) % echPayloadLens.count]

        // The hybrid share only goes out with a real ML-KEM key behind it;
        // a forged one would fail key agreement with a server that picks it.
        let groups: [Int]
        let keyShares: [(group: Int, key: [UInt8])]
        if let mlkem = mlkem {
            groups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018]
            keyShares = [(gGroup, [0x00]), (0x11EC, mlkem768HybridKeyShare(mlkem, publicKey)), (0x001D, publicKey)]
        } else {
            groups = [gGroup, 0x001D, 0x0017, 0x0018]
            keyShares = [(gGroup, [0x00]), (0x001D, publicKey)]
        }

        var exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(groups),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms),
            sctExt(),
            keyShareExt(keyShares),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                 // Brotli
            applicationSettingsNewExt(["h2"]),         // ALPS 0x44CD
            greaseECHExt(random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen),
            greaseExt(gExt2),
        ]
        shuffleChromeExtensions(&exts, random: random)
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Firefox 148 --

    private static func buildFirefox148(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?,
        _ mlkem: [UInt8]?, _ p256: [UInt8]
    ) -> FingerprintParts {
        let suites = cipherSuitesData(firefoxCipherSuites)
        let protocols = alpn ?? defaultALPN
        let echAead = Int(random[30]) % 2 == 0 ? 0x0001 : 0x0003

        let groups: [Int]
        let keyShares: [(group: Int, key: [UInt8])]
        if let mlkem = mlkem {
            groups = [0x11EC, 0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            keyShares = [(0x11EC, mlkem768HybridKeyShare(mlkem, publicKey)), (0x001D, publicKey), (0x0017, p256)]
        } else {
            groups = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            keyShares = [(0x001D, publicKey), (0x0017, p256)]
        }

        let exts: [[UInt8]] = [
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(groups),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt([0x0403, 0x0503, 0x0603, 0x0203]),
            sctExt(),
            keyShareExt(keyShares),
            supportedVersionsExt([0x0304, 0x0303]),
            signatureAlgorithmsExt(firefoxSignatureAlgorithms),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            // Firefox also offers zstd; nothing here can inflate it, and a
            // server that picks it leaves us with no certificate at all.
            compressCertExt([0x0001, 0x0002]),         // zlib, Brotli
            greaseECHExt(random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: false)
    }

    // -- Safari 26 --

    private static func buildSafari26(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?, _ mlkem: [UInt8]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suiteList: [Int] = [
            gCipher,
            0x1302, 0x1303, 0x1301,             // TLS 1.3 (AES-256 first)
            0xC02C, 0xC02B, 0xCCA9,             // ECDHE ECDSA
            0xC030, 0xC02F, 0xCCA8,             // ECDHE RSA
            0xC00A, 0xC009,                     // ECDHE ECDSA CBC
            0xC014, 0xC013,                     // ECDHE RSA CBC
            0x009D, 0x009C,                     // RSA GCM
            0x0035, 0x002F,                     // RSA CBC
            0xC008, 0xC012, 0x000A,             // 3DES (legacy)
        ]
        let suites = cipherSuitesData(suiteList)
        let protocols = alpn ?? defaultALPN

        let groups: [Int]
        let keyShares: [(group: Int, key: [UInt8])]
        if let mlkem = mlkem {
            groups = [gGroup, 0x11EC, 0x001D, 0x0017, 0x0018, 0x0019]
            keyShares = [(gGroup, [0x00]), (0x11EC, mlkem768HybridKeyShare(mlkem, publicKey)), (0x001D, publicKey)]
        } else {
            groups = [gGroup, 0x001D, 0x0017, 0x0018, 0x0019]
            keyShares = [(gGroup, [0x00]), (0x001D, publicKey)]
        }

        let signatureAlgorithms: [Int] = [
            0x0403, 0x0804, 0x0401,
            0x0503, 0x0805, 0x0805,             // intentional duplicate (real Safari)
            0x0501,
            0x0806, 0x0601,
            0x0201,
        ]

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt(groups),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(signatureAlgorithms),
            sctExt(),
            keyShareExt(keyShares),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0001]),                 // zlib
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Edge 85 --

    private static func buildEdge85(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suites = cipherSuitesData([gCipher] + chromeCipherSuites)
        let protocols = alpn ?? defaultALPN

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0002]),                 // Brotli
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Android 11 (OkHttp, TLS 1.2 only) --

    private static func buildAndroid11(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let suites = cipherSuitesData([
            0xC02B, 0xC02C,                     // ECDHE ECDSA AES-GCM
            0xCCA9,                             // ECDHE ECDSA ChaCha20
            0xC02F, 0xC030,                     // ECDHE RSA AES-GCM
            0xCCA8,                             // ECDHE RSA ChaCha20
            0xC013, 0xC014,                     // ECDHE RSA CBC
            0x009C, 0x009D,                     // RSA AES-GCM
            0x002F, 0x0035,                     // RSA AES-CBC
        ])
        let exts: [[UInt8]] = [
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms + [0x0201]),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: false)
    }

    // -- QQ 11 --

    private static func buildQQ11(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suites = cipherSuitesData([gCipher] + chromeCipherSuites)
        let protocols = alpn ?? defaultALPN

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0002]),                 // Brotli
            applicationSettingsExt(["h2"]),            // ALPS 0x4469
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- 360 Browser 7.5 (legacy, TLS 1.2 only) --

    private static func buildBrowser360(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let suites = cipherSuitesData([
            0xC00A, 0xC014, 0x0039, 0x006B, 0x0035, 0x003D,     // AES-256 variants
            0xC007, 0xC009, 0xC023,                             // ECDHE ECDSA (RC4, AES-128)
            0xC011, 0xC013, 0xC027,                             // ECDHE RSA
            0x0033, 0x0067, 0x0032,                             // DHE RSA/DSS
            0x0005, 0x0004,                                     // RSA RC4
            0x002F, 0x003C,                                     // RSA AES-128 CBC
            0x000A,                                             // 3DES
        ])
        let exts: [[UInt8]] = [
            buildSNIExtension(serverName),
            renegotiationInfoExt(),
            supportedGroupsExt([0x0017, 0x0018, 0x0019]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            npnExt(),
            alpnExt(["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"]),
            fakeChannelIDOldExt(),
            statusRequestExt(),
            signatureAlgorithmsExt([
                0x0401, 0x0501, 0x0201,
                0x0403, 0x0503, 0x0203,
                0x0402, 0x0202,
            ]),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: false)
    }

    // -- Chrome 120 --

    private static func buildChrome120(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suites = cipherSuitesData([gCipher] + chromeCipherSuites)
        let protocols = alpn ?? defaultALPN

        // BoringGREASEECH: HKDF-SHA256 / AES-128-GCM; payload from
        // [128, 160, 192, 224] plus the 16-byte AEAD overhead.
        let echPayloadLens = [144, 176, 208, 240]
        let echPayloadLen = echPayloadLens[Int(random[30]) % echPayloadLens.count]

        var exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                 // Brotli
            applicationSettingsExt(["h2"]),
            greaseECHExt(random, kdfId: 0x0001, aeadId: 0x0001, payloadLen: echPayloadLen),
            greaseExt(gExt2),
        ]
        shuffleChromeExtensions(&exts, random: random)
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Firefox 120 --

    private static func buildFirefox120(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?, _ p256: [UInt8]
    ) -> FingerprintParts {
        let suites = cipherSuitesData(firefoxCipherSuites)
        let protocols = alpn ?? defaultALPN
        let echAead = Int(random[30]) % 2 == 0 ? 0x0001 : 0x0003

        let exts: [[UInt8]] = [
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            delegatedCredentialsExt([0x0403, 0x0503, 0x0603, 0x0203]),
            keyShareExt([(0x001D, publicKey), (0x0017, p256)]),
            supportedVersionsExt([0x0304, 0x0303]),
            signatureAlgorithmsExt(firefoxSignatureAlgorithms),
            pskKeyExchangeModesExt(),
            recordSizeLimitExt(0x4001),
            greaseECHExt(random, kdfId: 0x0001, aeadId: echAead, payloadLen: 239),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: false)
    }

    // -- Safari 16.0 --

    private static func buildSafari16(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suiteList: [Int] = [
            gCipher,
            0x1301, 0x1302, 0x1303,             // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,             // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,             // ECDHE RSA (GCM, ChaCha)
            0xC00A, 0xC009,                     // ECDHE ECDSA CBC
            0xC014, 0xC013,                     // ECDHE RSA CBC
            0x009D, 0x009C,                     // RSA GCM
            0x0035, 0x002F,                     // RSA CBC
            0xC008, 0xC012, 0x000A,             // 3DES (legacy)
        ]
        let suites = cipherSuitesData(suiteList)
        let protocols = alpn ?? defaultALPN

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018, 0x0019]),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(appleSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            compressCertExt([0x0001]),                 // zlib
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    /// Safari 16 and iOS 14 send the same list, 0x0805 twice included.
    private static let appleSignatureAlgorithms: [Int] = [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0203,
        0x0805, 0x0805,
        0x0501,
        0x0806, 0x0601,
        0x0201,
    ]

    // -- iOS 14 --

    private static func buildIOS14(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suiteList: [Int] = [
            gCipher,
            0x1301, 0x1302, 0x1303,             // TLS 1.3
            0xC02C, 0xC02B, 0xCCA9,             // ECDHE ECDSA (GCM, ChaCha)
            0xC030, 0xC02F, 0xCCA8,             // ECDHE RSA (GCM, ChaCha)
            0xC024, 0xC023, 0xC00A, 0xC009,     // ECDHE ECDSA CBC
            0xC028, 0xC027, 0xC014, 0xC013,     // ECDHE RSA CBC
            0x009D, 0x009C,                     // RSA GCM
            0x003D, 0x003C,                     // RSA CBC SHA256
            0x0035, 0x002F,                     // RSA CBC SHA
            0xC008, 0xC012, 0x000A,             // 3DES (legacy)
        ]
        let suites = cipherSuitesData(suiteList)
        let protocols = alpn ?? defaultALPN

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018, 0x0019]),
            ecPointFormatsExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(appleSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303, 0x0302, 0x0301]),
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Edge 106 --

    private static func buildEdge106(
        _ random: [UInt8], _ serverName: String, _ publicKey: [UInt8], _ alpn: [String]?
    ) -> FingerprintParts {
        let gCipher = grease(random[24])
        let gExt1 = grease(random[25])
        let gGroup = grease(random[26])
        let gVersion = grease(random[28])
        let gExt2 = secondGrease(random, first: gExt1)

        let suites = cipherSuitesData([gCipher] + chromeCipherSuites)
        let protocols = alpn ?? defaultALPN

        let exts: [[UInt8]] = [
            greaseExt(gExt1),
            buildSNIExtension(serverName),
            extendedMasterSecretExt(),
            renegotiationInfoExt(),
            supportedGroupsExt([gGroup, 0x001D, 0x0017, 0x0018]),
            ecPointFormatsExt(),
            sessionTicketExt(),
            alpnExt(protocols),
            statusRequestExt(),
            signatureAlgorithmsExt(chromeSignatureAlgorithms),
            sctExt(),
            keyShareExt([(gGroup, [0x00]), (0x001D, publicKey)]),
            pskKeyExchangeModesExt(),
            supportedVersionsExt([gVersion, 0x0304, 0x0303]),
            compressCertExt([0x0002]),                 // Brotli
            applicationSettingsExt(["h2"]),
            greaseExt(gExt2),
        ]
        return FingerprintParts(cipherSuites: suites, extensions: exts.flatMap { $0 }, needsPadding: true)
    }

    // -- Reading a built hello back --

    /// The parts of a ClientHello handshake message.
    struct ParsedHello {
        let random: [UInt8]
        let sessionId: [UInt8]
        let cipherSuites: [UInt8]
        let extensions: [(type: Int, body: [UInt8])]
    }

    static func parse(_ hello: [UInt8]) throws -> ParsedHello {
        var reader = TLSByteReader(hello, context: "ClientHello")
        let type = try reader.u8()
        let length = try reader.u24()
        if type != 0x01 || length != hello.count - 4 {
            throw MythaiaError.tls("malformed ClientHello")
        }
        _ = try reader.u16()
        let random = try reader.take(32)
        let sessionIdLength = try reader.u8()
        let sessionId = try reader.take(sessionIdLength)
        let suitesLength = try reader.u16()
        let suites = try reader.take(suitesLength)
        let compressionLength = try reader.u8()
        try reader.skip(compressionLength)
        var extensions: [(type: Int, body: [UInt8])] = []
        if !reader.isAtEnd {
            let extensionsLength = try reader.u16()
            let start = reader.offset
            var extReader = TLSByteReader(hello, context: "ClientHello extensions", from: start, to: start + extensionsLength)
            while !extReader.isAtEnd {
                let extType = try extReader.u16()
                let bodyLength = try extReader.u16()
                let body = try extReader.take(bodyLength)
                extensions.append((type: extType, body: body))
            }
        }
        return ParsedHello(random: random, sessionId: sessionId, cipherSuites: suites, extensions: extensions)
    }

    /// The body of extension `type`, or nil when the hello does not carry it.
    static func extensionBody(in hello: [UInt8], type: Int) -> [UInt8]? {
        guard let parsed = try? parse(hello) else { return nil }
        for entry in parsed.extensions where entry.type == type {
            return entry.body
        }
        return nil
    }

    /// Whether the hello lists TLS 1.3 in supported_versions.
    static func offersTls13(_ hello: [UInt8]) -> Bool {
        guard let versions = extensionBody(in: hello, type: 0x002B), !versions.isEmpty else { return false }
        var index = 1
        while index + 2 <= versions.count {
            if versions[index] == 0x03 && versions[index + 1] == 0x04 { return true }
            index += 2
        }
        return false
    }

    /// The groups the hello carries a key share for, GREASE included.
    static func keyShareGroups(in hello: [UInt8]) -> [Int] {
        guard let body = extensionBody(in: hello, type: 0x0033), body.count >= 2 else { return [] }
        var reader = TLSByteReader(body, context: "key_share", from: 2, to: 2 + TLSWire.u16(body, 0))
        var groups: [Int] = []
        while !reader.isAtEnd {
            guard let group = try? reader.u16(), let length = try? reader.u16() else { break }
            if (try? reader.skip(length)) == nil { break }
            groups.append(group)
        }
        return groups
    }

    /// The second ClientHello after a HelloRetryRequest (RFC 8446 §4.1.2):
    /// the first one with key_share holding only the share the server asked
    /// for, the server's cookie echoed right after it, and the padding
    /// recomputed. Random, session id, suites and the order of everything
    /// else stay, as BoringSSL keeps them.
    static func retryClientHello(_ hello: [UInt8], keyShare: (group: Int, key: [UInt8])?, cookie: [UInt8]?) throws -> [UInt8] {
        let parsed = try parse(hello)
        var hadPadding = false
        var extensions: [UInt8] = []
        for entry in parsed.extensions {
            if entry.type == 0x0015 {
                hadPadding = true
                continue
            }
            if entry.type == 0x002C {
                continue
            }
            if entry.type == 0x0033 {
                if let share = keyShare {
                    extensions.append(contentsOf: keyShareExt([(share.group, share.key)]))
                } else {
                    extensions.append(contentsOf: ext(entry.type, entry.body))
                }
                if let cookie = cookie {
                    var body = TLSByteWriter()
                    body.u16(cookie.count)
                    body.append(cookie)
                    extensions.append(contentsOf: ext(0x002C, body.bytes))
                }
                continue
            }
            extensions.append(contentsOf: ext(entry.type, entry.body))
        }
        return assembleClientHello(
            random: parsed.random,
            sessionId: parsed.sessionId,
            cipherSuites: parsed.cipherSuites,
            extensions: extensions,
            applyBoringPadding: hadPadding
        )
    }
}
