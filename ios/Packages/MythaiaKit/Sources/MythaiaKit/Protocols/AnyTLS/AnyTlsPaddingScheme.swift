import Foundation

/// How AnyTLS shapes the sizes of its first few TLS records.
///
/// A scheme is a small text document: `stop=N` says how many packets to
/// shape, and `<n>=a-b,c,d-e` gives the record sizes packet `n` should be
/// split into. The client starts on a built-in default and replaces it with
/// whatever the server sends in `cmdUpdatePaddingScheme` — which is the point
/// of the design. When a censor learns the default pattern, the server can
/// push a new one and every client changes shape without an update.
///
/// The scheme is identified by the MD5 of its exact bytes, so the raw text is
/// kept rather than re-serialised: a scheme that round-trips through parsing
/// would hash differently and the server would push a replacement forever.
final class AnyTlsPaddingScheme: @unchecked Sendable {
    /// One entry in a packet's size list. A range keeps its bounds as plain
    /// integers: an earlier encoding packed it into one negative Int, which
    /// overflowed once the minimum reached 32768 and read back as a fixed
    /// size of about 1.6 GB.
    private enum Part {
        case check
        case fixed(Int)
        case range(Int, Int)
    }

    /// The check mark, written `c` in a scheme: "if the payload is used up,
    /// stop here", so a small request is not followed by padding records that
    /// would themselves be a signature.
    static let check = AnyTlsProtocol.checkMark

    /// The largest record this client produces. Padding travels inside a
    /// cmdWaste frame whose length is a uint16, so nothing larger can be
    /// expressed on the wire; it also stops a mistyped or hostile scheme from
    /// asking for a two-gigabyte buffer. A part is clamped, never dropped:
    /// dropping one would emit fewer records than the server asked for.
    static let maxRecord = 65535

    /// The scheme every client starts on, byte for byte as the reference
    /// implementation ships it. Its MD5 is what a server compares against, so
    /// a stray newline here would cause a pointless update on every session.
    static let defaultText: String = [
        "stop=8",
        "0=30-30",
        "1=100-400",
        "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
        "3=9-9,500-1000",
        "4=500-1000",
        "5=500-1000",
        "6=500-1000",
        "7=500-1000",
    ].joined(separator: "\n")

    static let defaultScheme: AnyTlsPaddingScheme = {
        guard let scheme = AnyTlsPaddingScheme.parse(Data(AnyTlsPaddingScheme.defaultText.utf8)) else {
            preconditionFailure("the built-in padding scheme does not parse")
        }
        return scheme
    }()

    /// The bytes as received, which is what the digest is taken over.
    let raw: Data
    let md5: String
    private let stop: Int
    private let sizes: [Int: [Part]]

    private init(raw: Data, md5: String, stop: Int, sizes: [Int: [Part]]) {
        self.raw = raw
        self.md5 = md5
        self.stop = stop
        self.sizes = sizes
    }

    /// The record sizes for `packet`, or empty when the scheme says nothing
    /// about it — in which case the caller writes the packet as it is. A
    /// range draws in [lo, hi), as the reference does.
    func recordSizes(_ packet: Int) -> [Int] {
        guard let spec = sizes[packet] else { return [] }
        return spec.map { part -> Int in
            switch part {
            case .check:
                return AnyTlsPaddingScheme.check
            case .fixed(let size):
                return size
            case .range(let lo, let hi):
                return lo + CryptoRandom.int(below: hi - lo)
            }
        }
    }

    /// Whether `packet` should still be shaped at all.
    func shapes(_ packet: Int) -> Bool {
        return packet < stop
    }

    /// Nil when the text is not a usable scheme; the caller keeps the old one.
    static func parse(_ raw: Data) -> AnyTlsPaddingScheme? {
        let entries = AnyTlsProtocol.parseSettings([UInt8](raw))
        if entries.isEmpty { return nil }
        guard let stopText = entries["stop"], let stop = Int(stopText) else { return nil }

        var sizes = [Int: [Part]]()
        for (key, value) in entries {
            guard let packet = Int(key) else { continue }
            var spec = [Part]()
            for piece in value.split(separator: ",", omittingEmptySubsequences: false) {
                if let part = parsePart(piece.trimmingCharacters(in: .whitespaces)) {
                    spec.append(part)
                }
            }
            if !spec.isEmpty {
                sizes[packet] = spec
            }
        }

        let digest = DigestHelper.md5(raw)
        let md5 = digest.map { String(format: "%02x", $0) }.joined()
        return AnyTlsPaddingScheme(raw: Data(raw), md5: md5, stop: stop, sizes: sizes)
    }

    /// A part is either `c`, a fixed size, or a range — as the reference
    /// reads it. Its only rejection: both bounds must be positive.
    private static func parsePart(_ part: String) -> Part? {
        if part == "c" { return .check }
        guard let dash = part.firstIndex(of: "-"), dash != part.startIndex else { return nil }
        guard var lo = Int(part[part.startIndex..<dash]), var hi = Int(part[part.index(after: dash)...]) else {
            return nil
        }
        if lo > hi {
            let t = lo
            lo = hi
            hi = t
        }
        if lo <= 0 || hi <= 0 { return nil }
        lo = min(lo, AnyTlsPaddingScheme.maxRecord)
        hi = min(hi, AnyTlsPaddingScheme.maxRecord)
        return lo == hi ? .fixed(lo) : .range(lo, hi)
    }
}
