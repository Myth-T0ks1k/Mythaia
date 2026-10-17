import Foundation

/**
 * Percent-decodes `s`: only `%XX` hex escapes are decoded; `+` stays literal
 * (unlike form decoding, which treats `+` as a space). VLESS/WebSocket share
 * links follow standard URL percent-encoding, not form encoding — a path like
 * `/?ed=2048+xray` must stay byte-identical, otherwise the HTTP upgrade
 * request path differs for the same share link.
 */
public func percentDecode(_ s: String) -> String {
    // A stray `%` (a name like "50%off") is not an escape; keep the text
    // rather than failing the whole link on it.
    return LinkText.percentDecodeOrNil(s, plusIsSpace: false) ?? s
}

/// Byte-level text helpers for the link and subscription parsers.
///
/// Links are cut at ASCII delimiters, so the parsers work on UTF-8 bytes
/// rather than on `Character`s: a delimiter is found where it is, even beside
/// a combining mark that a `Character` would fold it into, and "\r\n" is two
/// bytes rather than one character.
enum LinkText {

    static func string<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        String(decoding: bytes, as: UTF8.self)
    }

    static func lowerASCII(_ b: UInt8) -> UInt8 {
        (b >= 65 && b <= 90) ? b + 32 : b
    }

    /// Whether `s` starts with `prefix`, compared byte for byte (ASCII case folded when asked).
    static func hasPrefix(_ s: String, _ prefix: String, ignoreCase: Bool = false) -> Bool {
        var iterator = s.utf8.makeIterator()
        for p in prefix.utf8 {
            guard let c = iterator.next() else { return false }
            if c == p { continue }
            if ignoreCase && lowerASCII(c) == lowerASCII(p) { continue }
            return false
        }
        return true
    }

    static func hasSuffix(_ s: String, _ suffix: String) -> Bool {
        let a = Array(s.utf8)
        let b = Array(suffix.utf8)
        if b.count > a.count { return false }
        return Array(a[(a.count - b.count)...]) == b
    }

    /// `s` without `prefix` when it starts with it, `s` otherwise.
    static func removePrefix(_ s: String, _ prefix: String) -> String {
        guard hasPrefix(s, prefix) else { return s }
        return string(s.utf8.dropFirst(prefix.utf8.count))
    }

    static func removeSuffix(_ s: String, _ suffix: String) -> String {
        guard hasSuffix(s, suffix) else { return s }
        return string(s.utf8.dropLast(suffix.utf8.count))
    }

    /// Where `needle` first occurs in `haystack` at or after `from`.
    static func indexOf(_ haystack: [UInt8], _ needle: [UInt8], from: Int = 0) -> Int? {
        let n = needle.count
        if n == 0 { return from <= haystack.count ? from : nil }
        if haystack.count < n { return nil }
        let first = needle[0]
        var i = max(0, from)
        let last = haystack.count - n
        while i <= last {
            if haystack[i] == first {
                var j = 1
                while j < n && haystack[i + j] == needle[j] { j += 1 }
                if j == n { return i }
            }
            i += 1
        }
        return nil
    }

    static func contains(_ s: String, _ needle: String) -> Bool {
        indexOf(Array(s.utf8), Array(needle.utf8)) != nil
    }

    /// Whether any of `needles` occurs in `bytes`.
    static func containsAny(_ bytes: [UInt8], _ needles: [String]) -> Bool {
        for needle in needles where indexOf(bytes, Array(needle.utf8)) != nil {
            return true
        }
        return false
    }

    /// Splits at every `separator` byte, keeping empty pieces.
    static func split(_ s: String, _ separator: UInt8) -> [String] {
        var out: [String] = []
        var start = s.utf8.startIndex
        var i = start
        let utf8 = s.utf8
        while i != utf8.endIndex {
            if utf8[i] == separator {
                out.append(string(utf8[start..<i]))
                start = utf8.index(after: i)
            }
            i = utf8.index(after: i)
        }
        out.append(string(utf8[start..<utf8.endIndex]))
        return out
    }

    /// Splits at any of `separators`, keeping empty pieces.
    static func split(_ s: String, anyOf separators: Set<UInt8>) -> [String] {
        var out: [String] = []
        var current: [UInt8] = []
        for b in s.utf8 {
            if separators.contains(b) {
                out.append(string(current))
                current.removeAll(keepingCapacity: true)
            } else {
                current.append(b)
            }
        }
        out.append(string(current))
        return out
    }

    /// The lines of `s`, split at "\r\n", "\n" or "\r".
    static func lines(_ s: String) -> [String] {
        var out: [String] = []
        var current: [UInt8] = []
        var previousWasCR = false
        for b in s.utf8 {
            if b == 10 {
                if previousWasCR {
                    previousWasCR = false
                    continue
                }
                out.append(string(current))
                current.removeAll(keepingCapacity: true)
            } else if b == 13 {
                out.append(string(current))
                current.removeAll(keepingCapacity: true)
                previousWasCR = true
                continue
            } else {
                current.append(b)
            }
            previousWasCR = false
        }
        out.append(string(current))
        return out
    }

    static func trim(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func trimStart(_ s: String) -> String {
        let scalars = s.unicodeScalars
        guard let start = scalars.firstIndex(where: { !isWhitespace($0) }) else { return "" }
        if start == scalars.startIndex { return s }
        return String(String.UnicodeScalarView(scalars[start...]))
    }

    static func isBlank(_ s: String) -> Bool {
        s.unicodeScalars.allSatisfy { isWhitespace($0) }
    }

    /// White space: Unicode's, plus the four ASCII information separators.
    static func isWhitespace(_ scalar: Unicode.Scalar) -> Bool {
        if scalar.value >= 0x1C && scalar.value <= 0x1F { return true }
        return scalar.properties.isWhitespace
    }

    static func isWhitespaceByte(_ b: UInt8) -> Bool {
        b == 32 || b == 9 || b == 10 || b == 13 || b == 11 || b == 12 || (b >= 0x1C && b <= 0x1F)
    }

    static func isDigits(_ s: String) -> Bool {
        !s.isEmpty && s.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
    }

    // MARK: - Percent encoding

    /// Percent-decodes `s`, or nil when an escape is malformed. Bytes that
    /// are not valid UTF-8 become U+FFFD.
    static func percentDecodeOrNil(_ s: String, plusIsSpace: Bool) -> String? {
        let src = Array(s.utf8)
        if !src.contains(37) && !(plusIsSpace && src.contains(43)) { return s }
        var out: [UInt8] = []
        out.reserveCapacity(src.count)
        var i = 0
        while i < src.count {
            let b = src[i]
            if b == 37 {
                guard i + 2 < src.count else { return nil }
                guard let hi = hexValue(src[i + 1]), let lo = hexValue(src[i + 2]) else { return nil }
                out.append(hi << 4 | lo)
                i += 3
            } else if b == 43 && plusIsSpace {
                out.append(32)
                i += 1
            } else {
                out.append(b)
                i += 1
            }
        }
        return string(out)
    }

    /// Form decoding: `+` is a space. The original text when it does not decode.
    static func formDecode(_ s: String) -> String {
        percentDecodeOrNil(s, plusIsSpace: true) ?? s
    }

    /// Form encoding with the space written `%20`: letters, digits and `.-*_`
    /// stay; everything else, the space included, is percent-encoded byte by
    /// byte in upper-case hex. Other clients' links are written this way.
    static func urlEncode(_ value: String) -> String {
        var out: [UInt8] = []
        out.reserveCapacity(value.utf8.count)
        for b in value.utf8 {
            let keep = (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57) ||
                b == 46 || b == 45 || b == 42 || b == 95
            if keep {
                out.append(b)
            } else {
                out.append(37)
                out.append(upperHex[Int(b >> 4)])
                out.append(upperHex[Int(b & 0x0F)])
            }
        }
        return string(out)
    }

    private static let upperHex: [UInt8] = Array("0123456789ABCDEF".utf8)
    private static let lowerHex: [UInt8] = Array("0123456789abcdef".utf8)

    static func hexValue(_ b: UInt8) -> UInt8? {
        switch b {
        case 48...57: return b - 48
        case 65...70: return b - 55
        case 97...102: return b - 87
        default: return nil
        }
    }

    // MARK: - Hex

    /// Lower-case hex of `data`.
    static func hex<C: Collection>(_ data: C) -> String where C.Element == UInt8 {
        var out: [UInt8] = []
        out.reserveCapacity(data.count * 2)
        for b in data {
            out.append(lowerHex[Int(b >> 4)])
            out.append(lowerHex[Int(b & 0x0F)])
        }
        return string(out)
    }

    /// Hex text (spaces ignored) as bytes; nil when it is not whole bytes of hex.
    static func hexDecode(_ text: String) -> Data? {
        let digits = Array(text.utf8).filter { $0 != 32 }
        if digits.count % 2 != 0 { return nil }
        var out = Data(capacity: digits.count / 2)
        var i = 0
        while i < digits.count {
            guard let hi = hexValue(digits[i]), let lo = hexValue(digits[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    // MARK: - Base64

    /**
     * Strict base64: one alphabet (standard or URL-safe), padding optional
     * but correct when present, nothing after it. With `skipWhitespace`,
     * white space anywhere is passed over, which is what a body broken into
     * lines needs; anything beyond ASCII is never base64.
     */
    static func base64Decode(_ text: String, urlSafe: Bool, skipWhitespace: Bool = false) -> Data? {
        var out: [UInt8] = []
        out.reserveCapacity(text.utf8.count / 4 * 3 + 3)
        var acc: UInt32 = 0
        var n = 0
        var padCount = 0
        for scalar in text.unicodeScalars {
            if skipWhitespace && isWhitespace(scalar) { continue }
            if scalar.value > 127 { return nil }
            let b = UInt8(scalar.value)
            if padCount > 0 {
                // Only the second `=` of "xx==" may follow the first.
                if b == 61 && padCount == 1 && n == 2 {
                    padCount = 2
                    continue
                }
                return nil
            }
            if b == 61 {
                if n < 2 { return nil }
                padCount = 1
                continue
            }
            guard let v = sextet(b, urlSafe: urlSafe) else { return nil }
            acc = (acc << 6) | UInt32(v)
            n += 1
            if n == 4 {
                out.append(UInt8((acc >> 16) & 0xFF))
                out.append(UInt8((acc >> 8) & 0xFF))
                out.append(UInt8(acc & 0xFF))
                acc = 0
                n = 0
            }
        }
        if padCount > 0 && n == 2 && padCount != 2 { return nil }
        switch n {
        case 1:
            return nil
        case 2:
            out.append(UInt8((acc >> 4) & 0xFF))
        case 3:
            out.append(UInt8((acc >> 10) & 0xFF))
            out.append(UInt8((acc >> 2) & 0xFF))
        default:
            break
        }
        return Data(out)
    }

    private static func sextet(_ b: UInt8, urlSafe: Bool) -> UInt8? {
        switch b {
        case 65...90: return b - 65
        case 97...122: return b - 71
        case 48...57: return b + 4
        case 43: return urlSafe ? nil : 62
        case 47: return urlSafe ? nil : 63
        case 45: return urlSafe ? 62 : nil
        case 95: return urlSafe ? 63 : nil
        default: return nil
        }
    }

    /// Standard, padded base64.
    static func base64Encode<C: Collection>(_ data: C) -> String where C.Element == UInt8 {
        Data(data).base64EncodedString()
    }

    /// URL-safe base64 without padding.
    static func base64UrlEncode<C: Collection>(_ data: C) -> String where C.Element == UInt8 {
        var s = Data(data).base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }

    /// The URL-safe alphabet, trimmed, padding optional: how keys travel in links.
    static func base64UrlToData(_ text: String) -> Data? {
        base64Decode(trim(text), urlSafe: true)
    }

    /// Text padded with `=` to a whole number of quads.
    static func padBase64(_ text: String) -> String {
        let remainder = text.utf8.count % 4
        if remainder == 0 { return text }
        return text + String(repeating: "=", count: 4 - remainder)
    }

    /**
     * `decodeBase64Lenient`: white space and line breaks are skipped and the
     * trailing padding is optional. `urlSafe` selects the `-_` alphabet; the
     * standard `+/` one otherwise.
     */
    static func decodeBase64Lenient(_ text: String, urlSafe: Bool) -> Data? {
        base64Decode(text, urlSafe: urlSafe, skipWhitespace: true)
    }

    /// UTF-8 text from bytes, with U+FFFD for anything malformed.
    static func utf8(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
    }
}
