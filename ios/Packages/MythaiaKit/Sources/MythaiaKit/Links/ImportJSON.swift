import Foundation

/**
 * JSON as the importers read it.
 *
 * Panels write JSON loosely — a port as a string, a flag as text — and other
 * clients read it with forgiving accessors, so the importers do too:
 * `optString` of a number gives its digits, `optInt` of `"443"` gives 443,
 * `optBoolean` of `"true"` gives true. This tree keeps those
 * semantics, keeps each object's key order (so a document written back out
 * reads the same), and keeps numbers as the text they were written as.
 */
enum ImportJSON: Equatable {
    case null
    case bool(Bool)
    /// A number, as the literal it was written as.
    case number(String)
    case string(String)
    case array([ImportJSON])
    case object(ImportJSONObject)

    var objectValue: ImportJSONObject? {
        if case .object(let o) = self { return o }
        return nil
    }

    var arrayValue: [ImportJSON]? {
        if case .array(let a) = self { return a }
        return nil
    }

    var isNull: Bool {
        if case .null = self { return true }
        return false
    }

    /// The value as text: a string as it is, anything else as JSON.
    var text: String {
        switch self {
        case .string(let s): return s
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let n): return n
        case .array, .object: return serialized()
        }
    }

    /// The value as an integer: numbers truncated, numeric strings parsed, anything else nil.
    var intValue: Int? {
        switch self {
        case .number(let n):
            return ImportJSON.truncatedInt(n)
        case .string(let s):
            return ImportJSON.truncatedInt(LinkText.trim(s))
        default:
            return nil
        }
    }

    /// The value as a flag: true and false, and the strings that spell them.
    var boolValue: Bool? {
        switch self {
        case .bool(let b):
            return b
        case .string(let s):
            let lower = s.lowercased()
            if lower == "true" { return true }
            if lower == "false" { return false }
            return nil
        default:
            return nil
        }
    }

    /// A number as Double, for the importers that need fractions.
    var doubleValue: Double? {
        switch self {
        case .number(let n): return Double(n)
        case .string(let s): return Double(LinkText.trim(s))
        default: return nil
        }
    }

    private static func truncatedInt(_ text: String) -> Int? {
        if let exact = Int(text) {
            return max(Int(Int32.min), min(Int(Int32.max), exact))
        }
        guard let d = Double(text), d.isFinite else { return nil }
        // Out of range saturates rather than trapping.
        let clamped = max(Double(Int32.min), min(Double(Int32.max), d))
        return Int(clamped.rounded(.towardZero))
    }

    // MARK: - Writing

    /// Compact JSON text.
    func serialized() -> String {
        var out = ""
        write(into: &out)
        return out
    }

    private func write(into out: inout String) {
        switch self {
        case .null:
            out += "null"
        case .bool(let b):
            out += b ? "true" : "false"
        case .number(let n):
            out += n
        case .string(let s):
            ImportJSON.quote(s, into: &out)
        case .array(let items):
            out += "["
            var first = true
            for item in items {
                if !first { out += "," }
                first = false
                item.write(into: &out)
            }
            out += "]"
        case .object(let object):
            out += "{"
            var first = true
            for key in object.keys {
                guard let value = object[key] else { continue }
                if !first { out += "," }
                first = false
                ImportJSON.quote(key, into: &out)
                out += ":"
                value.write(into: &out)
            }
            out += "}"
        }
    }

    /// `value` as a double-quoted RFC 8259 string: only `"`, `\` and control characters escaped.
    static func quote(_ value: String, into out: inout String) {
        out += "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }

    static func quote(_ value: String) -> String {
        var out = ""
        quote(value, into: &out)
        return out
    }

    // MARK: - Reading

    /// Parses one JSON value; text after it is ignored, as other clients' readers ignore it.
    static func parse(_ text: String) throws -> ImportJSON {
        var parser = ImportJSONParser(bytes: Array(text.utf8))
        return try parser.parseDocument()
    }

    /// Parses `text`, which must be a JSON object.
    static func parseObject(_ text: String) throws -> ImportJSONObject {
        let value = try parse(text)
        guard let object = value.objectValue else {
            throw MythaiaError.parse("JSON text is not an object")
        }
        return object
    }
}

/// A JSON object that remembers the order its keys were first written in.
struct ImportJSONObject: Equatable {
    private(set) var keys: [String] = []
    private var storage: [String: ImportJSON] = [:]

    init() {}

    var count: Int { keys.count }
    var isEmpty: Bool { keys.isEmpty }

    subscript(key: String) -> ImportJSON? {
        storage[key]
    }

    /// Sets `key`; a key written again keeps its place and takes the new value.
    mutating func put(_ key: String, _ value: ImportJSON) {
        if storage.updateValue(value, forKey: key) == nil {
            keys.append(key)
        }
    }

    mutating func put(_ key: String, _ value: String) {
        put(key, ImportJSON.string(value))
    }

    mutating func put(_ key: String, _ value: Int) {
        put(key, ImportJSON.number(String(value)))
    }

    mutating func put(_ key: String, _ value: Bool) {
        put(key, ImportJSON.bool(value))
    }

    func has(_ key: String) -> Bool {
        storage[key] != nil
    }

    /// The value, null included; nil only when the key is absent.
    func opt(_ key: String) -> ImportJSON? {
        storage[key]
    }

    /// The value as text; `fallback` when absent or null.
    func optString(_ key: String, _ fallback: String = "") -> String {
        guard let value = storage[key] else { return fallback }
        if value.isNull { return fallback }
        return value.text
    }

    func optInt(_ key: String, _ fallback: Int = 0) -> Int {
        storage[key]?.intValue ?? fallback
    }

    func optBoolean(_ key: String, _ fallback: Bool = false) -> Bool {
        storage[key]?.boolValue ?? fallback
    }

    func optObject(_ key: String) -> ImportJSONObject? {
        storage[key]?.objectValue
    }

    func optArray(_ key: String) -> [ImportJSON]? {
        storage[key]?.arrayValue
    }

    func serialized() -> String {
        ImportJSON.object(self).serialized()
    }
}

extension Array where Element == ImportJSON {
    /// Element `index` as text: "" for a missing or null element.
    func optString(_ index: Int) -> String {
        guard index >= 0 && index < count else { return "" }
        let value = self[index]
        if value.isNull { return "" }
        return value.text
    }

    func optObject(_ index: Int) -> ImportJSONObject? {
        guard index >= 0 && index < count else { return nil }
        return self[index].objectValue
    }

    /// Every element that is an object, in order.
    var objectElements: [ImportJSONObject] {
        var out: [ImportJSONObject] = []
        for element in self {
            if let object = element.objectValue { out.append(object) }
        }
        return out
    }
}

/// A strict JSON reader over UTF-8 bytes. Comments and trailing commas are
/// the caller's business (XrayJsonImporter strips them and retries).
struct ImportJSONParser {
    private let bytes: [UInt8]
    private var i = 0

    init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    mutating func parseDocument() throws -> ImportJSON {
        // A byte order mark is not part of the document.
        if bytes.count >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF { i = 3 }
        skipWhitespace()
        return try parseValue(depth: 0)
    }

    private func error(_ what: String) -> MythaiaError {
        MythaiaError.parse("\(what) at character \(i)")
    }

    private mutating func skipWhitespace() {
        while i < bytes.count {
            let b = bytes[i]
            if b == 32 || b == 9 || b == 10 || b == 13 {
                i += 1
            } else {
                return
            }
        }
    }

    private mutating func parseValue(depth: Int) throws -> ImportJSON {
        if depth > 512 { throw error("JSON nested too deeply") }
        guard i < bytes.count else { throw error("End of input") }
        let b = bytes[i]
        switch b {
        case 123: // {
            return try parseObject(depth: depth)
        case 91: // [
            return try parseArray(depth: depth)
        case 34: // "
            return .string(try parseString())
        case 116: // t
            try expectLiteral("true")
            return .bool(true)
        case 102: // f
            try expectLiteral("false")
            return .bool(false)
        case 110: // n
            try expectLiteral("null")
            return .null
        default:
            if b == 45 || b == 43 || (b >= 48 && b <= 57) || b == 46 {
                return .number(try parseNumber())
            }
            throw error("Unexpected character")
        }
    }

    private mutating func expectLiteral(_ literal: String) throws {
        let expected = Array(literal.utf8)
        guard i + expected.count <= bytes.count, Array(bytes[i..<(i + expected.count)]) == expected else {
            throw error("Expected \(literal)")
        }
        i += expected.count
    }

    private mutating func parseNumber() throws -> String {
        let start = i
        while i < bytes.count {
            let b = bytes[i]
            let isNumberByte = (b >= 48 && b <= 57) || b == 45 || b == 43 || b == 46 || b == 101 || b == 69
            if !isNumberByte { break }
            i += 1
        }
        let literal = LinkText.string(bytes[start..<i])
        guard Double(literal) != nil else { throw error("Malformed number") }
        // A leading plus is not JSON; written back out it would not parse.
        if literal.hasPrefix("+") { return String(literal.dropFirst()) }
        return literal
    }

    private mutating func parseString() throws -> String {
        // Opening quote.
        i += 1
        var out: [UInt8] = []
        while true {
            guard i < bytes.count else { throw error("Unterminated string") }
            let b = bytes[i]
            if b == 34 {
                i += 1
                return LinkText.string(out)
            }
            if b != 92 {
                out.append(b)
                i += 1
                continue
            }
            i += 1
            guard i < bytes.count else { throw error("Unterminated escape") }
            let e = bytes[i]
            i += 1
            switch e {
            case 34: out.append(34)
            case 92: out.append(92)
            case 47: out.append(47)
            case 98: out.append(8)
            case 102: out.append(12)
            case 110: out.append(10)
            case 114: out.append(13)
            case 116: out.append(9)
            case 117:
                var scalarValue = try readHex4()
                if scalarValue >= 0xD800 && scalarValue <= 0xDBFF {
                    // A high surrogate wants its low half next.
                    if i + 1 < bytes.count && bytes[i] == 92 && bytes[i + 1] == 117 {
                        let save = i
                        i += 2
                        let low = try readHex4()
                        if low >= 0xDC00 && low <= 0xDFFF {
                            scalarValue = 0x10000 + ((scalarValue - 0xD800) << 10) + (low - 0xDC00)
                        } else {
                            i = save
                            scalarValue = 0xFFFD
                        }
                    } else {
                        scalarValue = 0xFFFD
                    }
                } else if scalarValue >= 0xDC00 && scalarValue <= 0xDFFF {
                    scalarValue = 0xFFFD
                }
                let replacement: Unicode.Scalar = "\u{FFFD}"
                let scalar = Unicode.Scalar(scalarValue) ?? replacement
                out.append(contentsOf: Array(String(Character(scalar)).utf8))
            default:
                // An unknown escape stands for its character, as lenient readers take it.
                out.append(e)
            }
        }
    }

    private mutating func readHex4() throws -> UInt32 {
        guard i + 4 <= bytes.count else { throw error("Short unicode escape") }
        var value: UInt32 = 0
        for k in 0..<4 {
            guard let v = LinkText.hexValue(bytes[i + k]) else { throw error("Malformed unicode escape") }
            value = value << 4 | UInt32(v)
        }
        i += 4
        return value
    }

    private mutating func parseArray(depth: Int) throws -> ImportJSON {
        i += 1
        var items: [ImportJSON] = []
        skipWhitespace()
        if i < bytes.count && bytes[i] == 93 {
            i += 1
            return .array(items)
        }
        while true {
            skipWhitespace()
            items.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            guard i < bytes.count else { throw error("Unterminated array") }
            if bytes[i] == 44 {
                i += 1
                continue
            }
            if bytes[i] == 93 {
                i += 1
                return .array(items)
            }
            throw error("Expected , or ]")
        }
    }

    private mutating func parseObject(depth: Int) throws -> ImportJSON {
        i += 1
        var object = ImportJSONObject()
        skipWhitespace()
        if i < bytes.count && bytes[i] == 125 {
            i += 1
            return .object(object)
        }
        while true {
            skipWhitespace()
            guard i < bytes.count, bytes[i] == 34 else { throw error("Expected a key") }
            let key = try parseString()
            skipWhitespace()
            guard i < bytes.count, bytes[i] == 58 else { throw error("Expected :") }
            i += 1
            skipWhitespace()
            let value = try parseValue(depth: depth + 1)
            object.put(key, value)
            skipWhitespace()
            guard i < bytes.count else { throw error("Unterminated object") }
            if bytes[i] == 44 {
                i += 1
                continue
            }
            if bytes[i] == 125 {
                i += 1
                return .object(object)
            }
            throw error("Expected , or }")
        }
    }
}
