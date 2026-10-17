import Foundation

/**
 * A YAML reader for Clash subscriptions, producing a tree in which every
 * scalar is a string and mappings and sequences are JSON objects and arrays. `ClashProxyParser` reads it with the same tolerant
 * accessors either way, so `port: 443` and `port: "443"` mean the same.
 *
 * It covers what real Clash documents use: block mappings and sequences
 * (sequences under a key at the key's own column included), `- key: value`
 * items, flow mappings `{...}` and flow sequences `[...]` (over several lines
 * too), single- and double-quoted scalars, `|`/`>` block scalars, comments,
 * document markers, and anchors with `<<` merges. It never fails: a line it
 * cannot place is passed over, because one odd rule in a 5,000-line config
 * must not cost the user every server above it.
 */
struct ClashYAML {
    private var lines: [[UInt8]]
    private var pos = 0
    private var seenContent = false
    private var ended = false
    private var anchors: [String: ImportJSON] = [:]

    private static let space: UInt8 = 32
    private static let tab: UInt8 = 9
    private static let colon: UInt8 = 58
    private static let hash: UInt8 = 35
    private static let dash: UInt8 = 45
    private static let doubleQuote: UInt8 = 34
    private static let singleQuote: UInt8 = 39
    private static let backslash: UInt8 = 92
    private static let openBracket: UInt8 = 91
    private static let closeBracket: UInt8 = 93
    private static let openBrace: UInt8 = 123
    private static let closeBrace: UInt8 = 125
    private static let comma: UInt8 = 44
    /// Flow collections, aliases, block scalars, complex keys and reserved indicators start values, not keys.
    private static let notKeyStarts: Set<UInt8> = [91, 123, 35, 42, 124, 62, 63, 37, 64, 96]

    private init(_ text: String) {
        var bytes = Array(text.utf8)
        if bytes.count >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
            bytes.removeFirst(3)
        }
        var split: [[UInt8]] = []
        var current: [UInt8] = []
        for b in bytes {
            if b == 10 {
                if current.last == 13 { current.removeLast() }
                split.append(current)
                current = []
            } else {
                current.append(b)
            }
        }
        if current.last == 13 { current.removeLast() }
        split.append(current)
        lines = split
    }

    /// The first document of `text` as a tree; nil when it holds no content.
    static func parse(_ text: String) -> ImportJSON? {
        var reader = ClashYAML(text)
        guard let first = reader.nextContentIndex() else { return nil }
        return reader.parseBlock(indent: reader.indentOf(first))
    }

    // MARK: - Lines

    private func indentOf(_ index: Int) -> Int {
        ClashYAML.indent(lines[index])
    }

    private static func indent(_ line: [UInt8]) -> Int {
        var n = 0
        while n < line.count && (line[n] == space || line[n] == tab) { n += 1 }
        return n
    }

    private func content(_ index: Int) -> ArraySlice<UInt8> {
        let line = lines[index]
        return line[ClashYAML.indent(line)...]
    }

    private static func isBlank(_ line: [UInt8]) -> Bool {
        line.allSatisfy { $0 == space || $0 == tab }
    }

    private static func isDocumentMarker(_ line: [UInt8]) -> Bool {
        guard line.count >= 3 else { return false }
        let isDashes = line[0] == dash && line[1] == dash && line[2] == dash
        let isDots = line[0] == 46 && line[1] == 46 && line[2] == 46
        guard isDashes || isDots else { return false }
        return line.count == 3 || line[3] == space || line[3] == tab
    }

    /// The next line that holds content, blank lines, comments and
    /// directives skipped; nil at the end of the first document.
    private mutating func nextContentIndex() -> Int? {
        if ended { return nil }
        while pos < lines.count {
            let line = lines[pos]
            if ClashYAML.isDocumentMarker(line) {
                if seenContent {
                    ended = true
                    return nil
                }
                pos += 1
                continue
            }
            if line.first == 37 && !seenContent { // %YAML, %TAG
                pos += 1
                continue
            }
            let body = content(pos)
            if body.isEmpty || body.first == ClashYAML.hash {
                pos += 1
                continue
            }
            return pos
        }
        return nil
    }

    private static func isSequenceEntry(_ text: ArraySlice<UInt8>) -> Bool {
        guard let first = text.first, first == dash else { return false }
        let next = text.index(after: text.startIndex)
        return next == text.endIndex || text[next] == space || text[next] == tab
    }

    // MARK: - Block structure

    private mutating func parseBlock(indent: Int) -> ImportJSON {
        guard let i = nextContentIndex() else { return .string("") }
        let ind = indentOf(i)
        let body = content(i)
        if ClashYAML.isSequenceEntry(body) { return parseSequence(indent: ind) }
        if splitKey(body) != nil { return parseMapping(indent: ind) }
        // A scalar or a flow collection on a line of its own.
        pos = i + 1
        seenContent = true
        return parseValue(body, parentIndent: ind - 1, allowIndentlessSequence: false)
    }

    private mutating func parseMapping(indent: Int) -> ImportJSON {
        var object = ImportJSONObject()
        while let i = nextContentIndex() {
            let ind = indentOf(i)
            if ind < indent { break }
            let body = content(i)
            if ind > indent || ClashYAML.isSequenceEntry(body) {
                // Indented under nothing, or a list where a key belongs:
                // not YAML, and not worth losing the rest of the document over.
                pos = i + 1
                continue
            }
            guard let pair = splitKey(body) else {
                pos = i + 1
                continue
            }
            let key = pair.0
            let rest = pair.1
            pos = i + 1
            seenContent = true
            let value = parseValue(rest, parentIndent: indent, allowIndentlessSequence: true)
            if key == "<<" {
                ClashYAML.merge(value, into: &object)
            } else {
                object.put(key, value)
            }
        }
        return .object(object)
    }

    private mutating func parseSequence(indent: Int) -> ImportJSON {
        var items: [ImportJSON] = []
        while let i = nextContentIndex() {
            let ind = indentOf(i)
            if ind < indent { break }
            let body = content(i)
            if ind > indent {
                pos = i + 1
                continue
            }
            guard ClashYAML.isSequenceEntry(body) else { break }
            seenContent = true
            var k = body.index(after: body.startIndex)
            while k < body.endIndex && (body[k] == ClashYAML.space || body[k] == ClashYAML.tab) { k += 1 }
            let rest = body[k...]
            let itemIndent = ind + (k - body.startIndex)
            if rest.isEmpty || rest.first == ClashYAML.hash {
                pos = i + 1
                items.append(parseNested(parentIndent: indent, allowIndentlessSequence: false))
            } else if ClashYAML.isSequenceEntry(rest) || splitKey(rest) != nil {
                // A nested list or a compact mapping: read the line again as
                // if the item started at its own column.
                lines[i] = [UInt8](repeating: ClashYAML.space, count: itemIndent) + Array(rest)
                pos = i
                if ClashYAML.isSequenceEntry(rest) {
                    items.append(parseSequence(indent: itemIndent))
                } else {
                    items.append(parseMapping(indent: itemIndent))
                }
            } else {
                pos = i + 1
                items.append(parseValue(rest, parentIndent: indent, allowIndentlessSequence: false))
            }
        }
        return .array(items)
    }

    /// What a key with nothing after its colon holds: the block below it, a
    /// list at the key's own column, or the empty scalar.
    private mutating func parseNested(parentIndent: Int, allowIndentlessSequence: Bool) -> ImportJSON {
        guard let j = nextContentIndex() else { return .string("") }
        let ind = indentOf(j)
        if ind > parentIndent { return parseBlock(indent: ind) }
        if ind == parentIndent && allowIndentlessSequence && ClashYAML.isSequenceEntry(content(j)) {
            return parseSequence(indent: ind)
        }
        return .string("")
    }

    private static func merge(_ value: ImportJSON, into object: inout ImportJSONObject) {
        switch value {
        case .object(let source):
            for key in source.keys where !object.has(key) {
                if let v = source[key] { object.put(key, v) }
            }
        case .array(let sources):
            for source in sources { merge(source, into: &object) }
        default:
            break
        }
    }

    // MARK: - Values

    private mutating func parseValue(_ raw: ArraySlice<UInt8>, parentIndent: Int, allowIndentlessSequence: Bool) -> ImportJSON {
        var text = ClashYAML.trimmed(ClashYAML.withoutComment(ClashYAML.trimmedStart(raw)))
        var anchor: String? = nil
        // Node properties: an anchor and a tag, either order.
        while let first = text.first, first == 38 || first == 33 { // & or !
            let token = ClashYAML.leadingToken(text)
            if first == 38 { anchor = LinkText.string(token.dropFirst()) }
            text = ClashYAML.trimmedStart(text[token.endIndex...])
        }

        let value: ImportJSON
        if text.isEmpty {
            value = parseNested(parentIndent: parentIndent, allowIndentlessSequence: allowIndentlessSequence)
        } else if text.first == 42 { // *alias
            let name = LinkText.string(ClashYAML.leadingToken(text).dropFirst())
            value = anchors[name] ?? .null
        } else if text.first == 124 || text.first == 62 { // | or >
            value = .string(parseBlockScalar(header: text, parentIndent: parentIndent))
        } else if text.first == ClashYAML.openBracket || text.first == ClashYAML.openBrace {
            let whole = collectFlow(Array(text))
            var parser = ClashFlowParser(bytes: whole, anchors: anchors)
            value = parser.parseValue()
        } else if text.first == ClashYAML.doubleQuote || text.first == ClashYAML.singleQuote {
            value = .string(parseQuotedScalar(Array(text)))
        } else {
            value = .string(parsePlainScalar(text, parentIndent: parentIndent))
        }
        if let anchor = anchor { anchors[anchor] = value }
        return value
    }

    /// A quoted scalar, its closing quote looked for on the following lines
    /// when it is not on this one.
    private mutating func parseQuotedScalar(_ start: [UInt8]) -> String {
        var text = start
        while true {
            if let quoted = ClashYAML.readQuoted(text[...]) { return quoted.0 }
            guard pos < lines.count, !ClashYAML.isDocumentMarker(lines[pos]) else { break }
            let next = Array(ClashYAML.trimmed(content(pos)))
            pos += 1
            text.append(ClashYAML.space)
            text.append(contentsOf: next)
        }
        // Never closed: the text as it stands, without its opening quote.
        return LinkText.string(text.dropFirst())
    }

    /// A plain scalar, with the lines that continue it (more indented than its key) folded in.
    private mutating func parsePlainScalar(_ first: ArraySlice<UInt8>, parentIndent: Int) -> String {
        var out = Array(first)
        while pos < lines.count {
            let line = lines[pos]
            if ClashYAML.isBlank(line) || ClashYAML.isDocumentMarker(line) { break }
            if ClashYAML.indent(line) <= parentIndent { break }
            let body = content(pos)
            if body.first == ClashYAML.hash || ClashYAML.isSequenceEntry(body) || splitKey(body) != nil { break }
            let more = ClashYAML.trimmed(ClashYAML.withoutComment(body))
            if more.isEmpty { break }
            out.append(ClashYAML.space)
            out.append(contentsOf: more)
            pos += 1
        }
        return LinkText.string(out)
    }

    private mutating func parseBlockScalar(header: ArraySlice<UInt8>, parentIndent: Int) -> String {
        let literal = header.first == 124
        var chomp: UInt8 = 0
        for b in header.dropFirst() where b == 45 || b == 43 { chomp = b } // - or +

        var collected: [String] = []
        var contentIndent: Int? = nil
        while pos < lines.count {
            let line = lines[pos]
            if ClashYAML.isBlank(line) {
                collected.append("")
                pos += 1
                continue
            }
            let ind = ClashYAML.indent(line)
            if contentIndent == nil {
                if ind <= parentIndent { break }
                contentIndent = ind
            }
            guard let column = contentIndent, ind >= column else { break }
            collected.append(LinkText.string(line[column...]))
            pos += 1
        }
        var trailingBlank = 0
        while let last = collected.last, last.isEmpty {
            collected.removeLast()
            trailingBlank += 1
        }
        var body: String
        if literal {
            body = collected.joined(separator: "\n")
        } else {
            body = ""
            var previousEmpty = true
            for line in collected {
                if line.isEmpty {
                    body += "\n"
                    previousEmpty = true
                } else {
                    if !previousEmpty { body += " " }
                    body += line
                    previousEmpty = false
                }
            }
        }
        switch chomp {
        case 45: return body
        case 43: return body + "\n" + String(repeating: "\n", count: trailingBlank)
        default: return body.isEmpty ? body : body + "\n"
        }
    }

    /// A flow collection, joined with the following lines until its brackets close.
    private mutating func collectFlow(_ start: [UInt8]) -> [UInt8] {
        var text = start
        while ClashYAML.flowDepth(text) > 0 && pos < lines.count {
            let line = lines[pos]
            if ClashYAML.isDocumentMarker(line) { break }
            pos += 1
            let more = ClashYAML.trimmed(ClashYAML.withoutComment(ClashYAML.trimmedStart(line[...])))
            if more.isEmpty { continue }
            text.append(ClashYAML.space)
            text.append(contentsOf: more)
        }
        return text
    }

    /// How many brackets are still open at the end of `text`, quotes respected.
    private static func flowDepth(_ text: [UInt8]) -> Int {
        var depth = 0
        var i = 0
        var previous: UInt8 = space
        while i < text.count {
            let b = text[i]
            if (b == doubleQuote || b == singleQuote) && opensQuote(previous) {
                if let end = quotedEnd(text[...], from: i) {
                    i = end
                    previous = b
                    continue
                }
                return depth + 1
            }
            if b == openBracket || b == openBrace { depth += 1 }
            if b == closeBracket || b == closeBrace { depth -= 1 }
            previous = b
            i += 1
        }
        return depth
    }

    // MARK: - Lexical pieces

    /// `key: rest` — the key (unquoted) and what follows its colon; nil when the text is not a key.
    private func splitKey(_ text: ArraySlice<UInt8>) -> (String, ArraySlice<UInt8>)? {
        guard let first = text.first else { return nil }
        if first == ClashYAML.doubleQuote || first == ClashYAML.singleQuote {
            guard let quoted = ClashYAML.readQuoted(text) else { return nil }
            let key = quoted.0
            var k = quoted.1
            while k < text.endIndex && (text[k] == ClashYAML.space || text[k] == ClashYAML.tab) { k += 1 }
            guard k < text.endIndex, text[k] == ClashYAML.colon else { return nil }
            let after = text.index(after: k)
            guard after == text.endIndex || text[after] == ClashYAML.space || text[after] == ClashYAML.tab else { return nil }
            return (key, text[after...])
        }
        // Flow collections, aliases, block scalars and complex keys are values, not keys.
        if ClashYAML.notKeyStarts.contains(first) { return nil }
        var k = text.startIndex
        var previous: UInt8 = ClashYAML.space
        while k < text.endIndex {
            let b = text[k]
            if b == ClashYAML.colon {
                let after = text.index(after: k)
                if after == text.endIndex || text[after] == ClashYAML.space || text[after] == ClashYAML.tab {
                    let key = LinkText.string(ClashYAML.trimmed(text[text.startIndex..<k]))
                    return (key, text[after...])
                }
            } else if b == ClashYAML.hash && (previous == ClashYAML.space || previous == ClashYAML.tab) {
                return nil
            }
            previous = b
            k += 1
        }
        return nil
    }

    private static func opensQuote(_ previous: UInt8) -> Bool {
        previous == space || previous == tab || previous == openBracket || previous == openBrace ||
            previous == comma || previous == colon
    }

    /// The index just past the quoted scalar that starts at `from`, or nil when it does not close.
    private static func quotedEnd(_ text: ArraySlice<UInt8>, from: Int) -> Int? {
        let quote = text[from]
        var i = from + 1
        while i < text.endIndex {
            let b = text[i]
            if quote == doubleQuote && b == backslash {
                i += 2
                continue
            }
            if b == quote {
                if quote == singleQuote && i + 1 < text.endIndex && text[i + 1] == singleQuote {
                    i += 2
                    continue
                }
                return i + 1
            }
            i += 1
        }
        return nil
    }

    /// The quoted scalar `text` starts with, unescaped, and the index past its closing quote.
    static func readQuoted(_ text: ArraySlice<UInt8>) -> (String, Int)? {
        guard let quote = text.first else { return nil }
        guard let end = quotedEnd(text, from: text.startIndex) else { return nil }
        let inner = text[(text.startIndex + 1)..<(end - 1)]
        if quote == singleQuote {
            var out: [UInt8] = []
            var i = inner.startIndex
            while i < inner.endIndex {
                out.append(inner[i])
                if inner[i] == singleQuote && i + 1 < inner.endIndex && inner[i + 1] == singleQuote { i += 2 } else { i += 1 }
            }
            return (LinkText.string(out), end)
        }
        return (unescapeDoubleQuoted(inner), end)
    }

    private static func unescapeDoubleQuoted(_ inner: ArraySlice<UInt8>) -> String {
        var out: [UInt8] = []
        var i = inner.startIndex
        while i < inner.endIndex {
            let b = inner[i]
            guard b == backslash, i + 1 < inner.endIndex else {
                out.append(b)
                i += 1
                continue
            }
            let e = inner[i + 1]
            i += 2
            switch e {
            case 48: out.append(0)              // \0
            case 97: out.append(7)              // \a
            case 98: out.append(8)              // \b
            case 116, 9: out.append(9)          // \t
            case 110: out.append(10)            // \n
            case 118: out.append(11)            // \v
            case 102: out.append(12)            // \f
            case 114: out.append(13)            // \r
            case 101: out.append(27)            // \e
            case 120, 117, 85:                  // \xXX \uXXXX \UXXXXXXXX
                let width = e == 120 ? 2 : (e == 117 ? 4 : 8)
                var value: UInt32 = 0
                var ok = i + width <= inner.endIndex
                if ok {
                    for k in 0..<width {
                        guard let v = LinkText.hexValue(inner[i + k]) else { ok = false; break }
                        value = value << 4 | UInt32(v)
                    }
                }
                if ok, let scalar = Unicode.Scalar(value) {
                    out.append(contentsOf: Array(String(Character(scalar)).utf8))
                    i += width
                } else {
                    out.append(e)
                }
            case 78: out.append(contentsOf: [0xC2, 0x85])        // \N
            case 95: out.append(contentsOf: [0xC2, 0xA0])        // \_
            case 76: out.append(contentsOf: [0xE2, 0x80, 0xA8])  // \L
            case 80: out.append(contentsOf: [0xE2, 0x80, 0xA9])  // \P
            default: out.append(e)              // \" \\ \/ \  and anything unknown
            }
        }
        return LinkText.string(out)
    }

    /// The text before a comment: a `#` after white space, outside quotes.
    static func withoutComment(_ text: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        guard let first = text.first else { return text }
        let structured = first == doubleQuote || first == singleQuote || first == openBracket || first == openBrace
        var i = text.startIndex
        var previous: UInt8 = space
        while i < text.endIndex {
            let b = text[i]
            if structured && (b == doubleQuote || b == singleQuote) && opensQuote(previous) {
                if let end = quotedEnd(text, from: i) {
                    previous = b
                    i = end
                    continue
                }
                return text
            }
            if b == hash && (previous == space || previous == tab) {
                return text[text.startIndex..<i]
            }
            previous = b
            i += 1
        }
        return text
    }

    static func trimmedStart(_ text: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        var start = text.startIndex
        while start < text.endIndex && (text[start] == space || text[start] == tab) { start += 1 }
        return text[start..<text.endIndex]
    }

    static func trimmed(_ text: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        var end = text.endIndex
        let trimmedFront = trimmedStart(text)
        while end > trimmedFront.startIndex && (text[end - 1] == space || text[end - 1] == tab) { end -= 1 }
        return text[trimmedFront.startIndex..<end]
    }

    /// The run of non-blank bytes `text` starts with.
    private static func leadingToken(_ text: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
        var i = text.startIndex
        while i < text.endIndex && text[i] != space && text[i] != tab { i += 1 }
        return text[text.startIndex..<i]
    }
}

/// The flow collections `{...}` and `[...]`, on one logical line.
struct ClashFlowParser {
    private let bytes: [UInt8]
    private let anchors: [String: ImportJSON]
    private var i = 0

    init(bytes: [UInt8], anchors: [String: ImportJSON]) {
        self.bytes = bytes
        self.anchors = anchors
    }

    private mutating func skipSpaces() {
        while i < bytes.count && (bytes[i] == 32 || bytes[i] == 9) { i += 1 }
    }

    mutating func parseValue() -> ImportJSON {
        skipSpaces()
        // Properties inside a flow node: skipped.
        while i < bytes.count && (bytes[i] == 38 || bytes[i] == 33) {
            while i < bytes.count && bytes[i] != 32 && bytes[i] != 9 && bytes[i] != 44 && bytes[i] != 93 && bytes[i] != 125 { i += 1 }
            skipSpaces()
        }
        guard i < bytes.count else { return .string("") }
        switch bytes[i] {
        case 91: return parseSequence()
        case 123: return parseMapping()
        case 34, 39:
            return .string(readQuoted())
        case 42:
            i += 1
            let start = i
            while i < bytes.count && bytes[i] != 32 && bytes[i] != 44 && bytes[i] != 93 && bytes[i] != 125 { i += 1 }
            return anchors[LinkText.string(bytes[start..<i])] ?? .null
        default:
            return .string(readPlain(isKey: false))
        }
    }

    private mutating func readQuoted() -> String {
        let rest = bytes[i...]
        if let quoted = ClashYAML.readQuoted(rest) {
            i = quoted.1
            return quoted.0
        }
        // Never closed: everything to the end.
        i = bytes.count
        return LinkText.string(rest.dropFirst())
    }

    /// A plain scalar, up to a flow indicator or a `: ` separator.
    private mutating func readPlain(isKey: Bool) -> String {
        let start = i
        while i < bytes.count {
            let b = bytes[i]
            if b == 44 || b == 91 || b == 93 || b == 123 || b == 125 { break }
            if b == 58 {
                let next = i + 1 < bytes.count ? bytes[i + 1] : 32
                if next == 32 || next == 9 || next == 44 || next == 93 || next == 125 || (isKey && i + 1 == bytes.count) { break }
            }
            if b == 35 && i > start && (bytes[i - 1] == 32 || bytes[i - 1] == 9) { break }
            i += 1
        }
        return LinkText.string(ClashYAML.trimmed(bytes[start..<i]))
    }

    private mutating func parseSequence() -> ImportJSON {
        i += 1
        var items: [ImportJSON] = []
        while true {
            skipSpaces()
            guard i < bytes.count else { break }
            if bytes[i] == 93 {
                i += 1
                break
            }
            if bytes[i] == 44 {
                i += 1
                continue
            }
            let item = parseValue()
            skipSpaces()
            // `[a: b]` is a sequence holding a one-pair mapping.
            if i < bytes.count && bytes[i] == 58, case .string(let key) = item {
                i += 1
                var pair = ImportJSONObject()
                pair.put(key, parseValue())
                items.append(.object(pair))
            } else {
                items.append(item)
            }
            let before = i
            skipSpaces()
            if i < bytes.count && bytes[i] != 44 && bytes[i] != 93 && i == before {
                // Something this reader does not understand: step over it.
                i += 1
            }
        }
        return .array(items)
    }

    private mutating func parseMapping() -> ImportJSON {
        i += 1
        var object = ImportJSONObject()
        while true {
            skipSpaces()
            guard i < bytes.count else { break }
            if bytes[i] == 125 {
                i += 1
                break
            }
            if bytes[i] == 44 {
                i += 1
                continue
            }
            let key: String
            if bytes[i] == 34 || bytes[i] == 39 {
                key = readQuoted()
            } else {
                key = readPlain(isKey: true)
            }
            skipSpaces()
            var value = ImportJSON.string("")
            if i < bytes.count && bytes[i] == 58 {
                i += 1
                value = parseValue()
            }
            if key == "<<" {
                if case .object(let source) = value {
                    for k in source.keys where !object.has(k) {
                        if let v = source[k] { object.put(k, v) }
                    }
                }
            } else {
                object.put(key, value)
            }
            skipSpaces()
            if i < bytes.count && bytes[i] != 44 && bytes[i] != 125 {
                // Stray text after a value: step over it rather than loop on it.
                i += 1
            }
        }
        return .object(object)
    }
}
