import Foundation

/// One header field, name and value, as HPACK carries it.
struct HpackHeader: Hashable, CustomStringConvertible {
    var name: String
    var value: String

    init(_ name: String, _ value: String) {
        self.name = name
        self.value = value
    }

    var description: String { "\(name): \(value)" }
}

/// Minimal HPACK encoder/decoder (RFC 7541) for the HTTP/2 client: integer
/// encoding and decoding (§5.1), raw and Huffman string decoding, indexed
/// header fields, literals with and without indexing, and static table
/// lookup.
///
/// The encoders here emit **only** Literal Header Field without Indexing
/// (§6.2.2). Nothing is ever inserted into an encoder-side dynamic table, so
/// the encoder is stateless and its (empty) dynamic table can never drift out
/// of step with the peer's decoder. gRPC and XHTTP write their own blocks
/// with incremental indexing, as Xray's clients do; the server keeps those
/// entries, this side never refers to them.
enum HpackEncoder {

    /// A CONNECT request: `:method CONNECT`, `:authority`, then `extraHeaders`.
    static func encodeConnectRequest(authority: String, extraHeaders: [HpackHeader]) -> Data {
        var block: [UInt8] = []
        encodeLiteralWithoutIndexing(nameIndex: 2, value: "CONNECT", into: &block)
        encodeLiteralWithoutIndexing(nameIndex: 1, value: authority, into: &block)
        for header in extraHeaders {
            if let nameIndex = staticTableNameIndex(header.name) {
                encodeLiteralWithoutIndexing(nameIndex: nameIndex, value: header.value, into: &block)
            } else {
                encodeLiteralWithoutIndexing(name: header.name, value: header.value, into: &block)
            }
        }
        return Data(block)
    }

    /// An ordered list of header fields (pseudo-headers included) as one
    /// self-contained header block. Names are lowercased: RFC 9113 §8.2
    /// requires lowercase field names, and a peer must treat an uppercase
    /// one as malformed.
    static func encodeHeaderBlock(_ headers: [HpackHeader]) -> Data {
        var block: [UInt8] = []
        for header in headers {
            let lower = header.name.lowercased()
            if let nameIndex = staticTableNameIndex(lower) {
                encodeLiteralWithoutIndexing(nameIndex: nameIndex, value: header.value, into: &block)
            } else {
                encodeLiteralWithoutIndexing(name: lower, value: header.value, into: &block)
            }
        }
        return Data(block)
    }

    /// Decodes one header block with a dynamic table that lives only for
    /// this call; streams that span several blocks need HpackDecoder.
    static func decodeHeaders(_ data: Data) -> [HpackHeader]? {
        var cursor = HpackCursor([UInt8](data))
        var headers: [HpackHeader] = []
        var dynamicTable: [HpackHeader] = []
        while !cursor.atEnd {
            let byte = cursor.peek
            if (byte & 0x80) != 0 {
                guard let index = cursor.decodeInteger(prefixBits: 7),
                      let entry = lookup(index, dynamicTable: dynamicTable) else { return nil }
                headers.append(entry)
            } else if (byte & 0xC0) == 0x40 {
                guard let field = decodeLiteral(&cursor, prefixBits: 6, dynamicTable: dynamicTable) else { return nil }
                headers.append(field)
                dynamicTable.insert(field, at: 0)
            } else if (byte & 0xF0) == 0x00 || (byte & 0xF0) == 0x10 {
                guard let field = decodeLiteral(&cursor, prefixBits: 4, dynamicTable: dynamicTable) else { return nil }
                headers.append(field)
            } else if (byte & 0xE0) == 0x20 {
                // §6.3 Dynamic Table Size Update: consumed without enforcing.
                guard cursor.decodeInteger(prefixBits: 5) != nil else { return nil }
            } else {
                return nil
            }
        }
        return headers
    }

    /// RFC 7541 §5.1 integer with a `prefixBits`-wide prefix. The first byte
    /// holds only the prefix bits; the caller ORs in the representation's
    /// pattern.
    static func encodeInteger(_ value: Int, prefixBits: Int) -> [UInt8] {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            return [UInt8(value)]
        }
        var out: [UInt8] = [UInt8(maxPrefix)]
        var remaining = value - maxPrefix
        while remaining >= 128 {
            out.append(UInt8(remaining % 128 + 128))
            remaining /= 128
        }
        out.append(UInt8(remaining))
        return out
    }

    /// RFC 7541 §5.2 string literal, raw (H = 0).
    static func encodeString(_ string: String) -> [UInt8] {
        let bytes = Array(string.utf8)
        var out = encodeInteger(bytes.count, prefixBits: 7)
        out[0] &= 0x7F
        out.append(contentsOf: bytes)
        return out
    }

    /// The prefix of a Literal Header Field with Incremental Indexing whose
    /// name is static-table entry `nameIndex` (§6.2.1, `01xxxxxx`).
    static func literalWithIndexing(nameIndex: Int) -> [UInt8] {
        var out = encodeInteger(nameIndex, prefixBits: 6)
        out[0] |= 0x40
        return out
    }

    private static func encodeLiteralWithoutIndexing(nameIndex: Int, value: String, into block: inout [UInt8]) {
        var prefix = encodeInteger(nameIndex, prefixBits: 4)
        prefix[0] &= 0x0F
        block.append(contentsOf: prefix)
        block.append(contentsOf: encodeString(value))
    }

    private static func encodeLiteralWithoutIndexing(name: String, value: String, into block: inout [UInt8]) {
        block.append(0x00)
        block.append(contentsOf: encodeString(name))
        block.append(contentsOf: encodeString(value))
    }

    private static func decodeLiteral(_ cursor: inout HpackCursor, prefixBits: Int, dynamicTable: [HpackHeader]) -> HpackHeader? {
        guard let nameIndex = cursor.decodeInteger(prefixBits: prefixBits) else { return nil }
        let name: String
        if nameIndex == 0 {
            guard let literal = cursor.decodeString() else { return nil }
            name = literal
        } else {
            guard let entry = lookup(nameIndex, dynamicTable: dynamicTable) else { return nil }
            name = entry.name
        }
        guard let value = cursor.decodeString() else { return nil }
        return HpackHeader(name, value)
    }

    /// A 1-based header index: the static table is 1–61, the dynamic table
    /// (newest first) starts at 62.
    private static func lookup(_ index: Int, dynamicTable: [HpackHeader]) -> HpackHeader? {
        if index < 1 { return nil }
        if index <= staticTable.count { return staticTable[index - 1] }
        let dynamicIndex = index - staticTable.count - 1
        if dynamicIndex >= dynamicTable.count { return nil }
        return dynamicTable[dynamicIndex]
    }

    static func staticTableNameIndex(_ name: String) -> Int? {
        let lower = name.lowercased()
        for (i, entry) in staticTable.enumerated() where entry.name == lower {
            return i + 1
        }
        return nil
    }

    /// RFC 7541 Appendix A static table.
    static let staticTable: [HpackHeader] = [
        HpackHeader(":authority", ""),
        HpackHeader(":method", "GET"),
        HpackHeader(":method", "POST"),
        HpackHeader(":path", "/"),
        HpackHeader(":path", "/index.html"),
        HpackHeader(":scheme", "http"),
        HpackHeader(":scheme", "https"),
        HpackHeader(":status", "200"),
        HpackHeader(":status", "204"),
        HpackHeader(":status", "206"),
        HpackHeader(":status", "304"),
        HpackHeader(":status", "400"),
        HpackHeader(":status", "404"),
        HpackHeader(":status", "500"),
        HpackHeader("accept-charset", ""),
        HpackHeader("accept-encoding", "gzip, deflate"),
        HpackHeader("accept-language", ""),
        HpackHeader("accept-ranges", ""),
        HpackHeader("accept", ""),
        HpackHeader("access-control-allow-origin", ""),
        HpackHeader("age", ""),
        HpackHeader("allow", ""),
        HpackHeader("authorization", ""),
        HpackHeader("cache-control", ""),
        HpackHeader("content-disposition", ""),
        HpackHeader("content-encoding", ""),
        HpackHeader("content-language", ""),
        HpackHeader("content-length", ""),
        HpackHeader("content-location", ""),
        HpackHeader("content-range", ""),
        HpackHeader("content-type", ""),
        HpackHeader("cookie", ""),
        HpackHeader("date", ""),
        HpackHeader("etag", ""),
        HpackHeader("expect", ""),
        HpackHeader("expires", ""),
        HpackHeader("from", ""),
        HpackHeader("host", ""),
        HpackHeader("if-match", ""),
        HpackHeader("if-modified-since", ""),
        HpackHeader("if-none-match", ""),
        HpackHeader("if-range", ""),
        HpackHeader("if-unmodified-since", ""),
        HpackHeader("last-modified", ""),
        HpackHeader("link", ""),
        HpackHeader("location", ""),
        HpackHeader("max-forwards", ""),
        HpackHeader("proxy-authenticate", ""),
        HpackHeader("proxy-authorization", ""),
        HpackHeader("range", ""),
        HpackHeader("referer", ""),
        HpackHeader("refresh", ""),
        HpackHeader("retry-after", ""),
        HpackHeader("server", ""),
        HpackHeader("set-cookie", ""),
        HpackHeader("strict-transport-security", ""),
        HpackHeader("transfer-encoding", ""),
        HpackHeader("user-agent", ""),
        HpackHeader("vary", ""),
        HpackHeader("via", ""),
        HpackHeader("www-authenticate", ""),
    ]
}

/// Reads HPACK primitives off a header block. Every read checks the end
/// first: a truncated block must fail, never read past what it holds.
struct HpackCursor {
    let bytes: [UInt8]
    var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var atEnd: Bool { offset >= bytes.count }

    var peek: UInt8 { bytes[offset] }

    /// RFC 7541 §5.1. Values past 2^35 are refused: nothing in a header block
    /// is that large, and the sum would otherwise be able to overflow.
    mutating func decodeInteger(prefixBits: Int) -> Int? {
        if offset >= bytes.count { return nil }
        let maxPrefix = (1 << prefixBits) - 1
        var value = Int(bytes[offset]) & maxPrefix
        offset += 1
        if value < maxPrefix { return value }
        var shift = 0
        while true {
            if offset >= bytes.count { return nil }
            if shift > 28 { return nil }
            let b = Int(bytes[offset])
            offset += 1
            value += (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0 { break }
        }
        return value
    }

    mutating func decodeString() -> String? {
        if offset >= bytes.count { return nil }
        let huffman = (bytes[offset] & 0x80) != 0
        guard let length = decodeInteger(prefixBits: 7) else { return nil }
        if length > bytes.count - offset { return nil }
        let raw = Array(bytes[offset..<(offset + length)])
        offset += length
        if huffman {
            guard let decoded = HpackHuffman.decode(raw) else { return nil }
            return String(decoding: decoded, as: UTF8.self)
        }
        return String(decoding: raw, as: UTF8.self)
    }
}

/// Huffman decoder for HPACK string literals (RFC 7541 Appendix B).
enum HpackHuffman {
    /// The code tree as three parallel arrays: children (or -1) and the
    /// symbol a leaf ends (or -1; 256 is EOS).
    private struct Tree {
        var left: [Int]
        var right: [Int]
        var symbol: [Int]
    }

    private static let tree: Tree = buildTree()

    private static func buildTree() -> Tree {
        var left: [Int] = [-1]
        var right: [Int] = [-1]
        var symbol: [Int] = [-1]
        for sym in 0..<codes.count {
            let code = codes[sym]
            let bits = Int(lengths[sym])
            var node = 0
            for bitPos in 0..<bits {
                let bit = (code >> UInt32(31 - bitPos)) & 1
                if bit == 0 {
                    if left[node] < 0 {
                        left.append(-1)
                        right.append(-1)
                        symbol.append(-1)
                        left[node] = symbol.count - 1
                    }
                    node = left[node]
                } else {
                    if right[node] < 0 {
                        left.append(-1)
                        right.append(-1)
                        symbol.append(-1)
                        right[node] = symbol.count - 1
                    }
                    node = right[node]
                }
            }
            symbol[node] = sym
        }
        return Tree(left: left, right: right, symbol: symbol)
    }

    /// The decoded bytes, or nil for input RFC 7541 calls a decoding error.
    static func decode(_ data: [UInt8]) -> [UInt8]? {
        let t = tree
        var result: [UInt8] = []
        var node = 0

        // What is left over after the last complete symbol. §5.2 only allows
        // that to be padding: at most 7 bits, and all ones, since the padding
        // is the leading bits of the EOS code. Anything else is a decoding
        // error rather than a shorter string.
        var danglingBits = 0
        var danglingAllOnes = true

        for byte in data {
            var bitPos = 7
            while bitPos >= 0 {
                let bit = (Int(byte) >> bitPos) & 1
                let next = bit == 0 ? t.left[node] : t.right[node]
                if next < 0 { return nil }
                node = next
                danglingBits += 1
                if bit == 0 { danglingAllOnes = false }
                let sym = t.symbol[node]
                if sym >= 0 {
                    // EOS must never appear in a real header block.
                    if sym == 256 { return nil }
                    result.append(UInt8(sym))
                    node = 0
                    danglingBits = 0
                    danglingAllOnes = true
                }
                bitPos -= 1
            }
        }

        if danglingBits > 7 || !danglingAllOnes { return nil }
        return result
    }

    /// RFC 7541 Appendix B codes, left-aligned in 32 bits, by symbol 0–256
    /// (256 = EOS); `lengths` holds their bit lengths.
    private static let codes: [UInt32] = [
        0xffc00000, 0xffffb000, 0xfffffe20, 0xfffffe30, 0xfffffe40, 0xfffffe50, 0xfffffe60, 0xfffffe70,
        0xfffffe80, 0xffffea00, 0xfffffff0, 0xfffffe90, 0xfffffea0, 0xfffffff4, 0xfffffeb0, 0xfffffec0,
        0xfffffed0, 0xfffffee0, 0xfffffef0, 0xffffff00, 0xffffff10, 0xffffff20, 0xfffffff8, 0xffffff30,
        0xffffff40, 0xffffff50, 0xffffff60, 0xffffff70, 0xffffff80, 0xffffff90, 0xffffffa0, 0xffffffb0,
        0x50000000, 0xfe000000, 0xfe400000, 0xffa00000, 0xffc80000, 0x54000000, 0xf8000000, 0xff400000,
        0xfe800000, 0xfec00000, 0xf9000000, 0xff600000, 0xfa000000, 0x58000000, 0x5c000000, 0x60000000,
        0x00000000, 0x08000000, 0x10000000, 0x64000000, 0x68000000, 0x6c000000, 0x70000000, 0x74000000,
        0x78000000, 0x7c000000, 0xb8000000, 0xfb000000, 0xfff80000, 0x80000000, 0xffb00000, 0xff000000,
        0xffd00000, 0x84000000, 0xba000000, 0xbc000000, 0xbe000000, 0xc0000000, 0xc2000000, 0xc4000000,
        0xc6000000, 0xc8000000, 0xca000000, 0xcc000000, 0xce000000, 0xd0000000, 0xd2000000, 0xd4000000,
        0xd6000000, 0xd8000000, 0xda000000, 0xdc000000, 0xde000000, 0xe0000000, 0xe2000000, 0xe4000000,
        0xfc000000, 0xe6000000, 0xfd000000, 0xffd80000, 0xfffe0000, 0xffe00000, 0xfff00000, 0x88000000,
        0xfffa0000, 0x18000000, 0x8c000000, 0x20000000, 0x90000000, 0x28000000, 0x94000000, 0x98000000,
        0x9c000000, 0x30000000, 0xe8000000, 0xea000000, 0xa0000000, 0xa4000000, 0xa8000000, 0x38000000,
        0xac000000, 0xec000000, 0xb0000000, 0x40000000, 0x48000000, 0xb4000000, 0xee000000, 0xf0000000,
        0xf2000000, 0xf4000000, 0xf6000000, 0xfffc0000, 0xff800000, 0xfff40000, 0xffe80000, 0xffffffc0,
        0xfffe6000, 0xffff4800, 0xfffe7000, 0xfffe8000, 0xffff4c00, 0xffff5000, 0xffff5400, 0xffffb200,
        0xffff5800, 0xffffb400, 0xffffb600, 0xffffb800, 0xffffba00, 0xffffbc00, 0xffffeb00, 0xffffbe00,
        0xffffec00, 0xffffed00, 0xffff5c00, 0xffffc000, 0xffffee00, 0xffffc200, 0xffffc400, 0xffffc600,
        0xffffc800, 0xfffee000, 0xffff6000, 0xffffca00, 0xffff6400, 0xffffcc00, 0xffffce00, 0xffffef00,
        0xffff6800, 0xfffee800, 0xfffe9000, 0xffff6c00, 0xffff7000, 0xffffd000, 0xffffd200, 0xfffef000,
        0xffffd400, 0xffff7400, 0xffff7800, 0xfffff000, 0xfffef800, 0xffff7c00, 0xffffd600, 0xffffd800,
        0xffff0000, 0xffff0800, 0xffff8000, 0xffff1000, 0xffffda00, 0xffff8400, 0xffffdc00, 0xffffde00,
        0xfffea000, 0xffff8800, 0xffff8c00, 0xffff9000, 0xffffe000, 0xffff9400, 0xffff9800, 0xffffe200,
        0xfffff800, 0xfffff840, 0xfffeb000, 0xfffe2000, 0xffff9c00, 0xffffe400, 0xffffa000, 0xfffff600,
        0xfffff880, 0xfffff8c0, 0xfffff900, 0xfffffbc0, 0xfffffbe0, 0xfffff940, 0xfffff100, 0xfffff680,
        0xfffe4000, 0xffff1800, 0xfffff980, 0xfffffc00, 0xfffffc20, 0xfffff9c0, 0xfffffc40, 0xfffff200,
        0xffff2000, 0xffff2800, 0xfffffa00, 0xfffffa40, 0xffffffd0, 0xfffffc60, 0xfffffc80, 0xfffffca0,
        0xfffec000, 0xfffff300, 0xfffed000, 0xffff3000, 0xffffa400, 0xffff3800, 0xffff4000, 0xffffe600,
        0xffffa800, 0xffffac00, 0xfffff700, 0xfffff780, 0xfffff400, 0xfffff500, 0xfffffa80, 0xffffe800,
        0xfffffac0, 0xfffffcc0, 0xfffffb00, 0xfffffb40, 0xfffffce0, 0xfffffd00, 0xfffffd20, 0xfffffd40,
        0xfffffd60, 0xffffffe0, 0xfffffd80, 0xfffffda0, 0xfffffdc0, 0xfffffde0, 0xfffffe00, 0xfffffb80,
        0xfffffffc,
    ]

    private static let lengths: [UInt8] = [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
        30,
    ]
}

/// Stateful HPACK decoder with a dynamic table that persists across header
/// blocks (RFC 7541 §2.3.3), as one connection's streams share it.
///
/// `maxTableSize` is the SETTINGS_HEADER_TABLE_SIZE this side advertised
/// (4096 when it sent none, RFC 9113 §6.5.2): the peer may shrink its table
/// below it with a size update, never grow it past it. The table is kept to
/// the size the peer's encoder keeps, evicting the oldest entries (§4.3), or
/// the two tables drift apart and every index after the first eviction names
/// the wrong field.
final class HpackDecoder {
    static let defaultTableSize = 4096

    /// RFC 7541 §4.1: an entry's size is its name and value in bytes plus 32.
    private static let entryOverhead = 32

    private let maxTableSize: Int

    /// Newest entry first, as §2.3.3 numbers them from 62 up.
    private var dynamicTable: [HpackHeader] = []
    private var dynamicTableSize = 0

    /// The peer's current limit: `maxTableSize` until a size update lowers it.
    private var tableCapacity: Int

    init(maxTableSize: Int = HpackDecoder.defaultTableSize) {
        self.maxTableSize = maxTableSize
        self.tableCapacity = maxTableSize
    }

    /// The block's fields, or nil when it does not decode, in which case the
    /// table's state is no longer known and the connection has to go.
    func decode(_ data: Data) -> [HpackHeader]? {
        var cursor = HpackCursor([UInt8](data))
        var headers: [HpackHeader] = []
        while !cursor.atEnd {
            let byte = cursor.peek
            if (byte & 0x80) != 0 {
                // §6.1 Indexed Header Field
                guard let index = cursor.decodeInteger(prefixBits: 7), let entry = lookup(index) else { return nil }
                headers.append(entry)
            } else if (byte & 0xC0) == 0x40 {
                // §6.2.1 Literal with Incremental Indexing
                guard let field = decodeLiteral(&cursor, prefixBits: 6) else { return nil }
                headers.append(field)
                addEntry(field)
            } else if (byte & 0xF0) == 0x00 || (byte & 0xF0) == 0x10 {
                // §6.2.2 / §6.2.3 Literal without Indexing / Never Indexed
                guard let field = decodeLiteral(&cursor, prefixBits: 4) else { return nil }
                headers.append(field)
            } else if (byte & 0xE0) == 0x20 {
                // §6.3 Dynamic Table Size Update. §4.2: past what we
                // advertised it is a decoding error (COMPRESSION_ERROR).
                guard let size = cursor.decodeInteger(prefixBits: 5) else { return nil }
                if size > maxTableSize { return nil }
                tableCapacity = size
                evictDownTo(tableCapacity)
            } else {
                return nil
            }
        }
        return headers
    }

    func reset() {
        dynamicTable.removeAll()
        dynamicTableSize = 0
        tableCapacity = maxTableSize
    }

    private func addEntry(_ field: HpackHeader) {
        let size = HpackDecoder.entrySize(field)
        // §4.4: make room from the oldest end; an entry larger than the whole
        // table empties it and is itself not added.
        evictDownTo(tableCapacity - size)
        if size > tableCapacity { return }
        dynamicTable.insert(field, at: 0)
        dynamicTableSize += size
    }

    private func evictDownTo(_ limit: Int) {
        while dynamicTableSize > limit, let oldest = dynamicTable.last {
            dynamicTable.removeLast()
            dynamicTableSize -= HpackDecoder.entrySize(oldest)
        }
    }

    private static func entrySize(_ field: HpackHeader) -> Int {
        field.name.utf8.count + field.value.utf8.count + entryOverhead
    }

    private func lookup(_ index: Int) -> HpackHeader? {
        if index < 1 { return nil }
        let staticTable = HpackEncoder.staticTable
        if index <= staticTable.count { return staticTable[index - 1] }
        let dynamicIndex = index - staticTable.count - 1
        if dynamicIndex >= dynamicTable.count { return nil }
        return dynamicTable[dynamicIndex]
    }

    private func decodeLiteral(_ cursor: inout HpackCursor, prefixBits: Int) -> HpackHeader? {
        guard let nameIndex = cursor.decodeInteger(prefixBits: prefixBits) else { return nil }
        let name: String
        if nameIndex == 0 {
            guard let literal = cursor.decodeString() else { return nil }
            name = literal
        } else {
            guard let entry = lookup(nameIndex) else { return nil }
            name = entry.name
        }
        guard let value = cursor.decodeString() else { return nil }
        return HpackHeader(name, value)
    }
}
