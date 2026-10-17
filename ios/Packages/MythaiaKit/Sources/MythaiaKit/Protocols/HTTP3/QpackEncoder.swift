import Foundation

/// One HTTP/3 field line: a lowercase name and its value.
struct Http3Field: Equatable {
    let name: String
    let value: String
}

/// QPACK field-section coding for HTTP/3 (RFC 9204).
///
/// HTTP/3 cannot reuse HPACK because QUIC delivers streams out of order, so
/// QPACK splits compression into a static table plus an optional dynamic table
/// on its own streams. This client advertises
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, so the dynamic table is never
/// populated in either direction: every field line we send resolves against
/// the static table or carries its own bytes, and a dynamic reference from a
/// peer is a protocol violation rather than something to look up. That keeps
/// this a pure function of bytes, testable against the RFC's own values.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
enum QpackEncoder {
    /// The largest value a prefixed integer may carry, 2^62 - 1 (RFC 9204 §4.1.1).
    static let maxInteger: Int64 = 4_611_686_018_427_387_903

    /// Entries in the RFC 9204 Appendix A static table, indexed 0...98.
    static let staticTableSize = 99

    // The static entries this client emits by index. Named because a bare 23
    // in a header block is unreadable and silently wrong if misremembered.
    private static let indexAuthority = 0
    private static let indexPath = 1
    private static let indexMethodConnect = 15
    private static let indexMethodGet = 17
    private static let indexMethodPost = 20
    private static let indexSchemeHttps = 23

    /// A decoded prefixed integer and the number of bytes it occupied.
    struct PrefixedInteger: Equatable {
        let value: Int64
        let size: Int
    }

    // MARK: - Encoding

    /// The field section of a CONNECT request. Classic CONNECT carries only
    /// `:method` and `:authority`; a `protocolPseudo` switches to extended
    /// CONNECT (RFC 9220), where `:protocol`, `:scheme` and `:path` all
    /// become mandatory, which is why they are emitted together.
    static func encodeConnectHeaders(authority: String, protocolPseudo: String? = nil, path: String? = nil,
                                     extraHeaders: [Http3Field] = []) -> [UInt8] {
        var block: [UInt8] = [0x00, 0x00]
        block.append(contentsOf: indexedFieldLine(indexMethodConnect))
        if let protocolPseudo = protocolPseudo {
            block.append(contentsOf: literalFieldLine(name: ":protocol", value: protocolPseudo))
            block.append(contentsOf: indexedFieldLine(indexSchemeHttps))
            block.append(contentsOf: literalFieldLineWithNameReference(indexPath, value: path ?? "/"))
        }
        block.append(contentsOf: literalFieldLineWithNameReference(indexAuthority, value: authority))
        for field in extraHeaders {
            block.append(contentsOf: literalFieldLine(name: field.name, value: field.value))
        }
        return block
    }

    /// The field section of a POST request.
    static func encodePostHeaders(authority: String, path: String, extraHeaders: [Http3Field] = []) -> [UInt8] {
        return encodeRequestHeaders(method: "POST", authority: authority, path: path, extraHeaders: extraHeaders)
    }

    /// The field section of a request with an arbitrary method. GET and POST
    /// have static entries and cost one byte; anything else is spelled out.
    static func encodeRequestHeaders(method: String, authority: String, path: String,
                                     extraHeaders: [Http3Field] = []) -> [UInt8] {
        // The field section prefix (RFC 9204 §4.5.1): Required Insert Count 0
        // and Delta Base 0, two zero bytes for as long as the dynamic table
        // stays empty.
        var block: [UInt8] = [0x00, 0x00]
        switch method.uppercased() {
        case "GET": block.append(contentsOf: indexedFieldLine(indexMethodGet))
        case "POST": block.append(contentsOf: indexedFieldLine(indexMethodPost))
        default: block.append(contentsOf: literalFieldLine(name: ":method", value: method))
        }
        block.append(contentsOf: indexedFieldLine(indexSchemeHttps))
        block.append(contentsOf: literalFieldLineWithNameReference(indexAuthority, value: authority))
        block.append(contentsOf: literalFieldLineWithNameReference(indexPath, value: path))
        for field in extraHeaders {
            block.append(contentsOf: literalFieldLine(name: field.name, value: field.value))
        }
        return block
    }

    /// Indexed field line (RFC 9204 §4.5.2): `1 T index(6+)`, T=1 for static.
    private static func indexedFieldLine(_ index: Int) -> [UInt8] {
        return encodePrefixedInteger(Int64(index), prefixBits: 6, prefix: 0xC0)
    }

    /// Literal field line with name reference (RFC 9204 §4.5.4):
    /// `01 N T index(4+)` then the value; N=0, T=1 (static table).
    private static func literalFieldLineWithNameReference(_ staticIndex: Int, value: String) -> [UInt8] {
        return encodePrefixedInteger(Int64(staticIndex), prefixBits: 4, prefix: 0x50) + encodeStringLiteral(value)
    }

    /// Literal field line with literal name (RFC 9204 §4.5.6):
    /// `001 N H len(3+)` then the name, then the value. The name is lowercased
    /// because RFC 9114 §4.2 makes an uppercase field name malformed.
    private static func literalFieldLine(name: String, value: String) -> [UInt8] {
        let nameBytes = Array(name.lowercased().utf8)
        return encodePrefixedInteger(Int64(nameBytes.count), prefixBits: 3, prefix: 0x20) + nameBytes + encodeStringLiteral(value)
    }

    /// String literal (RFC 9204 §4.1.2), H=0: sending raw is always legal,
    /// and the decoder below still accepts Huffman from peers.
    private static func encodeStringLiteral(_ string: String) -> [UInt8] {
        let bytes = Array(string.utf8)
        return encodePrefixedInteger(Int64(bytes.count), prefixBits: 7, prefix: 0x00) + bytes
    }

    // MARK: - Prefixed integers

    /// The QPACK prefixed integer of RFC 9204 §4.1.1: `prefixBits` low bits of
    /// the first byte hold the value, and once they are all ones the rest
    /// spills into 7-bit continuation bytes. `prefix` supplies the pattern
    /// bits above. This is NOT the QUIC varint, though the two sit bytes apart
    /// on the wire: 15293 is `7b bd` as a varint and `1f 9e 77` as a 5-bit
    /// prefixed integer, and mixing them up decodes into plausible nonsense.
    static func encodePrefixedInteger(_ value: Int64, prefixBits: Int, prefix: Int) -> [UInt8] {
        let bits = min(max(prefixBits, 1), 8)
        let clamped = min(max(value, 0), maxInteger)
        let maxPrefix = Int64((1 << bits) - 1)
        if clamped < maxPrefix {
            return [UInt8(truncatingIfNeeded: Int64(prefix) | clamped)]
        }
        var out: [UInt8] = [UInt8(truncatingIfNeeded: Int64(prefix) | maxPrefix)]
        var remaining = clamped - maxPrefix
        while remaining >= 128 {
            out.append(UInt8(truncatingIfNeeded: (remaining & 0x7F) | 0x80))
            remaining >>= 7
        }
        out.append(UInt8(truncatingIfNeeded: remaining))
        return out
    }

    /// Reads a prefixed integer at `offset`, or nil when the buffer stops
    /// short or the value cannot be represented. Room is checked before each
    /// shift so a hostile run of continuation bytes cannot wrap the value.
    static func decodePrefixedInteger(_ data: [UInt8], offset: Int, prefixBits: Int) -> PrefixedInteger? {
        if prefixBits < 1 || prefixBits > 8 { return nil }
        if offset < 0 || offset >= data.count { return nil }
        let mask = (1 << prefixBits) - 1
        let first = Int(data[offset]) & mask
        if first < mask { return PrefixedInteger(value: Int64(first), size: 1) }

        var value = Int64(mask)
        var shift: Int64 = 0
        var position = offset + 1
        while position < data.count {
            let byte = Int64(data[position])
            let addend = byte & 0x7F
            if shift > 62 || (maxInteger >> shift) < addend { return nil }
            let shifted = addend << shift
            if maxInteger - shifted < value { return nil }
            value += shifted
            position += 1
            if byte & 0x80 == 0 { return PrefixedInteger(value: value, size: position - offset) }
            shift += 7
        }
        return nil
    }

    // MARK: - Decoding

    /// Decodes a field section, or nil when it is malformed or references the
    /// dynamic table. A dynamic reference is refused rather than ignored: we
    /// advertised a capacity of zero, so a peer that sends one has lost track
    /// of the connection state or is trying to desynchronise us.
    static func decodeHeaders(_ data: [UInt8]) -> [Http3Field]? {
        if data.count < 2 { return nil }
        var headers: [Http3Field] = []
        var offset = 0

        // Required Insert Count must be zero for us.
        guard let requiredInsertCount = decodePrefixedInteger(data, offset: offset, prefixBits: 8),
              requiredInsertCount.value == 0 else { return nil }
        offset += requiredInsertCount.size
        // Delta Base: a sign bit above a 7-bit prefix; only its width matters.
        guard let deltaBase = decodePrefixedInteger(data, offset: offset, prefixBits: 7) else { return nil }
        offset += deltaBase.size

        while offset < data.count {
            let first = Int(data[offset])
            if first & 0x80 != 0 {
                // Indexed field line: 1 T index(6+). T=0 is the dynamic table.
                if first & 0x40 == 0 { return nil }
                guard let index = decodePrefixedInteger(data, offset: offset, prefixBits: 6),
                      let entry = staticTableEntry(index.value) else { return nil }
                offset += index.size
                headers.append(entry)
            } else if first & 0x40 != 0 {
                // Literal with name reference: 01 N T index(4+) value.
                if first & 0x10 == 0 { return nil }
                guard let nameIndex = decodePrefixedInteger(data, offset: offset, prefixBits: 4),
                      let entry = staticTableEntry(nameIndex.value) else { return nil }
                offset += nameIndex.size
                guard let value = decodeStringLiteral(data, offset: offset) else { return nil }
                offset += value.size
                headers.append(Http3Field(name: entry.name, value: value.text))
            } else if first & 0x20 != 0 {
                // Literal with literal name: 001 N H nameLen(3+) name value.
                let nameIsHuffman = first & 0x08 != 0
                guard let nameLength = decodePrefixedInteger(data, offset: offset, prefixBits: 3) else { return nil }
                offset += nameLength.size
                guard let name = readText(data, offset: offset, length: nameLength.value, huffman: nameIsHuffman) else { return nil }
                offset += Int(nameLength.value)
                guard let value = decodeStringLiteral(data, offset: offset) else { return nil }
                offset += value.size
                headers.append(Http3Field(name: name, value: value.text))
            } else {
                // 0001xxxx and 0000xxxx are the post-base forms, which exist
                // only to reference entries inserted after the base.
                return nil
            }
        }
        return headers
    }

    private static func decodeStringLiteral(_ data: [UInt8], offset: Int) -> (text: String, size: Int)? {
        if offset < 0 || offset >= data.count { return nil }
        let huffman = data[offset] & 0x80 != 0
        guard let length = decodePrefixedInteger(data, offset: offset, prefixBits: 7) else { return nil }
        let start = offset + length.size
        guard let text = readText(data, offset: start, length: length.value, huffman: huffman) else { return nil }
        return (text, length.size + Int(length.value))
    }

    private static func readText(_ data: [UInt8], offset: Int, length: Int64, huffman: Bool) -> String? {
        if offset < 0 || length < 0 || length > Int64(data.count - offset) { return nil }
        let slice = Array(data[offset..<(offset + Int(length))])
        // QPACK reuses HPACK's Huffman code verbatim (RFC 9204 §4.1.2 points
        // at RFC 7541 Appendix B), so the HTTP/2 table is the same table.
        let bytes: [UInt8]
        if huffman {
            guard let decoded = HpackHuffman.decode(slice) else { return nil }
            bytes = decoded
        } else {
            bytes = slice
        }
        // Strict UTF-8: a field that silently mutates is worse than a failure.
        return HysteriaProtocol.strictUtf8(bytes)
    }

    // MARK: - Static table

    /// The entry at `index`, or nil outside RFC 9204 Appendix A.
    static func staticTableEntry(_ index: Int64) -> Http3Field? {
        guard index >= 0 && index < Int64(staticTable.count) else { return nil }
        let entry = staticTable[Int(index)]
        return Http3Field(name: entry.0, value: entry.1)
    }

    /// RFC 9204 Appendix A, complete and in index order: a peer may reference
    /// any of it, and an entry this client cannot resolve is a field line
    /// that would go missing. Values are reproduced exactly, whitespace
    /// inconsistencies included, since they are compared as bytes.
    private static let staticTable: [(String, String)] = [
        (":authority", ""),
        (":path", "/"),
        ("age", "0"),
        ("content-disposition", ""),
        ("content-length", "0"),
        ("cookie", ""),
        ("date", ""),
        ("etag", ""),
        ("if-modified-since", ""),
        ("if-none-match", ""),
        ("last-modified", ""),
        ("link", ""),
        ("location", ""),
        ("referer", ""),
        ("set-cookie", ""),
        (":method", "CONNECT"),
        (":method", "DELETE"),
        (":method", "GET"),
        (":method", "HEAD"),
        (":method", "OPTIONS"),
        (":method", "POST"),
        (":method", "PUT"),
        (":scheme", "http"),
        (":scheme", "https"),
        (":status", "103"),
        (":status", "200"),
        (":status", "304"),
        (":status", "404"),
        (":status", "503"),
        ("accept", "*/*"),
        ("accept", "application/dns-message"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-ranges", "bytes"),
        ("access-control-allow-headers", "cache-control"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-allow-origin", "*"),
        ("cache-control", "max-age=0"),
        ("cache-control", "max-age=2592000"),
        ("cache-control", "max-age=604800"),
        ("cache-control", "no-cache"),
        ("cache-control", "no-store"),
        ("cache-control", "public, max-age=31536000"),
        ("content-encoding", "br"),
        ("content-encoding", "gzip"),
        ("content-type", "application/dns-message"),
        ("content-type", "application/javascript"),
        ("content-type", "application/json"),
        ("content-type", "application/x-www-form-urlencoded"),
        ("content-type", "image/gif"),
        ("content-type", "image/jpeg"),
        ("content-type", "image/png"),
        ("content-type", "text/css"),
        ("content-type", "text/html; charset=utf-8"),
        ("content-type", "text/plain"),
        ("content-type", "text/plain;charset=utf-8"),
        ("range", "bytes=0-"),
        ("strict-transport-security", "max-age=31536000"),
        ("strict-transport-security", "max-age=31536000; includesubdomains"),
        ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        ("vary", "accept-encoding"),
        ("vary", "origin"),
        ("x-content-type-options", "nosniff"),
        ("x-xss-protection", "1; mode=block"),
        (":status", "100"),
        (":status", "204"),
        (":status", "206"),
        (":status", "302"),
        (":status", "400"),
        (":status", "403"),
        (":status", "421"),
        (":status", "425"),
        (":status", "500"),
        ("accept-language", ""),
        ("access-control-allow-credentials", "FALSE"),
        ("access-control-allow-credentials", "TRUE"),
        ("access-control-allow-headers", "*"),
        ("access-control-allow-methods", "get"),
        ("access-control-allow-methods", "get, post, options"),
        ("access-control-allow-methods", "options"),
        ("access-control-expose-headers", "content-length"),
        ("access-control-request-headers", "content-type"),
        ("access-control-request-method", "get"),
        ("access-control-request-method", "post"),
        ("alt-svc", "clear"),
        ("authorization", ""),
        ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        ("early-data", "1"),
        ("expect-ct", ""),
        ("forwarded", ""),
        ("if-range", ""),
        ("origin", ""),
        ("purpose", "prefetch"),
        ("server", ""),
        ("timing-allow-origin", "*"),
        ("upgrade-insecure-requests", "1"),
        ("user-agent", ""),
        ("x-forwarded-for", ""),
        ("x-frame-options", "deny"),
        ("x-frame-options", "sameorigin"),
    ]
}
