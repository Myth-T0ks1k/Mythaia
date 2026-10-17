import Foundation

/// The `quic_transport_parameters` TLS extension (RFC 9000 §18).
///
/// QUIC settles its transport limits inside the TLS handshake rather than in
/// band: the client's are an extension in its ClientHello, the server's come
/// back in EncryptedExtensions. The encoding is uniform — a varint identifier,
/// a varint length, then that many bytes — and for the integer parameters the
/// value is itself a varint, which is why a window of 64 MiB costs four bytes
/// rather than eight.
///
/// Kept apart from `QuicTuning`, which decides *what* to advertise: this only
/// decides how it looks on the wire.
enum QuicTransportParameters {
    /// The extension identifier, 0x39.
    ///
    /// Not to be confused with the 0xffa5 that draft implementations used; a
    /// server that only knows the draft number will ignore an extension sent
    /// under this one, and the handshake fails with no useful diagnostic.
    static let extensionType = 0x0039

    /// Encodes `parameters` into the extension body.
    ///
    /// A parameter with a nil value is a flag — `disable_active_migration` is
    /// the one in use — and is written with a zero length rather than
    /// omitted, because presence is what carries its meaning.
    static func encode(_ parameters: [QuicTuning.TransportParameter]) -> [UInt8] {
        var out: [UInt8] = []
        for parameter in parameters {
            QuicVarInt.append(Int64(parameter.id), to: &out)
            if let value = parameter.value {
                QuicVarInt.append(Int64(QuicVarInt.sizeOf(value)), to: &out)
                QuicVarInt.append(value, to: &out)
            } else {
                QuicVarInt.append(0, to: &out)
            }
        }
        return out
    }

    /// Decodes what a peer advertised, or nil when the bytes are malformed.
    ///
    /// Nil rather than an error: a peer that sends nonsense here is a
    /// connection to abandon. A parameter this build does not recognise is
    /// kept rather than dropped — RFC 9000 §18.1 requires unknown ones to be
    /// ignored rather than treated as an error.
    static func decode(_ bytes: [UInt8]) -> [QuicTuning.TransportParameter]? {
        var out: [QuicTuning.TransportParameter] = []
        var at = 0
        while at < bytes.count {
            guard let id = QuicVarInt.decode(bytes, at) else { return nil }
            at += id.size
            guard let length = QuicVarInt.decode(bytes, at) else { return nil }
            at += length.size
            if length.value < 0 || length.value > Int64(bytes.count - at) { return nil }
            let end = at + Int(length.value)

            if length.value == 0 {
                out.append(QuicTuning.TransportParameter(id: Int(id.value), value: nil))
            } else {
                let value = QuicVarInt.decode(Array(bytes[at..<end]))
                let framed = value != nil && value!.size == Int(length.value)
                if integerIds.contains(id.value) {
                    // An integer parameter whose length does not frame its
                    // varint exactly is malformed.
                    guard framed, let decoded = value else { return nil }
                    out.append(QuicTuning.TransportParameter(id: Int(id.value), value: decoded.value))
                } else if opaqueIds.contains(id.value) {
                    // Connection ids, the stateless reset token,
                    // preferred_address and version_information are opaque
                    // bytes, listed without a value; ngtcp2 decodes the same
                    // bytes itself and enforces the rules for them.
                    out.append(QuicTuning.TransportParameter(id: Int(id.value), value: nil))
                } else {
                    // An unknown parameter is kept (RFC 9000 §18.1), with its
                    // value when it happens to be a varint.
                    out.append(QuicTuning.TransportParameter(id: Int(id.value), value: framed ? value!.value : nil))
                }
            }
            at = end
        }
        return out
    }

    /// RFC 9000 §18.2 and RFC 9368 parameters whose value is opaque bytes.
    private static let opaqueIds: Set<Int64> = [
        0x00, // original_destination_connection_id
        0x02, // stateless_reset_token
        0x0d, // preferred_address
        0x0f, // initial_source_connection_id
        0x10, // retry_source_connection_id
        0x11, // version_information
    ]

    /// RFC 9000 §18.2 and RFC 9221 parameters whose value is a varint.
    private static let integerIds: Set<Int64> = [
        0x01, // max_idle_timeout
        0x03, // max_udp_payload_size
        0x04, // initial_max_data
        0x05, // initial_max_stream_data_bidi_local
        0x06, // initial_max_stream_data_bidi_remote
        0x07, // initial_max_stream_data_uni
        0x08, // initial_max_streams_bidi
        0x09, // initial_max_streams_uni
        0x0a, // ack_delay_exponent
        0x0b, // max_ack_delay
        0x0e, // active_connection_id_limit
        0x20, // max_datagram_frame_size
    ]

    /// Wraps an encoded body as a TLS extension: type, length, body.
    static func asExtension(_ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [
            UInt8(truncatingIfNeeded: extensionType >> 8),
            UInt8(truncatingIfNeeded: extensionType),
            UInt8(truncatingIfNeeded: body.count >> 8),
            UInt8(truncatingIfNeeded: body.count),
        ]
        out.append(contentsOf: body)
        return out
    }
}
