package com.mythaia.vpn.protocol.quic

/**
 * The `quic_transport_parameters` TLS extension (RFC 9000 §18).
 *
 * QUIC settles its transport limits inside the TLS handshake rather than in
 * band: the client's are an extension in its ClientHello, the server's come
 * back in EncryptedExtensions. The encoding is uniform — a varint identifier,
 * a varint length, then that many bytes — and for the integer parameters the
 * value is itself a varint, which is why a window of 64 MiB costs four bytes
 * rather than eight.
 *
 * Kept apart from [QuicTuning], which decides *what* to advertise: this only
 * decides how it looks on the wire.
 */
object QuicTransportParameters {

    /**
     * The extension identifier, 0x39.
     *
     * Not to be confused with the 0xffa5 that draft implementations used; a
     * server that only knows the draft number will ignore an extension sent
     * under this one, and the handshake fails with no useful diagnostic.
     */
    const val EXTENSION_TYPE = 0x0039

    /**
     * Encodes [parameters] into the extension body.
     *
     * A parameter with a null value is a flag — `disable_active_migration` is
     * the one in use — and is written with a zero length rather than omitted,
     * because presence is what carries its meaning.
     */
    fun encode(parameters: List<QuicTuning.TransportParameter>): ByteArray {
        var size = 0
        for (parameter in parameters) {
            val valueSize = parameter.value?.let { QuicVarInt.sizeOf(it) } ?: 0
            size += QuicVarInt.sizeOf(parameter.id.toLong()) +
                QuicVarInt.sizeOf(valueSize.toLong()) +
                valueSize
        }

        val out = ByteArray(size)
        var at = 0
        for (parameter in parameters) {
            at += QuicVarInt.write(out, at, parameter.id.toLong())
            val value = parameter.value
            if (value == null) {
                at += QuicVarInt.write(out, at, 0)
            } else {
                val valueSize = QuicVarInt.sizeOf(value)
                at += QuicVarInt.write(out, at, valueSize.toLong())
                at += QuicVarInt.write(out, at, value)
            }
        }
        return out
    }

    /**
     * Decodes what a peer advertised, or null when the bytes are malformed.
     *
     * Null rather than an exception: a peer that sends nonsense here is a
     * connection to abandon, not a crash to propagate. A parameter this build
     * does not recognise is kept rather than dropped — the caller may know
     * about it, and RFC 9000 §18.1 requires unknown ones to be ignored rather
     * than treated as an error.
     */
    fun decode(bytes: ByteArray): List<QuicTuning.TransportParameter>? {
        val out = ArrayList<QuicTuning.TransportParameter>()
        var at = 0

        while (at < bytes.size) {
            val id = QuicVarInt.decode(bytes, at) ?: return null
            at += id.size

            val length = QuicVarInt.decode(bytes, at) ?: return null
            at += length.size

            val end = at + length.value.toInt()
            if (length.value < 0 || end > bytes.size) return null

            if (length.value == 0L) {
                out.add(QuicTuning.TransportParameter(id.value.toInt(), null))
            } else {
                val value = QuicVarInt.decode(bytes, at)
                val framed = value != null && value.size == length.value.toInt()
                when {
                    // An integer parameter whose length does not frame its
                    // varint exactly is malformed.
                    id.value in INTEGER_IDS -> {
                        if (!framed) return null
                        out.add(QuicTuning.TransportParameter(id.value.toInt(), value!!.value))
                    }
                    // Connection ids, the stateless reset token,
                    // preferred_address and version_information are opaque
                    // bytes, listed without a value; ngtcp2 decodes the same
                    // bytes itself and enforces the rules for them.
                    id.value in OPAQUE_IDS -> out.add(QuicTuning.TransportParameter(id.value.toInt(), null))
                    // An unknown parameter is kept (RFC 9000 §18.1), with its
                    // value when it happens to be a varint.
                    else -> out.add(QuicTuning.TransportParameter(id.value.toInt(), if (framed) value!!.value else null))
                }
            }
            at = end
        }

        return out
    }

    /** RFC 9000 §18.2 and RFC 9368 parameters whose value is opaque bytes. */
    private val OPAQUE_IDS: Set<Long> = setOf(
        0x00L, // original_destination_connection_id
        0x02L, // stateless_reset_token
        0x0dL, // preferred_address
        0x0fL, // initial_source_connection_id
        0x10L, // retry_source_connection_id
        0x11L  // version_information
    )

    /** RFC 9000 §18.2 and RFC 9221 parameters whose value is a varint. */
    private val INTEGER_IDS: Set<Long> = setOf(
        0x01L, // max_idle_timeout
        0x03L, // max_udp_payload_size
        0x04L, // initial_max_data
        0x05L, // initial_max_stream_data_bidi_local
        0x06L, // initial_max_stream_data_bidi_remote
        0x07L, // initial_max_stream_data_uni
        0x08L, // initial_max_streams_bidi
        0x09L, // initial_max_streams_uni
        0x0aL, // ack_delay_exponent
        0x0bL, // max_ack_delay
        0x0eL, // active_connection_id_limit
        0x20L  // max_datagram_frame_size
    )

    /** Wraps an encoded body as a TLS extension: type, length, body. */
    fun asExtension(body: ByteArray): ByteArray {
        val out = ByteArray(4 + body.size)
        out[0] = (EXTENSION_TYPE ushr 8).toByte()
        out[1] = EXTENSION_TYPE.toByte()
        out[2] = (body.size ushr 8).toByte()
        out[3] = body.size.toByte()
        body.copyInto(out, 4)
        return out
    }
}
