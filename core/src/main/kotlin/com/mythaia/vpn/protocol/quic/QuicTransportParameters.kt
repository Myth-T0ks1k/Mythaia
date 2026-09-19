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
                val value = QuicVarInt.decode(bytes, at) ?: return null
                // A parameter whose body is longer than the varint inside it is
                // malformed; the length must frame the value exactly.
                if (value.size != length.value.toInt()) return null
                out.add(QuicTuning.TransportParameter(id.value.toInt(), value.value))
            }
            at = end
        }

        return out
    }

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
