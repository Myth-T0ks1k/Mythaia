package com.mythaia.vpn

/**
 * What a VLESS or VMess dial waits for before it sends its request, so the
 * request and the client's opening bytes leave as one message; see
 * [TunnelConstants.firstDataWaitMs].
 *
 * Some servers read that first message as the client's TLS ClientHello and
 * close the connection when it is cut short. A browser's ClientHello with a
 * post-quantum key share is about 1.8 KB, two TCP segments, so dialling on
 * the first segment broke every HTTPS page in Chrome through such a server.
 */
object FirstData {

    /**
     * True once [size] bytes of [data] are worth sending with the request: any
     * bytes that are not a TLS handshake record, or a whole first TLS record.
     */
    fun isComplete(data: ByteArray, size: Int = data.size): Boolean {
        if (size <= 0) return false
        if (data[0] != TLS_HANDSHAKE) return true
        if (size < RECORD_HEADER) return false
        val length = ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
        return size >= RECORD_HEADER + length
    }

    private const val TLS_HANDSHAKE: Byte = 0x16
    private const val RECORD_HEADER = 5
}
