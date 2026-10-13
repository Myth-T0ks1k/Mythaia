package com.mythaia.vpn.protocol.grpc

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * gRPC transport configuration.
 *
 *  - [serviceName] has two interpretations:
 *    * Plain name (e.g. `"example"`) — standard stream names `Tun` / `TunMulti` are used;
 *      path becomes `/<serviceName>/Tun` (or `/TunMulti`).
 *    * Custom path (starts with `/`, e.g. `"/my/service/TunName"`) — treated as the full
 *      path; segments are URL-path-escaped.
 *  - [authority] is the HTTP/2 `:authority` header; when empty it is derived from the TLS
 *    SNI / Reality server name / server address at dial time.
 *  - [multiMode] toggles the `TunMulti` stream (MultiHunk) instead of `Tun` (Hunk). A single
 *    Hunk is wire-compatible with a one-element MultiHunk, so encoding always emits one
 *    data element per message regardless of mode.
 */
@Serializable
data class GrpcConfiguration(
    val serviceName: String = "",
    val authority: String = "",
    val multiMode: Boolean = false,
    val userAgent: String = "",
    @SerialName("initialWindowsSize") val initialWindowsSize: Int = 0,
    val idleTimeout: Int = 0,
    val healthCheckTimeout: Int = 0,
    val permitWithoutStream: Boolean = false
) {
    companion object {
        /** Default gRPC service name used when [serviceName] is empty. */
        const val DEFAULT_SERVICE_NAME = "xray.transport.internet.grpc.encoding.GRPCService"

        fun parse(params: Map<String, String>): GrpcConfiguration {
            val mode = (params["mode"] ?: "gun").lowercase()
            val permit = params["permit_without_stream"]?.let { it != "false" && it != "0" } ?: false
            return GrpcConfiguration(
                serviceName = params["serviceName"] ?: "",
                authority = params["authority"] ?: "",
                multiMode = mode == "multi",
                userAgent = params["userAgent"] ?: "",
                initialWindowsSize = params["initial_windows_size"]?.toIntOrNull() ?: 0,
                idleTimeout = params["idle_timeout"]?.toIntOrNull() ?: 0,
                healthCheckTimeout = params["health_check_timeout"]?.toIntOrNull() ?: 0,
                permitWithoutStream = permit
            )
        }
    }

    /**
     * HTTP/2 `:authority` value. Priority: explicit config → TLS SNI → Reality SNI → server.
     */
    fun resolvedAuthority(
        tlsServerName: String?,
        realityServerName: String?,
        serverAddress: String
    ): String {
        if (authority.isNotEmpty()) return authority
        if (!tlsServerName.isNullOrEmpty()) return tlsServerName
        if (!realityServerName.isNullOrEmpty()) return realityServerName
        return serverAddress
    }

    /**
     * HTTP/2 `:path` value for this transport.
     *  - Plain [serviceName]: path = `/<url-escaped serviceName>/Tun` (or `/TunMulti`).
     *  - [serviceName] starting with `/`: treated as a full custom path. The part between
     *    the first and last `/` becomes the service path (each segment URL-escaped); the
     *    part after the last `/` is the stream name. For multi mode, if the last segment
     *    contains `|`, the first half is Tun and the second is TunMulti.
     */
    fun resolvedPath(): String {
        val name = serviceName.ifEmpty { DEFAULT_SERVICE_NAME }
        if (!name.startsWith("/")) {
            val stream = if (multiMode) "TunMulti" else "Tun"
            return "/${urlPathEscape(name)}/$stream"
        }

        // As Xray's getServiceName: a lone leading slash is both ends of the service part.
        val lastSlash = name.lastIndexOf('/').coerceAtLeast(1)
        val serviceRaw = name.substring(1, lastSlash)
        val endingPath = name.substring(lastSlash + 1)

        val servicePart = serviceRaw
            .split('/')
            .joinToString("/") { urlPathEscape(it) }

        val streamName: String = if (multiMode) {
            val parts = endingPath.split('|')
            if (parts.size >= 2) parts[1] else parts[0]
        } else {
            endingPath.split('|')[0]
        }

        val prefix = if (servicePart.isEmpty()) "" else "/$servicePart"
        return "$prefix/${urlPathEscape(streamName)}"
    }

    /**
     * Go's `url.PathEscape`, which Xray applies to each segment of the service
     * name, exactly: unreserved characters (RFC 3986 §2.3: letters, digits,
     * `-_.~`) and the sub-delims `$&+:=@` stay; `/;,?` and every other byte of
     * the UTF-8 form are percent-encoded, uppercase hex. `URLEncoder` is the
     * form encoding, which escapes `~`, `@`, `:` and friends and keeps `*`, so
     * a service name with any of them asked for a path the server did not serve.
     */
    internal fun urlPathEscape(value: String): String {
        val out = StringBuilder(value.length)
        for (b in value.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            val keep = c < 0x80 && (
                ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' ||
                    ch in "-_.~" || ch in "\$&+:=@"
                )
            if (keep) {
                out.append(ch)
            } else {
                out.append('%').append(HEX[c shr 4]).append(HEX[c and 0xF])
            }
        }
        return out.toString()
    }

    private val HEX = "0123456789ABCDEF"
}

/** gRPC transport errors. */
sealed class GrpcError(message: String) : Exception(message) {
    class SetupFailed(reason: String) : GrpcError("gRPC setup failed: $reason")
    class ConnectionClosed : GrpcError("gRPC connection closed")
    class InvalidResponse(reason: String) : GrpcError("gRPC invalid response: $reason")
    class CompressedMessageUnsupported : GrpcError("gRPC compressed messages are not supported")
    class CallFailed(val status: Int, val statusName: String, val detail: String?) : GrpcError(
        if (detail.isNullOrEmpty()) "gRPC call failed: $statusName ($status)"
        else "gRPC call failed: $statusName ($status) — $detail"
    )
}
