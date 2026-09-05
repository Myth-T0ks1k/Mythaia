package com.mythaia.data.model

import com.mythaia.vpn.util.base64UrlToByteArrayOrNull
import com.mythaia.vpn.util.hexToByteArrayOrNull
import com.mythaia.vpn.util.toBase64Url
import com.mythaia.vpn.util.toHex
import com.mythaia.vpn.protocol.shadowsocks.ShadowsocksCipher
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.UUID
import org.json.JSONObject

/**
 * Percent-decodes [s]: only `%XX` hex escapes are decoded; `+` stays literal
 * (unlike `URLDecoder.decode`, which treats `+` as a space per form-url-encoded
 * rules). VLESS/WebSocket share links follow standard URL percent-encoding, not
 * form encoding — a path like `/?ed=2048+xray` must stay byte-identical,
 * otherwise the HTTP upgrade request path differs for the same share link.
 */
internal fun percentDecode(s: String): String =
    URLDecoder.decode(s.replace("+", "%2B"), "UTF-8")

@Serializable
enum class TlsFingerprint(val raw: String) {
    @SerialName("chrome_133") CHROME_133("chrome_133"),
    @SerialName("firefox_148") FIREFOX_148("firefox_148"),
    @SerialName("safari_26") SAFARI_26("safari_26"),
    @SerialName("ios_14") IOS_14("ios_14"),
    @SerialName("edge_85") EDGE_85("edge_85"),
    @SerialName("android_11") ANDROID_11("android_11"),
    @SerialName("qq_11") QQ_11("qq_11"),
    @SerialName("360_7") BROWSER_360("360_7"),
    @SerialName("chrome_120") CHROME_120("chrome_120"),
    @SerialName("firefox_120") FIREFOX_120("firefox_120"),
    @SerialName("safari_16") SAFARI_16("safari_16"),
    @SerialName("edge_106") EDGE_106("edge_106"),
    @SerialName("random") RANDOM("random");

    val displayName: String
        get() = when (this) {
            CHROME_133 -> "Chrome 133"
            FIREFOX_148 -> "Firefox 148"
            SAFARI_26 -> "Safari 26"
            IOS_14 -> "iOS 14"
            EDGE_85 -> "Edge 85"
            ANDROID_11 -> "Android 11"
            QQ_11 -> "QQ 11"
            BROWSER_360 -> "360 Browser"
            CHROME_120 -> "Chrome 120"
            FIREFOX_120 -> "Firefox 120"
            SAFARI_16 -> "Safari 16"
            EDGE_106 -> "Edge 106"
            RANDOM -> "Random"
        }

    companion object {
        fun fromRaw(value: String): TlsFingerprint =
            entries.find { it.raw == value } ?: CHROME_133

        /**
         * Pool used when the user picks "Random". Android-only fingerprints
         * (ANDROID_11, QQ_11, BROWSER_360) are kept in the enum for backward
         * compatibility with previously imported share links but excluded from
         * the random pool.
         */
        val concreteFingerprints: List<TlsFingerprint> = entries.filter {
            it != RANDOM && it != ANDROID_11 && it != QQ_11 && it != BROWSER_360
        }

        /**
         * Picker entries for [com.mythaia.ui.proxy.ProxyEditorScreen].
         * Excludes Android-only fingerprints from the dropdown, but `fromRaw`
         * still resolves them when imported from URLs.
         */
        val pickerFingerprints: List<TlsFingerprint> = entries.filter {
            it != ANDROID_11 && it != QQ_11 && it != BROWSER_360
        }
    }
}

/**
 * Negotiated TLS protocol version. The numeric `value` matches the on-the-wire
 * protocol version field (RFC 5246/RFC 8446).
 */
@Serializable
enum class TlsVersion(val value: Int) {
    @SerialName("tls12") TLS12(0x0303),
    @SerialName("tls13") TLS13(0x0304);

    val displayName: String
        get() = when (this) {
            TLS12 -> "TLS 1.2"
            TLS13 -> "TLS 1.3"
        }

    /** Wire-compatible version string for URL query params (e.g. "1.2", "1.3"). */
    val urlValue: String
        get() = when (this) {
            TLS12 -> "1.2"
            TLS13 -> "1.3"
        }
}

@Serializable
data class TlsConfiguration(
    val serverName: String,
    val alpn: List<String>? = null,
    val allowInsecure: Boolean = false,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133,
    /** Minimum acceptable TLS version (null = no minimum, accept any). */
    val minVersion: TlsVersion? = null,
    /** Maximum acceptable TLS version (null = no maximum, accept any). */
    val maxVersion: TlsVersion? = null,
    /**
     * How this server's ClientHello goes out on a direct dial. Null means the
     * link carried no `fragment=`, so the tunnel-wide default applies — see
     * [com.mythaia.vpn.protocol.tls.FragmentPolicy].
     */
    val fragment: FragmentSettings? = null
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): TlsConfiguration? {
            if (params["security"] != "tls") return null
            val sni = params["sni"] ?: serverAddress
            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val allowInsecure = params["allowInsecure"] == "1" || params["allowInsecure"] == "true"
            val fp = params["fp"] ?: "chrome_133"
            val minVersion = parseTlsVersion(params["minVersion"])
            val maxVersion = parseTlsVersion(params["maxVersion"])
            val fragment = params["fragment"]?.let(FragmentSettings::fromShareLink)
            return TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = allowInsecure,
                fingerprint = TlsFingerprint.fromRaw(fp),
                minVersion = minVersion,
                maxVersion = maxVersion,
                fragment = fragment
            )
        }

        /** Parses a TLS version string ("1.0"–"1.3") into a [TlsVersion].
         *  "1.0" and "1.1" are legacy; treated as TLS 1.2 since Android does not implement deprecated versions. */
        private fun parseTlsVersion(version: String?): TlsVersion? = when (version) {
            "1.0", "1.1", "1.2" -> TlsVersion.TLS12
            "1.3" -> TlsVersion.TLS13
            else -> null
        }
    }
}

@Serializable
data class RealityConfiguration(
    val serverName: String,
    @Serializable(with = Base64UrlByteArraySerializer::class) val publicKey: ByteArray,
    @Serializable(with = HexByteArraySerializer::class) val shortId: ByteArray,
    val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RealityConfiguration) return false
        return serverName == other.serverName &&
                publicKey.contentEquals(other.publicKey) &&
                shortId.contentEquals(other.shortId) &&
                fingerprint == other.fingerprint
    }

    override fun hashCode(): Int {
        var result = serverName.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + shortId.contentHashCode()
        result = 31 * result + fingerprint.hashCode()
        return result
    }

    companion object {
        fun parse(params: Map<String, String>): RealityConfiguration? {
            if (params["security"] != "reality") return null
            val sni = params["sni"]?.takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("Missing Reality parameter: sni")
            val pbk = params["pbk"]?.takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("Missing Reality parameter: pbk (public key)")
            val publicKey = pbk.base64UrlToByteArrayOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid Reality public key")
            if (publicKey.size != 32) throw ProxyError.InvalidUrl("Invalid Reality public key")
            val shortId = (params["sid"] ?: "").hexToByteArrayOrNull() ?: byteArrayOf()
            val fp = params["fp"] ?: "chrome_133"
            return RealityConfiguration(
                serverName = sni,
                publicKey = publicKey,
                shortId = shortId,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )
        }
    }
}

@Serializable
data class WebSocketConfiguration(
    val host: String,
    val path: String = "/",
    val headers: Map<String, String> = emptyMap(),
    val maxEarlyData: Int = 0,
    val earlyDataHeaderName: String = "Sec-WebSocket-Protocol",
    val heartbeatPeriod: UInt = 0u
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): WebSocketConfiguration {
            val host = params["host"] ?: serverAddress
            val path = params["path"]?.let { percentDecode(it) } ?: "/"
            val maxEarlyData = params["ed"]?.toIntOrNull() ?: 0
            return WebSocketConfiguration(host = host, path = path, maxEarlyData = maxEarlyData)
        }
    }
}

@Serializable
data class HttpUpgradeConfiguration(
    val host: String,
    val path: String = "/",
    val headers: Map<String, String> = emptyMap()
) {
    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): HttpUpgradeConfiguration {
            val host = params["host"] ?: serverAddress
            var path = params["path"]?.let { percentDecode(it) } ?: "/"
            if (!path.startsWith("/")) path = "/$path"
            return HttpUpgradeConfiguration(host = host, path = path)
        }
    }
}

@Serializable
enum class XHttpMode(val raw: String) {
    @SerialName("auto") AUTO("auto"),
    @SerialName("stream-one") STREAM_ONE("stream-one"),
    @SerialName("packet-up") PACKET_UP("packet-up"),
    @SerialName("stream-up") STREAM_UP("stream-up");

    val displayName: String
        get() = when (this) {
            AUTO -> "Auto"
            STREAM_ONE -> "Stream One"
            PACKET_UP -> "Packet Up"
            STREAM_UP -> "Stream Up"
        }

    companion object {
        fun fromRaw(value: String): XHttpMode =
            entries.find { it.raw == value } ?: AUTO
    }
}

/** Metadata placement for session ID, sequence numbers, and padding. */
@Serializable
enum class XHttpPlacement(val raw: String) {
    @SerialName("path") PATH("path"),
    @SerialName("query") QUERY("query"),
    @SerialName("header") HEADER("header"),
    @SerialName("cookie") COOKIE("cookie"),
    @SerialName("queryInHeader") QUERY_IN_HEADER("queryInHeader"),
    @SerialName("body") BODY("body");

    companion object {
        fun fromRaw(value: String): XHttpPlacement =
            entries.find { it.raw == value } ?: QUERY_IN_HEADER
    }
}

/** X-Padding generation method. */
@Serializable
enum class XHttpPaddingMethod(val raw: String) {
    @SerialName("repeat-x") REPEAT_X("repeat-x"),
    @SerialName("tokenish") TOKENISH("tokenish");

    companion object {
        fun fromRaw(value: String): XHttpPaddingMethod =
            entries.find { it.raw == value } ?: REPEAT_X
    }
}

@Serializable
data class XHttpConfiguration(
    val host: String,
    val path: String = "/",
    val mode: XHttpMode = XHttpMode.AUTO,
    val headers: Map<String, String> = emptyMap(),
    @SerialName("noGRPCHeader") val noGrpcHeader: Boolean = false,
    val scMaxEachPostBytes: Int = 1_000_000,
    val scMinPostsIntervalMs: Int = 30,
    val xPaddingBytesFrom: Int = 100,
    val xPaddingBytesTo: Int = 1000,
    val xPaddingObfsMode: Boolean = false,
    val xPaddingKey: String = "x_padding",
    val xPaddingHeader: String = "X-Padding",
    val xPaddingPlacement: XHttpPlacement = XHttpPlacement.QUERY_IN_HEADER,
    val xPaddingMethod: XHttpPaddingMethod = XHttpPaddingMethod.REPEAT_X,
    val uplinkHTTPMethod: String = "POST",
    val sessionPlacement: XHttpPlacement = XHttpPlacement.PATH,
    val sessionKey: String = "",
    val seqPlacement: XHttpPlacement = XHttpPlacement.PATH,
    val seqKey: String = "",
    val uplinkDataPlacement: XHttpPlacement = XHttpPlacement.BODY,
    val uplinkDataKey: String = "",
    val uplinkChunkSize: Int = 0
) {
    val normalizedPath: String
        get() {
            val pathOnly = path.split("?", limit = 2).first()
            var p = pathOnly
            if (!p.startsWith("/")) p = "/$p"
            if (!p.endsWith("/")) p = "$p/"
            return p
        }

    val normalizedQuery: String
        get() {
            val parts = path.split("?", limit = 2)
            return if (parts.size > 1) parts[1] else ""
        }

    /** Normalized session key, auto-determined by placement if not set. */
    val normalizedSessionKey: String
        get() {
            if (sessionKey.isNotEmpty()) return sessionKey
            return when (sessionPlacement) {
                XHttpPlacement.HEADER -> "X-Session"
                XHttpPlacement.COOKIE, XHttpPlacement.QUERY -> "x_session"
                else -> ""
            }
        }

    /** Normalized seq key, auto-determined by placement if not set. */
    val normalizedSeqKey: String
        get() {
            if (seqKey.isNotEmpty()) return seqKey
            return when (seqPlacement) {
                XHttpPlacement.HEADER -> "X-Seq"
                XHttpPlacement.COOKIE, XHttpPlacement.QUERY -> "x_seq"
                else -> ""
            }
        }

    fun generatePadding(): String {
        val length = (xPaddingBytesFrom..xPaddingBytesTo).random()
        return when (xPaddingMethod) {
            XHttpPaddingMethod.REPEAT_X -> "X".repeat(length)
            XHttpPaddingMethod.TOKENISH -> generateTokenishPadding(length)
        }
    }

    fun toExtraJson(): String {
        val parts = mutableListOf<String>()
        if (noGrpcHeader) parts.add("\"noGRPCHeader\":true")
        if (scMaxEachPostBytes != 1_000_000) parts.add("\"scMaxEachPostBytes\":$scMaxEachPostBytes")
        if (scMinPostsIntervalMs != 30) parts.add("\"scMinPostsIntervalMs\":$scMinPostsIntervalMs")
        if (xPaddingBytesFrom != 100) parts.add("\"xPaddingBytesFrom\":$xPaddingBytesFrom")
        if (xPaddingBytesTo != 1000) parts.add("\"xPaddingBytesTo\":$xPaddingBytesTo")
        if (xPaddingObfsMode) parts.add("\"xPaddingObfsMode\":true")
        if (xPaddingKey != "x_padding") parts.add("\"xPaddingKey\":\"$xPaddingKey\"")
        if (xPaddingHeader != "X-Padding") parts.add("\"xPaddingHeader\":\"$xPaddingHeader\"")
        if (xPaddingPlacement != XHttpPlacement.QUERY_IN_HEADER) parts.add("\"xPaddingPlacement\":\"${xPaddingPlacement.raw}\"")
        if (xPaddingMethod != XHttpPaddingMethod.REPEAT_X) parts.add("\"xPaddingMethod\":\"${xPaddingMethod.raw}\"")
        if (uplinkHTTPMethod != "POST") parts.add("\"uplinkHTTPMethod\":\"$uplinkHTTPMethod\"")
        if (sessionPlacement != XHttpPlacement.PATH) parts.add("\"sessionPlacement\":\"${sessionPlacement.raw}\"")
        if (sessionKey.isNotEmpty()) parts.add("\"sessionKey\":\"$sessionKey\"")
        if (seqPlacement != XHttpPlacement.PATH) parts.add("\"seqPlacement\":\"${seqPlacement.raw}\"")
        if (seqKey.isNotEmpty()) parts.add("\"seqKey\":\"$seqKey\"")
        if (uplinkDataPlacement != XHttpPlacement.BODY) parts.add("\"uplinkDataPlacement\":\"${uplinkDataPlacement.raw}\"")
        if (uplinkDataKey.isNotEmpty()) parts.add("\"uplinkDataKey\":\"$uplinkDataKey\"")
        if (uplinkChunkSize != 0) parts.add("\"uplinkChunkSize\":$uplinkChunkSize")
        if (headers.isNotEmpty()) {
            val headersJson = headers.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }
            parts.add("\"headers\":{$headersJson}")
        }
        return if (parts.isEmpty()) "" else "{${parts.joinToString(",")}}"
    }

    companion object {
        fun parse(params: Map<String, String>, serverAddress: String): XHttpConfiguration {
            val host = params["host"] ?: serverAddress
            val path = params["path"]?.let { percentDecode(it) } ?: "/"
            val mode = XHttpMode.fromRaw(params["mode"] ?: "auto")
            val extra = params["extra"] ?: ""
            return if (extra.isNotBlank()) {
                fromExtraJson(host, path, mode, extra)
            } else {
                XHttpConfiguration(host = host, path = path, mode = mode)
            }
        }

        fun fromExtraJson(host: String, path: String, mode: XHttpMode, extraJson: String): XHttpConfiguration {
            if (extraJson.isBlank()) return XHttpConfiguration(host = host, path = path, mode = mode)
            return try {
                val json = org.json.JSONObject(extraJson)

                // scMaxEachPostBytes: can be int or {"from":N,"to":N}
                val scMaxEachPostBytes = json.opt("scMaxEachPostBytes").let { v ->
                    when (v) {
                        is org.json.JSONObject -> v.optInt("to", 1_000_000)
                        is Number -> v.toInt()
                        else -> 1_000_000
                    }
                }

                // scMinPostsIntervalMs: can be int or {"from":N,"to":N}
                val scMinPostsIntervalMs = json.opt("scMinPostsIntervalMs").let { v ->
                    when (v) {
                        is org.json.JSONObject -> v.optInt("to", 30)
                        is Number -> v.toInt()
                        else -> 30
                    }
                }

                // xPaddingBytes: can be int or {"from":N,"to":N}
                var xPaddingFrom = 100
                var xPaddingTo = 1000
                json.opt("xPaddingBytes")?.let { v ->
                    when (v) {
                        is org.json.JSONObject -> {
                            xPaddingFrom = v.optInt("from", 100)
                            xPaddingTo = v.optInt("to", 1000)
                        }
                        is Number -> {
                            xPaddingFrom = v.toInt()
                            xPaddingTo = v.toInt()
                        }
                    }
                }
                // Also accept flat xPaddingBytesFrom/xPaddingBytesTo keys
                if (!json.has("xPaddingBytes")) {
                    xPaddingFrom = json.optInt("xPaddingBytesFrom", xPaddingFrom)
                    xPaddingTo = json.optInt("xPaddingBytesTo", xPaddingTo)
                }

                val uplinkDataPlacement = XHttpPlacement.fromRaw(json.optString("uplinkDataPlacement", "body"))
                val defaultUplinkDataKey = when (uplinkDataPlacement) {
                    XHttpPlacement.HEADER -> "X-Data"
                    XHttpPlacement.COOKIE -> "x_data"
                    else -> ""
                }
                val defaultUplinkChunkSize = when (uplinkDataPlacement) {
                    XHttpPlacement.HEADER -> 4096
                    XHttpPlacement.COOKIE -> 3072
                    else -> 0
                }

                XHttpConfiguration(
                    host = host, path = path, mode = mode,
                    headers = json.optJSONObject("headers")?.let { h ->
                        h.keys().asSequence().associateWith { k -> h.optString(k, "") }
                    } ?: emptyMap(),
                    noGrpcHeader = json.optBoolean("noGRPCHeader", false),
                    scMaxEachPostBytes = scMaxEachPostBytes,
                    scMinPostsIntervalMs = scMinPostsIntervalMs,
                    xPaddingBytesFrom = xPaddingFrom,
                    xPaddingBytesTo = xPaddingTo,
                    xPaddingObfsMode = json.optBoolean("xPaddingObfsMode", false),
                    xPaddingKey = json.optString("xPaddingKey", "x_padding"),
                    xPaddingHeader = json.optString("xPaddingHeader", "X-Padding"),
                    xPaddingPlacement = XHttpPlacement.fromRaw(json.optString("xPaddingPlacement", "queryInHeader")),
                    xPaddingMethod = XHttpPaddingMethod.fromRaw(json.optString("xPaddingMethod", "repeat-x")),
                    uplinkHTTPMethod = json.optString("uplinkHTTPMethod", "POST"),
                    sessionPlacement = XHttpPlacement.fromRaw(json.optString("sessionPlacement", "path")),
                    sessionKey = json.optString("sessionKey", ""),
                    seqPlacement = XHttpPlacement.fromRaw(json.optString("seqPlacement", "path")),
                    seqKey = json.optString("seqKey", ""),
                    uplinkDataPlacement = uplinkDataPlacement,
                    uplinkDataKey = json.optString("uplinkDataKey", defaultUplinkDataKey),
                    uplinkChunkSize = json.optInt("uplinkChunkSize", defaultUplinkChunkSize)
                )
            } catch (_: Exception) {
                XHttpConfiguration(host = host, path = path, mode = mode)
            }
        }

        private val tokenishChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

        /**
         * Generates pseudo-random alphanumeric padding that looks like a token.
         * Target Huffman byte length: ceil(length / 0.8) to compensate for
         * HTTP/2 Huffman compression.
         */
        fun generateTokenishPadding(length: Int): String {
            val charCount = kotlin.math.ceil(length / 0.8).toInt()
            val sb = StringBuilder(charCount)
            val random = java.security.SecureRandom()
            for (i in 0 until charCount) {
                sb.append(tokenishChars[random.nextInt(tokenishChars.length)])
            }
            return sb.toString()
        }
    }
}

object UuidSerializer : KSerializer<UUID> {
    override val descriptor = PrimitiveSerialDescriptor("UUID", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: UUID) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder): UUID = UUID.fromString(decoder.decodeString())
}

object Base64UrlByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("Base64UrlByteArray", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.toBase64Url())
    override fun deserialize(decoder: Decoder): ByteArray =
        decoder.decodeString().base64UrlToByteArrayOrNull() ?: byteArrayOf()
}

object HexByteArraySerializer : KSerializer<ByteArray> {
    override val descriptor = PrimitiveSerialDescriptor("HexByteArray", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(value.toHex())
    override fun deserialize(decoder: Decoder): ByteArray =
        decoder.decodeString().hexToByteArrayOrNull() ?: byteArrayOf()
}

@Serializable(with = OutboundProtocolSerializer::class)
enum class OutboundProtocol(val raw: String) {
    VLESS("vless"),
    TROJAN("trojan"),
    SHADOWSOCKS("shadowsocks"),
    SOCKS5("socks5"),
    NAIVE_HTTP11("http11"),
    NAIVE_HTTP2("http2"),
    HYSTERIA2("hysteria2"),
    ANYTLS("anytls"),
    VMESS("vmess"),
    WIREGUARD("wireguard");

    val isNaive: Boolean get() = this == NAIVE_HTTP11 || this == NAIVE_HTTP2

    /**
     * Whether an outbound can actually be dialled yet.
     *
     * Links for these parse, round-trip and survive a subscription refresh, so
     * a subscription carrying them is not silently truncated — but dialling one
     * fails with a clear message instead of pretending.
     */
    // Every protocol here can now be dialled. The property stays because a
    // subscription may carry something a future build adds, and failing at the
    // dial with the name in the message beats a silent timeout.
    val isImplemented: Boolean get() = true

    /**
     * Whether this outbound is a layer-3 interface rather than a stream proxy.
     *
     * WireGuard carries whole IP packets, so it replaces the lwIP stack instead
     * of being dialled per flow. Domain routing rules do not apply to it — its
     * own AllowedIPs decide what enters the tunnel.
     */
    val isLayer3: Boolean get() = this == WIREGUARD

    val displayName: String
        get() = when (this) {
            VLESS -> "VLESS"
            TROJAN -> "Trojan"
            SHADOWSOCKS -> "Shadowsocks"
            SOCKS5 -> "SOCKS5"
            NAIVE_HTTP11 -> "HTTPS"
            NAIVE_HTTP2 -> "HTTP/2"
            HYSTERIA2 -> "Hysteria2"
            ANYTLS -> "AnyTLS"
            VMESS -> "VMess"
            WIREGUARD -> "WireGuard"
        }

    /**
     * Whether this protocol can embed the caller's first bytes inside its
     * outbound handshake. Only VLESS does — every other protocol opens the
     * tunnel first and the LWIP layer must forward the buffered first bytes
     * via a separate `connection.send` after connect (and ACK them back to
     * lwIP via `nativeTcpRecved`).
     *
     * Getting this wrong silently swallows the caller's first bytes for
     * non-VLESS protocols — the bytes are sent over the wire but lwIP never
     * ACKs them back to the local app, the app times out and sends RST.
     */
    val handshakeCarriesInitialData: Boolean
        get() = this == VLESS || this == VMESS
}

object OutboundProtocolSerializer : KSerializer<OutboundProtocol> {
    override val descriptor = PrimitiveSerialDescriptor("OutboundProtocol", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: OutboundProtocol) {
        encoder.encodeString(value.raw)
    }

    override fun deserialize(decoder: Decoder): OutboundProtocol {
        val raw = decoder.decodeString()
        return when (raw) {
            "vless" -> OutboundProtocol.VLESS
            "trojan" -> OutboundProtocol.TROJAN
            "shadowsocks" -> OutboundProtocol.SHADOWSOCKS
            "socks5" -> OutboundProtocol.SOCKS5
            "http11", "naive_http11" -> OutboundProtocol.NAIVE_HTTP11
            "http2", "naive_http2" -> OutboundProtocol.NAIVE_HTTP2
            "hysteria2", "hy2" -> OutboundProtocol.HYSTERIA2
            "anytls" -> OutboundProtocol.ANYTLS
            "vmess" -> OutboundProtocol.VMESS
            "wireguard", "wg", "awg", "amneziawg" -> OutboundProtocol.WIREGUARD
            else -> throw SerializationException("Unknown outbound protocol: $raw")
        }
    }
}

@Serializable
enum class NaiveProtocol {
    @SerialName("http11") HTTP11,
    @SerialName("http2") HTTP2
}

@Serializable
data class ProxyConfiguration(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    val name: String,
    val serverAddress: String,
    val serverPort: UShort,
    val resolvedIP: String? = null,
    @Serializable(with = UuidSerializer::class) val uuid: UUID,
    val encryption: String,
    val transport: String = "tcp",
    val flow: String? = null,
    val security: String = "none",
    val tls: TlsConfiguration? = null,
    val reality: RealityConfiguration? = null,
    val websocket: WebSocketConfiguration? = null,
    val httpUpgrade: HttpUpgradeConfiguration? = null,
    val xhttp: XHttpConfiguration? = null,
    val grpc: com.mythaia.vpn.protocol.grpc.GrpcConfiguration? = null,
    val testseed: List<UInt> = listOf(900u, 500u, 900u, 256u),
    val muxEnabled: Boolean = true,
    val xudpEnabled: Boolean = true,
    @Serializable(with = UuidSerializer::class) val subscriptionId: UUID? = null,
    val outboundProtocol: OutboundProtocol = OutboundProtocol.VLESS,
    val ssPassword: String? = null,
    val ssMethod: String? = null,
    val socks5Username: String? = null,
    val socks5Password: String? = null,
    val naiveUsername: String? = null,
    val naivePassword: String? = null,
    val naiveProtocol: NaiveProtocol? = null,
    val trojanPassword: String? = null,
    /** Trojan's mandatory TLS configuration. */
    val trojanTls: TlsConfiguration? = null,
    /** Hysteria2 and AnyTLS both authenticate with a single password. */
    val password: String? = null,
    /**
     * Hysteria2's declared bandwidth. Their presence is what selects Brutal
     * congestion control over BBR, so absence is information — left null
     * rather than defaulted.
     */
    val hysteriaUpMbps: Int? = null,
    val hysteriaDownMbps: Int? = null,
    /** Hysteria2 obfuscation, currently only `salamander`. */
    val obfuscation: String? = null,
    /**
     * VMess body cipher: `aes-128-gcm`, `chacha20-poly1305`, `none` or
     * `zero`. Null means the link said `auto`, or said nothing.
     */
    val vmessSecurity: String? = null,
    val obfuscationPassword: String? = null,
    /**
     * The peer's `wg-quick` INI, verbatim, for WireGuard and AmneziaWG.
     *
     * Kept as the text the user pasted rather than exploded into fields: it is
     * the format every peer hands out, it round-trips through export without
     * losing a key this build does not know yet, and it is what
     * [com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse] already reads.
     */
    val wireGuardConfig: String? = null,
    val chain: List<ProxyConfiguration>? = null
) {
    val connectAddress: String get() = resolvedIP ?: serverAddress

    /** RFC 3986 §3.2.2: IPv6 literals must be bracketed in URL authority components. */
    private val bracketedServerAddress: String
        get() = if (serverAddress.contains(":")) "[$serverAddress]" else serverAddress

    fun contentEquals(other: ProxyConfiguration): Boolean =
        name == other.name &&
                serverAddress == other.serverAddress &&
                serverPort == other.serverPort &&
                uuid == other.uuid &&
                encryption == other.encryption &&
                transport == other.transport &&
                flow == other.flow &&
                security == other.security &&
                tls == other.tls &&
                reality == other.reality &&
                websocket == other.websocket &&
                httpUpgrade == other.httpUpgrade &&
                xhttp == other.xhttp &&
                grpc == other.grpc &&
                testseed == other.testseed &&
                muxEnabled == other.muxEnabled &&
                xudpEnabled == other.xudpEnabled &&
                outboundProtocol == other.outboundProtocol &&
                ssPassword == other.ssPassword &&
                ssMethod == other.ssMethod &&
                socks5Username == other.socks5Username &&
                socks5Password == other.socks5Password &&
                naiveUsername == other.naiveUsername &&
                naivePassword == other.naivePassword &&
                naiveProtocol == other.naiveProtocol &&
                trojanPassword == other.trojanPassword &&
                trojanTls == other.trojanTls &&
                password == other.password &&
                hysteriaUpMbps == other.hysteriaUpMbps &&
                hysteriaDownMbps == other.hysteriaDownMbps &&
                obfuscation == other.obfuscation &&
                vmessSecurity == other.vmessSecurity &&
                obfuscationPassword == other.obfuscationPassword &&
                chain == other.chain

    fun withChain(chain: List<ProxyConfiguration>?): ProxyConfiguration = copy(chain = chain)

    fun toUrl(): String = when (outboundProtocol) {
        OutboundProtocol.VLESS -> toVlessUrl()
        OutboundProtocol.TROJAN -> toTrojanUrl()
        OutboundProtocol.SHADOWSOCKS -> toShadowsocksUrl()
        OutboundProtocol.SOCKS5 -> toSocks5Url()
        OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> toNaiveUrl()
        OutboundProtocol.HYSTERIA2 -> toHysteria2Url()
        OutboundProtocol.ANYTLS -> toAnyTlsUrl()
        OutboundProtocol.VMESS -> toVmessUrl()
        // WireGuard has no share-link scheme; peers hand out the INI itself,
        // so exporting one gives back exactly what was imported.
        OutboundProtocol.WIREGUARD -> wireGuardConfig.orEmpty()
    }

    /**
     * `hysteria2://password@host:port?…#name`.
     *
     * Always the long spelling: `hy2://` is an accepted alias on the way in,
     * and emitting the canonical scheme keeps a round trip stable.
     */
    private fun toHysteria2Url(): String {
        val params = mutableListOf<String>()
        tls?.let { appendPasswordProtocolTlsParams(params, it) }
        hysteriaUpMbps?.let { params.add("upmbps=$it") }
        hysteriaDownMbps?.let { params.add("downmbps=$it") }
        obfuscation?.let { params.add("obfs=$it") }
        obfuscationPassword?.let { params.add("obfs-password=${urlEncode(it)}") }

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        return "hysteria2://${urlEncode(password ?: "")}@$bracketedServerAddress:$serverPort" +
            "$query#${urlEncode(name)}"
    }

    /**
     * `vmess://` + base64 of the v2rayN JSON object.
     *
     * `v` is the object's own format version and is always 2; `aid` is always
     * 0, because that is the only header this client speaks.
     */
    private fun toVmessUrl(): String {
        val json = JSONObject()
        json.put("v", "2")
        json.put("ps", name)
        json.put("add", serverAddress)
        json.put("port", serverPort.toString())
        json.put("id", uuid.toString())
        json.put("aid", "0")
        json.put("scy", vmessSecurity ?: "auto")
        json.put("net", transport)
        json.put("type", "none")
        websocket?.let {
            json.put("path", it.path)
            json.put("host", it.host)
        }
        tls?.let {
            json.put("tls", "tls")
            json.put("sni", it.serverName)
            it.alpn?.takeIf { alpn -> alpn.isNotEmpty() }?.let { alpn ->
                json.put("alpn", alpn.joinToString(","))
            }
            json.put("fp", it.fingerprint.raw)
            // Without this a shared link silently turns certificate checking
            // back on, and the server the user could reach stops working.
            if (it.allowInsecure) json.put("allowInsecure", "true")
        } ?: json.put("tls", "")

        val encoded = java.util.Base64.getEncoder()
            .encodeToString(json.toString().toByteArray(Charsets.UTF_8))
        return "vmess://$encoded"
    }

    /** `anytls://password@host:port?sni=…&alpn=…&fp=…#name`. */
    private fun toAnyTlsUrl(): String {
        val params = mutableListOf<String>()
        tls?.let { appendPasswordProtocolTlsParams(params, it) }

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        return "anytls://${urlEncode(password ?: "")}@$bracketedServerAddress:$serverPort" +
            "$query#${urlEncode(name)}"
    }

    /**
     * The TLS query shared by the password-authenticated schemes.
     *
     * Separate from [appendTlsParams] because these links spell "do not verify"
     * `insecure=1`, not `allowInsecure=1`, and carry no version bounds.
     */
    private fun appendPasswordProtocolTlsParams(params: MutableList<String>, tls: TlsConfiguration) {
        if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
        tls.alpn?.takeIf { it.isNotEmpty() }?.let {
            params.add("alpn=${urlEncode(it.joinToString(","))}")
        }
        if (tls.fingerprint != TlsFingerprint.CHROME_133) params.add("fp=${tls.fingerprint.raw}")
        if (tls.allowInsecure) params.add("insecure=1")
    }

    private fun toTrojanUrl(): String {
        // Password in userinfo (whole chunk, no user:pass split), TLS
        // sni/alpn/fp optional in query.
        val password = urlEncode(trojanPassword ?: "")
        val params = mutableListOf<String>()
        trojanTls?.let { tls ->
            if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
            tls.alpn?.takeIf { it.isNotEmpty() }?.let {
                params.add("alpn=${urlEncode(it.joinToString(","))}")
            }
            if (tls.fingerprint != TlsFingerprint.CHROME_133) {
                params.add("fp=${tls.fingerprint.raw}")
            }
        }
        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "trojan://$password@$bracketedServerAddress:$serverPort$query#$fragment"
    }

    private fun toVlessUrl(): String {
        val params = mutableListOf<String>()
        if (encryption != "none") params.add("encryption=$encryption")
        if (!flow.isNullOrEmpty()) params.add("flow=$flow")
        params.add("security=$security")
        if (transport != "tcp") params.add("type=$transport")

        if (security == "tls" && tls != null) {
            appendTlsParams(params, tls)
        }

        if (security == "reality" && reality != null) {
            params.add("sni=${reality.serverName}")
            params.add("pbk=${reality.publicKey.toBase64Url()}")
            if (reality.shortId.isNotEmpty()) params.add("sid=${reality.shortId.toHex()}")
            if (reality.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${reality.fingerprint.raw}")
        }

        appendTransportParams(params)
        if (!muxEnabled) params.add("mux=false")
        if (!xudpEnabled) params.add("xudp=false")
        // testseed is Android-only and not exported — iOS share-links never carry it,
        // and round-trip parity matters more than expressing the local override.

        val query = if (params.isEmpty()) "" else "?${params.joinToString("&")}"
        val fragment = urlEncode(name)
        return "vless://${uuid.toString().lowercase()}@$bracketedServerAddress:$serverPort/$query#$fragment"
    }

    private fun toShadowsocksUrl(): String {
        // Plain `ss://base64(method:password)@host:port/#name` — no
        // transport/security params. Shadowsocks runs over bare TCP.
        val method = ssMethod ?: return "ss://invalid"
        val password = ssPassword ?: return "ss://invalid"
        val userInfo = "$method:$password"
        val encoded = java.util.Base64.getEncoder().encodeToString(userInfo.toByteArray())
            .trimEnd('=')
        val fragment = urlEncode(name)
        return "ss://$encoded@$bracketedServerAddress:$serverPort/#$fragment"
    }

    /**
     * Emits TLS query params (sni, alpn, fp, allowInsecure, minVersion,
     * maxVersion, fragment).
     */
    private fun appendTlsParams(params: MutableList<String>, tls: TlsConfiguration) {
        if (tls.serverName != serverAddress) params.add("sni=${tls.serverName}")
        tls.alpn?.takeIf { it.isNotEmpty() }?.let {
            params.add("alpn=${urlEncode(it.joinToString(","))}")
        }
        if (tls.fingerprint != TlsFingerprint.CHROME_120) params.add("fp=${tls.fingerprint.raw}")
        if (tls.allowInsecure) params.add("allowInsecure=1")
        tls.minVersion?.let { params.add("minVersion=${it.urlValue}") }
        tls.maxVersion?.let { params.add("maxVersion=${it.urlValue}") }
        // Only a per-server override is exported; a server following the
        // tunnel-wide default carries no `fragment=`, which is what the
        // default means.
        tls.fragment?.takeIf { it.isEnabled }?.let {
            params.add("fragment=${urlEncode(it.toShareLinkValue())}")
        }
    }

    private fun toNaiveUrl(): String {
        val user = urlEncode(naiveUsername ?: "")
        val pass = urlEncode(naivePassword ?: "")
        val fragment = urlEncode(name)
        return "https://$user:$pass@$bracketedServerAddress:$serverPort#$fragment"
    }

    private fun toSocks5Url(): String {
        val fragment = urlEncode(name)
        val userInfo = if (!socks5Username.isNullOrEmpty()) {
            val user = urlEncode(socks5Username)
            val pass = urlEncode(socks5Password ?: "")
            "$user:$pass@"
        } else {
            ""
        }
        return "socks5://$userInfo$bracketedServerAddress:$serverPort#$fragment"
    }

    private fun appendTransportParams(params: MutableList<String>) {
        if (transport == "ws" && websocket != null) {
            if (websocket.host != serverAddress) params.add("host=${websocket.host}")
            if (websocket.path != "/") params.add("path=${urlEncode(websocket.path)}")
            if (websocket.maxEarlyData > 0) params.add("ed=${websocket.maxEarlyData}")
        }
        if (transport == "httpupgrade" && httpUpgrade != null) {
            if (httpUpgrade.host != serverAddress) params.add("host=${httpUpgrade.host}")
            if (httpUpgrade.path != "/") params.add("path=${urlEncode(httpUpgrade.path)}")
        }
        if (transport == "xhttp" && xhttp != null) {
            if (xhttp.host != serverAddress) params.add("host=${xhttp.host}")
            if (xhttp.path != "/") params.add("path=${urlEncode(xhttp.path)}")
            if (xhttp.mode != XHttpMode.AUTO) params.add("mode=${xhttp.mode.raw}")
        }
        if (transport == "grpc" && grpc != null) {
            if (grpc.serviceName.isNotEmpty()) params.add("serviceName=${urlEncode(grpc.serviceName)}")
            if (grpc.authority.isNotEmpty()) params.add("authority=${urlEncode(grpc.authority)}")
            if (grpc.multiMode) params.add("mode=multi")
        }
    }

    companion object {
        /** URL scheme prefixes [fromUrl] recognises. */
        val parsableUrlPrefixes = listOf(
            "vless://", "trojan://", "ss://",
            "hysteria2://", "hy2://", "anytls://", "vmess://",
            "socks5://", "socks://", "https://"
        )

        /** Whether [fromUrl] can parse [url]. */
        fun canParseUrl(url: String): Boolean =
            parsableUrlPrefixes.any { url.startsWith(it) }

        fun fromUrl(url: String, naiveProtocol: OutboundProtocol? = null): ProxyConfiguration = when {
            url.startsWith("ss://") -> fromShadowsocksUrl(url)
            url.startsWith("socks5://") || url.startsWith("socks://") -> fromSocks5Url(url)
            url.startsWith("https://") -> fromNaiveUrl(url, naiveProtocol)
            url.startsWith("vless://") -> fromVlessUrl(url)
            url.startsWith("trojan://") -> fromTrojanUrl(url)
            url.startsWith("hysteria2://") -> fromHysteria2Url(url, "hysteria2://")
            url.startsWith("hy2://") -> fromHysteria2Url(url, "hy2://")
            url.startsWith("anytls://") -> fromAnyTlsUrl(url)
            url.startsWith("vmess://") -> fromVmessUrl(url)
            else -> throw ProxyError.InvalidUrl(
                "URL must start with vless://, trojan://, ss://, vmess://, hysteria2://, hy2://, anytls://, socks5://, or https://"
            )
        }

        /**
         * Whether this text is a `wg-quick` config rather than a share link.
         *
         * WireGuard has no URL scheme — a peer hands out the INI itself — so a
         * paste is recognised by its shape.
         */
        fun looksLikeWireGuardConfig(text: String): Boolean {
            val lower = text.lowercase()
            return lower.contains("[interface]") &&
                lower.contains("privatekey") &&
                lower.contains("[peer]")
        }

        /**
         * Builds a profile from a `wg-quick` INI, WireGuard or AmneziaWG.
         *
         * The text is kept verbatim so a key this build does not know survives
         * a round trip; parsing here only validates it and pulls out the
         * endpoint for the list and the latency check.
         */
        fun fromWireGuardConfig(text: String, name: String? = null): ProxyConfiguration {
            val parsed = try {
                com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse(text)
            } catch (e: Exception) {
                throw ProxyError.InvalidUrl(e.message ?: "WireGuard configuration is not usable")
            }

            val label = name?.takeIf { it.isNotBlank() }
                ?: if (parsed.amnezia.isEnabled) "AmneziaWG" else "WireGuard"

            return ProxyConfiguration(
                name = label,
                serverAddress = parsed.peer.endpointHost,
                serverPort = parsed.peer.endpointPort.toUShort(),
                uuid = UUID.randomUUID(), // placeholder; WireGuard has no user id
                outboundProtocol = OutboundProtocol.WIREGUARD,
                encryption = "none",
                security = "none",
                transport = "udp",
                wireGuardConfig = text
            )
        }

        /**
         * Parses a Trojan URL. Format:
         * `trojan://password@host:port?sni=...&alpn=h2%2Chttp%2F1.1&fp=chrome_133#name`
         * TLS is mandatory — there is no plaintext Trojan variant on the wire.
         */
        private fun fromTrojanUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("trojan://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            var queryString: String? = null
            val qIndex = remaining.indexOf('?')
            if (qIndex >= 0) {
                queryString = remaining.substring(qIndex + 1)
                remaining = remaining.substring(0, qIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in trojan URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)
            if (serverPart.endsWith("/")) serverPart = serverPart.dropLast(1)
            val slashIdx = serverPart.indexOf('/')
            if (slashIdx >= 0) serverPart = serverPart.substring(0, slashIdx)

            // Whole userinfo is the password (trojan-gfw spec — no user:pass split).
            val password = percentDecode(userInfo)

            val (host, port) = parseHostPort(serverPart)
            val params = parseQueryParams(queryString)

            val sni = params["sni"]?.takeIf { it.isNotEmpty() }
                ?: params["peer"]?.takeIf { it.isNotEmpty() }
                ?: host

            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val fp = params["fp"] ?: "chrome_133"
            val tls = TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                fingerprint = TlsFingerprint.fromRaw(fp)
            )

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for Trojan
                encryption = "none",
                transport = "tcp",
                security = "tls",
                tls = tls,
                outboundProtocol = OutboundProtocol.TROJAN,
                trojanPassword = password,
                trojanTls = tls
            )
        }

        /**
         * The parts every `password@host:port?query#name` link shares.
         *
         * Trojan predates this helper and keeps its own copy; the newer schemes
         * are all this shape.
         */
        private data class UserInfoLink(
            val password: String,
            val host: String,
            val port: UShort,
            val params: Map<String, String>,
            val name: String?
        )

        private fun decomposeUserInfoLink(
            url: String,
            scheme: String,
            /**
             * Used when the authority carries no port. Hysteria2 and AnyTLS
             * both default to 443, and a link written without one is common
             * enough that rejecting it is the wrong answer.
             */
            defaultPort: UShort? = null
        ): UserInfoLink {
            var remaining = url.removePrefix(scheme)

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            var queryString: String? = null
            val qIndex = remaining.indexOf('?')
            if (qIndex >= 0) {
                queryString = remaining.substring(qIndex + 1)
                remaining = remaining.substring(0, qIndex)
            }

            // lastIndexOf: a password may itself contain '@'.
            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) {
                throw ProxyError.InvalidUrl("Missing @ separator in ${scheme.removeSuffix("://")} URL")
            }

            val password = percentDecode(remaining.substring(0, atIndex))
            var serverPart = remaining.substring(atIndex + 1)
            if (serverPart.endsWith("/")) serverPart = serverPart.dropLast(1)
            val slashIdx = serverPart.indexOf('/')
            if (slashIdx >= 0) serverPart = serverPart.substring(0, slashIdx)

            val (host, port) = parseHostPort(serverPart, defaultPort)
            return UserInfoLink(
                password = password,
                host = host,
                port = port,
                params = parseQueryParams(queryString),
                name = fragmentName?.takeIf { it.isNotEmpty() }
            )
        }

        /**
         * `vmess://` + base64 of a JSON object — the "v2rayN" form every panel
         * writes. There is also a query-string spelling in the wild; it is rare
         * enough, and ambiguous enough, that only the JSON form is accepted.
         *
         * `aid` (alterId) must be 0: the legacy MD5-authenticated header it
         * selects was removed from v2ray in 2022, and pretending to support it
         * would produce a connection that silently never authenticates.
         */
        private fun fromVmessUrl(url: String): ProxyConfiguration {
            val payload = url.removePrefix("vmess://").trim()
            if (payload.isEmpty()) throw ProxyError.InvalidUrl("Empty vmess:// link")

            val decoded = decodeBase64Flexible(payload)
                ?: throw ProxyError.InvalidUrl("vmess:// payload is not base64")

            val json = runCatching { JSONObject(decoded) }.getOrNull()
                ?: throw ProxyError.InvalidUrl("vmess:// payload is not JSON")

            val host = json.optString("add").takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("vmess: missing add")
            val portValue = json.opt("port")?.toString()?.trim()?.toIntOrNull()
                ?: throw ProxyError.InvalidUrl("vmess: missing or malformed port")
            if (portValue !in 1..65535) throw ProxyError.InvalidUrl("vmess: port out of range")

            val idText = json.optString("id").takeIf { it.isNotEmpty() }
                ?: throw ProxyError.InvalidUrl("vmess: missing id")
            val id = runCatching { UUID.fromString(idText) }.getOrNull()
                ?: throw ProxyError.InvalidUrl("vmess: id is not a UUID")

            // aid may be a number or a string depending on who wrote the link.
            val alterId = json.opt("aid")?.toString()?.trim()?.toIntOrNull() ?: 0
            if (alterId != 0) {
                throw ProxyError.InvalidUrl(
                    "vmess: alterId $alterId is the removed legacy header; only alterId 0 (AEAD) is supported"
                )
            }

            val network = json.optString("net").ifEmpty { "tcp" }
            val transport = when (network) {
                "ws" -> "ws"
                "tcp" -> "tcp"
                else -> throw ProxyError.InvalidUrl("vmess: $network transport is not supported yet")
            }

            val tlsField = json.optString("tls")
            val useTls = tlsField == "tls" || tlsField == "1" || tlsField == "true"
            val sni = json.optString("sni").takeIf { it.isNotEmpty() }
                ?: json.optString("host").takeIf { it.isNotEmpty() }
                ?: host
            val alpn = json.optString("alpn").takeIf { it.isNotEmpty() }?.split(",")
            // v2rayN writes this either way round depending on its version.
            val allowInsecure = json.optString("allowInsecure").let { it == "true" || it == "1" } ||
                json.optString("verify_cert").let { it == "false" || it == "0" }

            val tls = if (useTls) {
                TlsConfiguration(
                    serverName = sni,
                    alpn = alpn,
                    allowInsecure = allowInsecure,
                    fingerprint = TlsFingerprint.fromRaw(
                        json.optString("fp").ifEmpty { "chrome_133" }
                    )
                )
            } else {
                null
            }

            val websocket = if (transport == "ws") {
                WebSocketConfiguration(
                    host = json.optString("host").takeIf { it.isNotEmpty() } ?: host,
                    path = json.optString("path").ifEmpty { "/" }
                )
            } else {
                null
            }

            return ProxyConfiguration(
                name = json.optString("ps").takeIf { it.isNotEmpty() } ?: host,
                serverAddress = host,
                serverPort = portValue.toUShort(),
                uuid = id,
                encryption = "none",
                transport = transport,
                security = if (useTls) "tls" else "none",
                tls = tls,
                websocket = websocket,
                outboundProtocol = OutboundProtocol.VMESS,
                vmessSecurity = json.optString("scy").takeIf { it.isNotEmpty() && it != "auto" }
            )
        }

        /**
         * Base64 that may or may not be padded, and may be either alphabet.
         *
         * Panels are inconsistent about all three, and a link that fails to
         * decode over punctuation is the most avoidable kind of import failure.
         */
        private fun decodeBase64Flexible(text: String): String? {
            val normalised = text.replace('-', '+').replace('_', '/').trim()
            val padded = when (normalised.length % 4) {
                2 -> "$normalised=="
                3 -> "$normalised="
                0 -> normalised
                else -> return null
            }
            return runCatching {
                String(java.util.Base64.getDecoder().decode(padded), Charsets.UTF_8)
            }.getOrNull()
        }

        /**
         * `hysteria2://password@host:port?sni=…&upmbps=…&downmbps=…&obfs=salamander&obfs-password=…#name`,
         * and the `hy2://` spelling of the same thing.
         *
         * TLS is mandatory; Hysteria2 runs over QUIC and has no plaintext form.
         */
        private fun fromHysteria2Url(url: String, scheme: String): ProxyConfiguration {
            val link = decomposeUserInfoLink(url, scheme, defaultPort = 443u)
            val params = link.params

            val sni = params["sni"]?.takeIf { it.isNotEmpty() } ?: link.host
            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val insecure = params["insecure"] == "1" || params["allowInsecure"] == "1"
            val tls = TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = insecure,
                fingerprint = TlsFingerprint.fromRaw(params["fp"] ?: "chrome_133")
            )

            return ProxyConfiguration(
                name = link.name ?: link.host,
                serverAddress = link.host,
                serverPort = link.port,
                uuid = UUID.randomUUID(),   // placeholder; Hysteria2 authenticates by password
                encryption = "none",
                transport = "tcp",
                security = "tls",
                tls = tls,
                outboundProtocol = OutboundProtocol.HYSTERIA2,
                password = link.password,
                // Absence is information: the bandwidth pair is what selects
                // Brutal over BBR, so no default is filled in here.
                hysteriaUpMbps = params["upmbps"]?.toIntOrNull(),
                hysteriaDownMbps = params["downmbps"]?.toIntOrNull(),
                obfuscation = params["obfs"]?.takeIf { it.isNotEmpty() }?.lowercase(),
                obfuscationPassword = params["obfs-password"]?.takeIf { it.isNotEmpty() }
            )
        }

        /** `anytls://password@host:port?sni=…&alpn=…&fp=…#name`. TLS is mandatory. */
        private fun fromAnyTlsUrl(url: String): ProxyConfiguration {
            val link = decomposeUserInfoLink(url, "anytls://", defaultPort = 443u)
            val params = link.params

            val sni = params["sni"]?.takeIf { it.isNotEmpty() } ?: link.host
            val alpn = params["alpn"]?.takeIf { it.isNotEmpty() }?.split(",")
            val insecure = params["insecure"] == "1" || params["allowInsecure"] == "1"
            val tls = TlsConfiguration(
                serverName = sni,
                alpn = alpn,
                allowInsecure = insecure,
                fingerprint = TlsFingerprint.fromRaw(params["fp"] ?: "chrome_133")
            )

            return ProxyConfiguration(
                name = link.name ?: link.host,
                serverAddress = link.host,
                serverPort = link.port,
                uuid = UUID.randomUUID(),   // placeholder; AnyTLS authenticates by password
                encryption = "none",
                transport = "tcp",
                security = "tls",
                tls = tls,
                outboundProtocol = OutboundProtocol.ANYTLS,
                password = link.password
            )
        }

        private fun fromVlessUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("vless://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator")

            val uuidString = remaining.substring(0, atIndex)
            val serverPart = remaining.substring(atIndex + 1)

            val uuid = runCatching { UUID.fromString(uuidString) }.getOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid UUID: $uuidString")

            val hostPort: String
            var queryString: String? = null
            val questionIndex = serverPart.indexOf('?')
            if (questionIndex >= 0) {
                val before = serverPart.substring(0, questionIndex)
                hostPort = if (before.endsWith("/")) before.dropLast(1) else before
                queryString = serverPart.substring(questionIndex + 1)
            } else {
                val slashIndex = serverPart.indexOf('/')
                hostPort = if (slashIndex >= 0) serverPart.substring(0, slashIndex) else serverPart
            }

            val (host, port) = parseHostPort(hostPort)
            val params = parseQueryParams(queryString)

            val encryption = params["encryption"] ?: "none"
            val flow = params["flow"]
            val security = params["security"] ?: "none"
            val transport = params["type"] ?: "tcp"

            var testseed: List<UInt>? = null
            params["testseed"]?.let { str ->
                val values = str.split(",").mapNotNull { it.toUIntOrNull() }
                if (values.size >= 4) testseed = values.take(4)
            }

            val realityConfig = if (security == "reality") RealityConfiguration.parse(params) else null
            val tlsConfig = if (security == "tls") TlsConfiguration.parse(params, host) else null
            val wsConfig = if (transport == "ws") WebSocketConfiguration.parse(params, host) else null
            val httpUpgradeConfig = if (transport == "httpupgrade") HttpUpgradeConfiguration.parse(params, host) else null
            val xhttpConfig = if (transport == "xhttp") {
                // Fall back to TLS/Reality SNI for XHTTP host
                val xhttpHost = params["host"]
                    ?: tlsConfig?.serverName ?: realityConfig?.serverName ?: host
                XHttpConfiguration.parse(params + ("host" to xhttpHost), host)
            } else null
            val grpcConfig = if (transport == "grpc") {
                com.mythaia.vpn.protocol.grpc.GrpcConfiguration.parse(params)
            } else null

            val muxEnabled = params["mux"]?.let { it != "false" && it != "0" } ?: true
            val xudpEnabled = params["xudp"]?.let { it != "false" && it != "0" } ?: true

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = uuid,
                encryption = encryption,
                transport = transport,
                flow = flow,
                security = security,
                tls = tlsConfig,
                reality = realityConfig,
                websocket = wsConfig,
                httpUpgrade = httpUpgradeConfig,
                xhttp = xhttpConfig,
                grpc = grpcConfig,
                testseed = testseed ?: listOf(900u, 500u, 900u, 256u),
                muxEnabled = muxEnabled,
                xudpEnabled = xudpEnabled
            )
        }

        private fun fromShadowsocksUrl(url: String): ProxyConfiguration {
            var remaining = url.removePrefix("ss://")

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val method: String
            val password: String
            val host: String
            val port: UShort

            val atIndex = remaining.indexOf('@')
            if (atIndex >= 0) {
                // SIP002 format: userinfo@host:port. The userinfo may be
                // either literal method:password or base64(method:password).
                val userInfo = remaining.substring(0, atIndex)
                var serverPart = remaining.substring(atIndex + 1)

                val questionIndex = serverPart.indexOf('?')
                if (questionIndex >= 0) {
                    serverPart = serverPart.substring(0, questionIndex)
                }
                val slashIndex = serverPart.indexOf('/')
                if (slashIndex >= 0) {
                    serverPart = serverPart.substring(0, slashIndex)
                }

                val parsed = decodeShadowsocksUserInfo(userInfo)
                method = parsed.first
                password = parsed.second

                val (h, p) = parseHostPort(serverPart)
                host = h
                port = p
            } else {
                // Legacy format: base64(method:password@host:port).
                val decoded = decodeBase64Text(remaining)
                    ?: throw ProxyError.InvalidUrl("Invalid SS URL encoding")
                val colonIndex = decoded.indexOf(':')
                if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing method:password separator")
                method = decoded.substring(0, colonIndex)
                val rest = decoded.substring(colonIndex + 1)
                val lastAtIndex = rest.lastIndexOf('@')
                if (lastAtIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in decoded SS URL")
                password = rest.substring(0, lastAtIndex)
                val serverPart = rest.substring(lastAtIndex + 1)
                val (h, p) = parseHostPort(serverPart)
                host = h
                port = p
            }

            if (ShadowsocksCipher.fromMethod(method) == null) {
                throw ProxyError.InvalidUrl("Unsupported SS method: $method")
            }

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for SS
                encryption = "none",
                transport = "tcp",
                security = "none",
                outboundProtocol = OutboundProtocol.SHADOWSOCKS,
                ssPassword = password,
                ssMethod = method
            )
        }

        private fun fromNaiveUrl(url: String, protocolOverride: OutboundProtocol? = null): ProxyConfiguration {
            var remaining = when {
                url.startsWith("https://") -> url.removePrefix("https://")
                else -> throw ProxyError.InvalidUrl("Naive URL must start with https://")
            }

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            val atIndex = remaining.lastIndexOf('@')
            if (atIndex < 0) throw ProxyError.InvalidUrl("Missing @ separator in naive URL")

            val userInfo = remaining.substring(0, atIndex)
            var serverPart = remaining.substring(atIndex + 1)

            val slashIndex = serverPart.indexOf('/')
            if (slashIndex >= 0) {
                serverPart = serverPart.substring(0, slashIndex)
            }

            val colonIndex = userInfo.indexOf(':')
            if (colonIndex < 0) throw ProxyError.InvalidUrl("Missing password in naive URL (expected user:pass)")
            val username = percentDecode(userInfo.substring(0, colonIndex))
            val password = percentDecode(userInfo.substring(colonIndex + 1))

            val (host, port) = parseHostPort(serverPart)

            val proto = protocolOverride ?: OutboundProtocol.NAIVE_HTTP2
            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for naive
                encryption = "none",
                outboundProtocol = proto,
                naiveUsername = username,
                naivePassword = password,
                naiveProtocol = if (proto == OutboundProtocol.NAIVE_HTTP11) NaiveProtocol.HTTP11 else NaiveProtocol.HTTP2
            )
        }

        /**
         * Parse a SOCKS5 URL into configuration.
         * Format: socks5://user:pass@host:port#name  or  socks5://host:port#name
         */
        private fun fromSocks5Url(url: String): ProxyConfiguration {
            var remaining = when {
                url.startsWith("socks5://") -> url.removePrefix("socks5://")
                url.startsWith("socks://") -> url.removePrefix("socks://")
                else -> throw ProxyError.InvalidUrl("SOCKS5 URL must start with socks5:// or socks://")
            }

            var fragmentName: String? = null
            val hashIndex = remaining.lastIndexOf('#')
            if (hashIndex >= 0) {
                fragmentName = percentDecode(remaining.substring(hashIndex + 1))
                remaining = remaining.substring(0, hashIndex)
            }

            var username: String? = null
            var password: String? = null
            val serverPart: String
            val atIndex = remaining.lastIndexOf('@')
            if (atIndex >= 0) {
                val userInfo = remaining.substring(0, atIndex)
                serverPart = remaining.substring(atIndex + 1).let { rest ->
                    val slashIndex = rest.indexOf('/')
                    if (slashIndex >= 0) rest.substring(0, slashIndex) else rest
                }
                val colonIndex = userInfo.indexOf(':')
                if (colonIndex >= 0) {
                    username = percentDecode(userInfo.substring(0, colonIndex))
                    password = percentDecode(userInfo.substring(colonIndex + 1))
                } else {
                    username = percentDecode(userInfo)
                }
            } else {
                val slashIndex = remaining.indexOf('/')
                serverPart = if (slashIndex >= 0) remaining.substring(0, slashIndex) else remaining
            }

            val (host, port) = parseHostPort(serverPart)

            return ProxyConfiguration(
                name = fragmentName ?: "Untitled",
                serverAddress = host,
                serverPort = port,
                uuid = UUID.randomUUID(), // placeholder, not used for SOCKS5
                encryption = "none",
                outboundProtocol = OutboundProtocol.SOCKS5,
                socks5Username = username,
                socks5Password = password
            )
        }

        private fun parseQueryParams(queryString: String?): Map<String, String> {
            if (queryString == null) return emptyMap()
            val params = mutableMapOf<String, String>()
            queryString.split("&").forEach { param ->
                val kv = param.split("=", limit = 2)
                if (kv.size == 2) {
                    params[kv[0]] = percentDecode(kv[1])
                }
            }
            return params
        }

        private fun parseHostPort(
            hostPort: String,
            defaultPort: UShort? = null
        ): Pair<String, UShort> {
            val host: String
            val portString: String
            if (hostPort.startsWith("[")) {
                val closeBracket = hostPort.indexOf(']')
                if (closeBracket < 0) throw ProxyError.InvalidUrl("Missing closing bracket for IPv6 address")
                host = hostPort.substring(1, closeBracket)
                val afterBracket = hostPort.substring(closeBracket + 1)
                if (afterBracket.isEmpty()) {
                    return Pair(
                        host,
                        defaultPort ?: throw ProxyError.InvalidUrl("Missing port after IPv6 address")
                    )
                }
                if (!afterBracket.startsWith(":")) throw ProxyError.InvalidUrl("Missing port after IPv6 address")
                portString = afterBracket.removePrefix(":")
            } else {
                val colonIndex = hostPort.lastIndexOf(':')
                if (colonIndex < 0) {
                    return Pair(
                        hostPort,
                        defaultPort ?: throw ProxyError.InvalidUrl("Missing port in server address")
                    )
                }
                host = hostPort.substring(0, colonIndex)
                // An unbracketed IPv6 literal has colons of its own, so this
                // split would take all but the last group as the host and the
                // last as a port. RFC 3986 §3.2.2 requires the brackets;
                // without them the address is not addressable and guessing at
                // it would connect somewhere else entirely.
                if (host.contains(':')) {
                    throw ProxyError.InvalidUrl("IPv6 address must be bracketed: $hostPort")
                }
                portString = hostPort.substring(colonIndex + 1)
            }
            val port = portString.toUShortOrNull()
                ?: throw ProxyError.InvalidUrl("Invalid port: $portString")
            return Pair(host, port)
        }

        private fun padBase64(str: String): String {
            val remainder = str.length % 4
            if (remainder == 0) return str
            return str + "=".repeat(4 - remainder)
        }

        private fun decodeShadowsocksUserInfo(userInfo: String): Pair<String, String> {
            val colonIndex = userInfo.indexOf(':')
            if (colonIndex >= 0) {
                return Pair(userInfo.substring(0, colonIndex), percentDecode(userInfo.substring(colonIndex + 1)))
            }

            val decoded = decodeBase64Text(userInfo)
                ?: throw ProxyError.InvalidUrl("Invalid SS user info encoding")
            val decodedColonIndex = decoded.indexOf(':')
            if (decodedColonIndex < 0) throw ProxyError.InvalidUrl("Invalid SS user info format")
            return Pair(decoded.substring(0, decodedColonIndex), decoded.substring(decodedColonIndex + 1))
        }

        private fun decodeBase64Text(value: String): String? {
            val padded = padBase64(value)
            val bytes = runCatching {
                java.util.Base64.getUrlDecoder().decode(padded)
            }.getOrElse {
                runCatching { java.util.Base64.getDecoder().decode(padded) }.getOrNull()
            } ?: return null
            return String(bytes, Charsets.UTF_8)
        }

        private fun urlEncode(value: String): String =
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")
    }
}

sealed class ProxyError(message: String) : Exception(message) {
    class InvalidUrl(message: String) : ProxyError("Invalid URL: $message")
    class ConnectionFailed(message: String) : ProxyError("Connection failed: $message")
    class ProtocolError(message: String) : ProxyError("Protocol error: $message")
    class InvalidResponse(message: String) : ProxyError("Invalid response: $message")
    class Dropped : ProxyError("Dropped")
}
