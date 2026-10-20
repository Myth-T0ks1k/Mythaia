package com.mythaia.data.network

import com.mythaia.data.model.HopInterval
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.PortUnion
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.WireGuardIni
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.util.Base64

/**
 * Imports sing-box JSON: a whole config (`{"outbounds": [...], "endpoints":
 * [...]}`, what Hiddify, NekoBox and sing-box subscriptions hand out), one
 * outbound object, or an array of outbounds.
 *
 * sing-box names an outbound's kind in `type` where Xray says `protocol`,
 * which is how the two are told apart ([isSingBox]). As with
 * [XrayJsonImporter], each outbound becomes the share link it is equivalent
 * to and goes through the same link parser as a pasted one; WireGuard, which
 * has no link worth the name, becomes the INI it is stored as. The routing
 * outbounds (`selector`, `urltest`, `direct`, `block`, `dns`) are skipped,
 * and a `detour` to another proxy becomes the entry hop of a chain.
 */
object SingBoxJsonImporter {

    private val PROXY_TYPES = setOf(
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http",
        "hysteria2", "tuic", "anytls", "naive", "wireguard"
    )

    /** Outbounds that route or terminate rather than reach a server. */
    private val ROUTING_TYPES = setOf("selector", "urltest", "direct", "block", "dns")

    /** Whether [text] is sing-box JSON rather than Xray's. */
    fun looksLikeSingBox(text: String): Boolean =
        looksLikeSingBox(text) { runCatching { XrayJsonImporter.parseJson(text) }.getOrNull() }

    /**
     * [looksLikeSingBox] with the parsing left to [tree], so a caller that
     * goes on to import the JSON builds the tree once rather than again for
     * each step: for a body of thousands of outbounds that was three parses.
     */
    internal fun looksLikeSingBox(text: String, tree: () -> Any?): Boolean {
        if (!XrayJsonImporter.startsLikeJson(text)) return false
        if (!text.contains("\"type\"")) return false
        val root = tree() ?: return false
        return isSingBox(root)
    }

    /**
     * Whether parsed JSON is sing-box's: its outbounds (or endpoints) say
     * `type` and none of them says `protocol`. Route rules may well mention
     * `"protocol"`, which is why the text alone cannot decide this.
     */
    internal fun isSingBox(root: Any): Boolean {
        val items = items(root)
        return items.any { it.has("type") && !it.has("protocol") } && items.none { it.has("protocol") }
    }

    /** One config per usable outbound. Throws [ProxyError.InvalidUrl] when nothing usable is there. */
    fun parse(text: String): List<ProxyConfiguration> = parse(XrayJsonImporter.parseJson(text))

    internal fun parse(root: Any): List<ProxyConfiguration> {
        val items = items(root)
        if (items.isEmpty()) throw ProxyError.InvalidUrl("No outbounds found in the JSON")

        val byTag = items.filter { it.optString("tag").isNotEmpty() }.associateBy { it.getString("tag") }
        // An outbound only there to carry another is imported as that one's
        // chain, not listed as a server of its own.
        val detourTargets = items.mapNotNull { it.optString("detour").takeIf { tag -> tag.isNotEmpty() } }.toSet()

        val errors = ArrayList<String>()
        val configurations = ArrayList<ProxyConfiguration>()
        for (item in items) {
            val type = item.optString("type").lowercase()
            if (type in ROUTING_TYPES) continue
            val tag = item.optString("tag")
            if (tag.isNotEmpty() && tag in detourTargets) continue
            try {
                if (type !in PROXY_TYPES) throw ProxyError.InvalidUrl("$type outbounds are not supported")
                configurations += convert(item, byTag, depth = 0)
            } catch (e: ProxyError) {
                errors += "${tag.ifEmpty { type }}: ${e.message}"
            }
        }
        if (configurations.isEmpty()) {
            throw ProxyError.InvalidUrl(
                if (errors.isEmpty()) "No proxy outbound in the JSON (only selector/urltest/direct/block/dns)"
                else errors.joinToString("; ")
            )
        }
        return configurations
    }

    /** The outbound-shaped objects in a config, a bare array, or one outbound. */
    private fun items(root: Any): List<JSONObject> = when (root) {
        is JSONObject ->
            if (root.has("outbounds") || root.has("endpoints")) {
                objects(root.optJSONArray("outbounds")) + objects(root.optJSONArray("endpoints"))
            } else {
                listOf(root)
            }
        is JSONArray -> objects(root)
        else -> emptyList()
    }

    private fun objects(array: JSONArray?): List<JSONObject> =
        array?.let { (0 until it.length()).mapNotNull { i -> it.optJSONObject(i) } } ?: emptyList()

    // ---------------------------------------------------------- conversion

    private fun convert(item: JSONObject, byTag: Map<String, JSONObject>, depth: Int): ProxyConfiguration {
        if (depth > 8) throw ProxyError.InvalidUrl("detour chain is too deep or circular")
        val type = item.optString("type").lowercase()
        val name = item.optString("tag")

        var chain: List<ProxyConfiguration>? = null
        item.optString("detour").takeIf { it.isNotEmpty() }?.let { tag ->
            val hop = byTag[tag] ?: throw ProxyError.InvalidUrl("detour '$tag' is not defined")
            // A detour to `direct` (or a selector, which cannot be resolved
            // here) dials the server directly, which is what it would do anyway.
            if (hop.optString("type").lowercase() in PROXY_TYPES) {
                val entry = convert(hop, byTag, depth + 1)
                if (entry.outboundProtocol.isLayer3) {
                    throw ProxyError.InvalidUrl("detour '$tag' is WireGuard, which cannot carry another proxy")
                }
                chain = (entry.chain ?: emptyList()) + entry.withChain(null)
            }
        }

        val config = when (type) {
            "wireguard" -> wireGuardConfig(item, name)
            "http" -> ProxyConfiguration.fromUrl(httpLink(item, name, "http"), OutboundProtocol.NAIVE_HTTP11)
            "naive" -> ProxyConfiguration.fromUrl(httpLink(item, name, "naive"), OutboundProtocol.NAIVE_HTTP2)
            else -> ProxyConfiguration.fromUrl(
                when (type) {
                    "vless" -> vlessLink(item, name)
                    "vmess" -> vmessLink(item, name)
                    "trojan" -> trojanLink(item, name)
                    "shadowsocks" -> shadowsocksLink(item, name)
                    "socks" -> socksLink(item, name)
                    "hysteria2" -> hysteria2Link(item, name)
                    "tuic" -> tuicLink(item, name)
                    "anytls" -> anyTlsLink(item, name)
                    else -> throw ProxyError.InvalidUrl("$type outbounds are not supported")
                }
            )
        }
        if (chain.isNullOrEmpty()) return config
        if (config.outboundProtocol.isLayer3) {
            throw ProxyError.InvalidUrl("WireGuard is a whole interface and cannot be dialled through another proxy")
        }
        return config.withChain(chain)
    }

    // ------------------------------------------------------------- pieces

    /**
     * `server:server_port`, IPv6 bracketed. A Hysteria2 outbound that hops
     * (`server_ports: ["20000:30000"]`) and names no `server_port` gets the
     * first port of the list here; the list itself goes into `mport`.
     */
    private fun hostPort(item: JSONObject): String {
        val type = item.optString("type")
        val address = item.optString("server").ifEmpty { throw ProxyError.InvalidUrl("$type: server is missing") }
        val port = item.optInt("server_port", 0).takeIf { it in 1..65535 }
            ?: XrayJsonImporter.stringList(item.opt("server_ports")).firstOrNull()
                ?.substringBefore(':')?.substringBefore('-')?.trim()?.toIntOrNull()?.takeIf { it in 1..65535 }
            ?: throw ProxyError.InvalidUrl("$type: server_port is missing")
        val host = if (address.contains(':') && !address.startsWith("[")) "[$address]" else address
        return "$host:$port"
    }

    private fun label(item: JSONObject, name: String): String = encode(name.ifEmpty { hostPort(item) })

    /**
     * The TLS block as link parameters, and the `security` it amounts to.
     *
     * sing-box only uses TLS when `enabled` is true; for the protocols that
     * cannot run without it ([mandatory]) the block is read either way, since
     * their links imply TLS regardless.
     */
    private fun tlsParams(
        item: JSONObject,
        params: MutableMap<String, String>,
        insecureKey: String,
        mandatory: Boolean = false
    ): String {
        val tls = item.optJSONObject("tls")
        if (tls == null || (!tls.optBoolean("enabled", false) && !mandatory)) return "none"
        tls.optString("server_name").takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
        XrayJsonImporter.stringList(tls.opt("alpn")).takeIf { it.isNotEmpty() }?.let { params["alpn"] = it.joinToString(",") }
        if (tls.optBoolean("insecure", false)) params[insecureKey] = "1"
        tls.optJSONObject("utls")?.takeIf { it.optBoolean("enabled", false) }
            ?.optString("fingerprint")?.takeIf { it.isNotEmpty() }?.let { params["fp"] = it }
        tls.optJSONObject("ech")?.takeIf { it.optBoolean("enabled", false) }
            ?.let { echConfig(it.opt("config")) }?.let { params["ech"] = it }
        val reality = tls.optJSONObject("reality")?.takeIf { it.optBoolean("enabled", false) }
        if (reality != null) {
            reality.optString("public_key").takeIf { it.isNotEmpty() }?.let { params["pbk"] = it }
            reality.optString("short_id").takeIf { it.isNotEmpty() }?.let { params["sid"] = it }
            return "reality"
        }
        // Hiddify's sing-box carries ClientHello fragmentation on the
        // outbound; it is the same thing a link's `fragment=` asks for.
        item.optJSONObject("tls_fragment")?.takeIf { it.optBoolean("enabled", false) }?.let { f ->
            val size = f.opt("size")?.toString()?.takeIf { it.isNotEmpty() } ?: "10-30"
            val sleep = f.opt("sleep")?.toString()?.takeIf { it.isNotEmpty() } ?: "2-8"
            params["fragment"] = "$size,$sleep,tlshello"
        }
        return "tls"
    }

    /**
     * sing-box's `ech.config`: the PEM block `sing-box generate ech-keypair`
     * prints, as an array of its lines or one string. Its body is the base64
     * ECHConfigList a link's `ech=` carries.
     */
    private fun echConfig(value: Any?): String? {
        val lines = when (value) {
            is JSONArray -> XrayJsonImporter.stringList(value)
            is String -> value.lines()
            else -> return null
        }
        return lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("").takeIf { it.isNotEmpty() }
    }

    /** The V2Ray transport block as link parameters. */
    private fun transportParams(item: JSONObject, params: MutableMap<String, String>) {
        val transport = item.optJSONObject("transport")
        when (val type = transport?.optString("type")?.lowercase().orEmpty()) {
            "", "tcp" -> params["type"] = "tcp"
            "ws" -> {
                params["type"] = "ws"
                transport!!.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                headerValue(transport.optJSONObject("headers"), "Host")?.let { params["host"] = it }
                // sing-box sends early data in the path unless a header is
                // named; only the header form is something this client
                // speaks, and leaving early data off is always accepted.
                val earlyData = transport.optInt("max_early_data", 0)
                val header = transport.optString("early_data_header_name")
                if (earlyData > 0 && header.isNotEmpty()) {
                    params["ed"] = earlyData.toString()
                    params["eh"] = header
                }
            }
            "httpupgrade" -> {
                params["type"] = "httpupgrade"
                transport!!.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                (transport.optString("host").takeIf { it.isNotEmpty() }
                    ?: headerValue(transport.optJSONObject("headers"), "Host"))?.let { params["host"] = it }
            }
            "grpc" -> {
                params["type"] = "grpc"
                transport!!.optString("service_name").takeIf { it.isNotEmpty() }?.let { params["serviceName"] = it }
            }
            "http" -> {
                params["type"] = "http"
                val hosts = XrayJsonImporter.stringList(transport!!.opt("host"))
                if (hosts.isNotEmpty()) params["host"] = hosts.joinToString(",")
                transport.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                transport.optString("method").takeIf { it.isNotEmpty() }?.let { params["method"] = it }
                transport.optJSONObject("headers")?.takeIf { it.length() > 0 }?.let { params["headers"] = it.toString() }
            }
            "quic" -> params["type"] = "quic"
            "xhttp", "splithttp" -> {
                params["type"] = "xhttp"
                transport!!.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                (XrayJsonImporter.stringList(transport.opt("host")).firstOrNull()
                    ?: headerValue(transport.optJSONObject("headers"), "Host"))?.let { params["host"] = it }
                transport.optString("mode").takeIf { it.isNotEmpty() }?.let { params["mode"] = it }
                transport.optJSONObject("extra")?.let { params["extra"] = it.toString() }
            }
            else -> throw ProxyError.InvalidUrl("the $type transport is not supported")
        }
    }

    /** A header from sing-box's map, whose values may be a string or a list of them. */
    private fun headerValue(headers: JSONObject?, name: String): String? {
        if (headers == null) return null
        val key = headers.keys().asSequence().firstOrNull { it.equals(name, ignoreCase = true) } ?: return null
        return XrayJsonImporter.stringList(headers.opt(key)).firstOrNull()
    }

    private fun query(params: Map<String, String>): String =
        params.entries.joinToString("&") { (k, v) -> "$k=${encode(v)}" }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun required(item: JSONObject, key: String): String =
        item.optString(key).ifEmpty { throw ProxyError.InvalidUrl("${item.optString("type")}: $key is missing") }

    // ---------------------------------------------------------- protocols

    private fun vlessLink(item: JSONObject, name: String): String {
        val uuid = required(item, "uuid")
        val params = LinkedHashMap<String, String>()
        transportParams(item, params)
        params["security"] = tlsParams(item, params, "allowInsecure")
        params["encryption"] = "none"
        item.optString("flow").takeIf { it.isNotEmpty() }?.let { params["flow"] = it }
        return "vless://${encode(uuid)}@${hostPort(item)}?${query(params)}#${label(item, name)}"
    }

    private fun vmessLink(item: JSONObject, name: String): String {
        val params = LinkedHashMap<String, String>()
        transportParams(item, params)
        val security = tlsParams(item, params, "allowInsecure")
        val server = item.optString("server")
        val net = params["type"] ?: "tcp"
        val vmessType = if (net == "xhttp") (params["mode"] ?: "auto") else "none"
        val json = JSONObject()
            .put("v", "2")
            .put("ps", name.ifEmpty { hostPort(item) })
            .put("add", server)
            .put("port", hostPort(item).substringAfterLast(':'))
            .put("id", required(item, "uuid"))
            .put("aid", item.optInt("alter_id", 0))
            .put("scy", item.optString("security").ifEmpty { "auto" })
            .put("net", net)
            .put("type", vmessType)
            .put("host", params["host"] ?: "")
            .put("path", params["path"] ?: params["serviceName"] ?: "")
            .put("tls", when (security) {
                "tls" -> "tls"
                "reality" -> "reality"
                else -> ""
            })
            .put("sni", params["sni"] ?: "")
            .put("fp", params["fp"] ?: "")
            .put("alpn", params["alpn"] ?: "")
        params["pbk"]?.let { json.put("pbk", it) }
        params["sid"]?.let { json.put("sid", it) }
        params["mode"]?.let { json.put("mode", it) }
        params["extra"]?.let { json.put("extra", it) }
        params["method"]?.let { json.put("method", it) }
        params["headers"]?.let { json.put("headers", it) }
        if (params["allowInsecure"] == "1") json.put("allowInsecure", "1")
        return "vmess://" + Base64.getEncoder().encodeToString(json.toString().toByteArray(Charsets.UTF_8))
    }

    private fun trojanLink(item: JSONObject, name: String): String {
        val password = required(item, "password")
        val params = LinkedHashMap<String, String>()
        transportParams(item, params)
        params["security"] = tlsParams(item, params, "allowInsecure", mandatory = true)
        return "trojan://${encode(password)}@${hostPort(item)}?${query(params)}#${label(item, name)}"
    }

    private fun shadowsocksLink(item: JSONObject, name: String): String {
        item.optString("plugin").takeIf { it.isNotEmpty() }?.let {
            throw ProxyError.InvalidUrl("shadowsocks: plugins are not supported ($it)")
        }
        val method = required(item, "method")
        val password = item.optString("password")
        val userInfo = Base64.getUrlEncoder().withoutPadding().encodeToString("$method:$password".toByteArray(Charsets.UTF_8))
        return "ss://$userInfo@${hostPort(item)}#${label(item, name)}"
    }

    private fun socksLink(item: JSONObject, name: String): String {
        val version = item.optString("version").ifEmpty { "5" }
        if (version != "5") throw ProxyError.InvalidUrl("socks: only SOCKS5 is supported, not $version")
        val user = item.optString("username")
        val auth = if (user.isNotEmpty()) "${encode(user)}:${encode(item.optString("password"))}@" else ""
        return "socks5://$auth${hostPort(item)}#${label(item, name)}"
    }

    /**
     * An HTTPS proxy (`http` with TLS) or a NaïveProxy server (`naive`), both
     * as the `https://user:pass@host:port` link the naive parser reads.
     *
     * That link has nowhere to put a server name, so the name has to be the
     * host itself; one that differs is refused rather than silently dropped,
     * which would present the wrong name to the server.
     */
    private fun httpLink(item: JSONObject, name: String, type: String): String {
        val tls = item.optJSONObject("tls")
        if (tls == null || !tls.optBoolean("enabled", false)) {
            throw ProxyError.InvalidUrl("$type: only a proxy over TLS is supported")
        }
        if (type == "naive" && item.optBoolean("quic", false)) {
            throw ProxyError.InvalidUrl("naive: the QUIC variant is not supported")
        }
        val server = item.optString("server")
        tls.optString("server_name").takeIf { it.isNotEmpty() && !it.equals(server, ignoreCase = true) }?.let {
            throw ProxyError.InvalidUrl("$type: a server name ($it) different from the server address is not supported")
        }
        val user = item.optString("username")
        if (user.isEmpty()) throw ProxyError.InvalidUrl("$type: a username and password are required")
        return "https://${encode(user)}:${encode(item.optString("password"))}@${hostPort(item)}#${label(item, name)}"
    }

    private fun hysteria2Link(item: JSONObject, name: String): String {
        val password = item.optString("password")
        val params = LinkedHashMap<String, String>()
        tlsParams(item, params, "insecure", mandatory = true)
        item.optJSONObject("obfs")?.let { obfs ->
            val type = obfs.optString("type").lowercase()
            if (type.isNotEmpty() && type != "salamander") {
                throw ProxyError.InvalidUrl("hysteria2: $type obfuscation is not supported")
            }
            obfs.optString("password").takeIf { it.isNotEmpty() }?.let {
                params["obfs"] = "salamander"
                params["obfs-password"] = it
            }
        }
        (XrayJsonImporter.bandwidthMbps(item.opt("up_mbps")) ?: XrayJsonImporter.bandwidthMbps(item.opt("up")))
            ?.let { params["upmbps"] = it.toString() }
        (XrayJsonImporter.bandwidthMbps(item.opt("down_mbps")) ?: XrayJsonImporter.bandwidthMbps(item.opt("down")))
            ?.let { params["downmbps"] = it.toString() }
        // Port hopping: `server_ports: ["20000:30000", "443"]`, every
        // `hop_interval` (a Go duration, 30s by default), or at random up to
        // `hop_interval_max` (sing-box 1.14).
        PortUnion.parse(XrayJsonImporter.stringList(item.opt("server_ports")))?.takeIf { it.hops }?.let { ports ->
            params["mport"] = ports.toString()
            val min = HopInterval.parse(item.optString("hop_interval"))
            val max = HopInterval.parse(item.optString("hop_interval_max"))
            HopInterval.of(min?.min, max?.max ?: min?.max)?.let { params["hop-interval"] = it.toString() }
        }
        val q = if (params.isEmpty()) "" else "?${query(params)}"
        return "hysteria2://${encode(password)}@${hostPort(item)}$q#${label(item, name)}"
    }

    private fun tuicLink(item: JSONObject, name: String): String {
        val uuid = required(item, "uuid")
        val params = LinkedHashMap<String, String>()
        tlsParams(item, params, "insecure", mandatory = true)
        // The usual TUIC link parameters; which of them a profile keeps is
        // the link parser's business, as it is for a pasted link.
        item.optString("congestion_control").takeIf { it.isNotEmpty() }?.let { params["congestion_control"] = it }
        item.optString("udp_relay_mode").takeIf { it.isNotEmpty() }?.let { params["udp_relay_mode"] = it }
        val q = if (params.isEmpty()) "" else "?${query(params)}"
        return "tuic://${encode(uuid)}:${encode(item.optString("password"))}@${hostPort(item)}$q#${label(item, name)}"
    }

    private fun anyTlsLink(item: JSONObject, name: String): String {
        val password = required(item, "password")
        val params = LinkedHashMap<String, String>()
        tlsParams(item, params, "insecure", mandatory = true)
        val q = if (params.isEmpty()) "" else "?${query(params)}"
        return "anytls://${encode(password)}@${hostPort(item)}$q#${label(item, name)}"
    }

    /**
     * WireGuard in either of sing-box's shapes: the legacy `wireguard`
     * outbound (`server`, `local_address`, `peer_public_key`, or a `peers`
     * list) and the 1.11+ endpoint (`address`, `peers[{address, port, ...}]`).
     * The first peer is used, as the INI parser does with several.
     */
    private fun wireGuardConfig(item: JSONObject, name: String): ProxyConfiguration {
        val peer = item.optJSONArray("peers")?.optJSONObject(0)
        val host = (peer?.optString("address")?.takeIf { it.isNotEmpty() }
            ?: peer?.optString("server")?.takeIf { it.isNotEmpty() }
            ?: item.optString("server"))
            .ifEmpty { throw ProxyError.InvalidUrl("wireguard: no server address") }
        val port = (peer?.optInt("port", 0)?.takeIf { it > 0 }
            ?: peer?.optInt("server_port", 0)?.takeIf { it > 0 }
            ?: item.optInt("server_port", 0)).takeIf { it in 1..65535 }
            ?: throw ProxyError.InvalidUrl("wireguard: no server port")
        val publicKey = peer?.optString("public_key")?.takeIf { it.isNotEmpty() }
            ?: item.optString("peer_public_key").ifEmpty { throw ProxyError.InvalidUrl("wireguard: peer public key is missing") }

        val ini = WireGuardIni.build(
            privateKey = item.optString("private_key"),
            addresses = XrayJsonImporter.stringList(item.opt("address") ?: item.opt("local_address")),
            peer = WireGuardIni.Peer(
                publicKey = publicKey,
                endpointHost = host,
                endpointPort = port,
                presharedKey = (peer?.optString("pre_shared_key")?.takeIf { it.isNotEmpty() }
                    ?: item.optString("pre_shared_key")).takeIf { it.isNotEmpty() },
                allowedIps = XrayJsonImporter.stringList(peer?.opt("allowed_ips")),
                keepalive = peer?.optInt("persistent_keepalive_interval", 0) ?: 0
            ),
            mtu = item.optInt("mtu", 0).takeIf { it > 0 },
            reserved = WireGuardIni.reservedFromJson(peer?.opt("reserved") ?: item.opt("reserved"))
        )
        return ProxyConfiguration.fromWireGuardConfig(ini, name.ifEmpty { WireGuardIni.endpoint(host, port) })
    }
}
