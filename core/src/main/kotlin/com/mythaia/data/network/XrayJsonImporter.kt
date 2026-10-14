package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.WireGuardIni
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.util.Base64

/**
 * Imports Xray / v2ray JSON: a whole config (`{"outbounds": [...]}`, the
 * shape v2rayNG's "custom config" and every panel export use), an array of
 * whole configs (a JSON subscription: one config per server, each named by
 * its `remarks`), one outbound object, or an array of outbounds.
 *
 * Each outbound becomes the share link it is equivalent to and goes through
 * the same link parser as a pasted `vless://`, so the two paths cannot
 * disagree about what a field means. `sockopt.dialerProxy` is honoured: a
 * `freedom` outbound with `fragment` settings becomes the server's
 * ClientHello fragmentation, and another proxy outbound becomes the entry
 * hop of a chain. A sing-box config handed in here is passed on to
 * [SingBoxJsonImporter], so a caller that only knows this importer (the
 * paste box, the desktop import) reads both.
 */
object XrayJsonImporter {

    private val PROXY_PROTOCOLS = setOf(
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "hysteria2", "wireguard"
    )

    /**
     * Whether [text] is worth handing to [parse]: a JSON object or array of
     * Xray or sing-box outbounds. A lone sing-box outbound has neither
     * `protocol` nor `outbounds`, only `type` and `server`.
     */
    fun looksLikeJson(text: String): Boolean {
        if (!startsLikeJson(text)) return false
        return text.contains("\"protocol\"") || text.contains("\"outbounds\"") || text.contains("\"endpoints\"") ||
            (text.contains("\"type\"") && text.contains("\"server\""))
    }

    /**
     * Whether the first thing past any whitespace opens an object or array.
     * Looked up in place: trimStart() copied the whole body, megabytes for a
     * subscription of thousands of servers, on every check.
     */
    internal fun startsLikeJson(text: String): Boolean {
        val first = text.indexOfFirst { !it.isWhitespace() }
        return first >= 0 && (text[first] == '{' || text[first] == '[')
    }

    /** One config per usable outbound. Throws [ProxyError.InvalidUrl] when nothing usable is there. */
    fun parse(text: String): List<ProxyConfiguration> = parse(parseJson(text))

    /** [parse] of a tree [parseJson] already built, for a caller that looked into it first. */
    internal fun parse(root: Any): List<ProxyConfiguration> {
        if (SingBoxJsonImporter.isSingBox(root)) return SingBoxJsonImporter.parse(root)

        val documents = collectDocuments(root)
        if (documents.all { it.outbounds.isEmpty() }) throw ProxyError.InvalidUrl("No outbounds found in the JSON")

        val errors = ArrayList<String>()
        val configurations = ArrayList<ProxyConfiguration>()
        for (document in documents) {
            val outbounds = document.outbounds
            // Tags are only unique within one config: every entry of a JSON
            // subscription calls its server "proxy".
            val byTag = outbounds.filter { it.optString("tag").isNotEmpty() }.associateBy { it.getString("tag") }
            // How many outbounds dial through each tag, counted once. Asking
            // every outbound about every other was quadratic, and a config of
            // thousands of servers froze the import.
            val dialers = outbounds.mapNotNull { dialerProxyOf(it) }.groupingBy { it }.eachCount()
            val servers = outbounds.filter { outbound ->
                val tag = outbound.optString("tag")
                // One that names itself is not carrying another, and is left
                // for convert() to refuse as circular.
                val others = (dialers[tag] ?: 0) - (if (dialerProxyOf(outbound) == tag) 1 else 0)
                outbound.optString("protocol").lowercase() in PROXY_PROTOCOLS &&
                    // A hop that only exists to carry another outbound is imported
                    // as part of that outbound's chain, not as a server of its own.
                    others == 0
            }
            servers.forEachIndexed { index, outbound ->
                val name = nameOf(outbound, document.remarks, index, servers.size)
                try {
                    configurations += convert(outbound, byTag, name, depth = 0)
                } catch (e: ProxyError) {
                    val label = name.ifEmpty { outbound.optString("protocol") }
                    errors += "$label: ${e.message}"
                }
            }
        }
        if (configurations.isEmpty()) {
            throw ProxyError.InvalidUrl(
                if (errors.isEmpty()) "No proxy outbound in the JSON (only freedom/blackhole/dns)"
                else errors.joinToString("; ")
            )
        }
        return configurations
    }

    /**
     * What to call a server.
     *
     * A config's `remarks` is the name the panel gave it, and every outbound
     * in it is tagged something generic (`proxy`, `proxy-3`) for routing
     * rules, so the remarks win. A balancer config holds several servers
     * under one remarks; they are told apart by their place in it, which is
     * stable across refreshes where the tags are not meant to be read.
     * Without remarks the tag is used, and without a tag the link builder
     * falls back to `host:port`.
     */
    private fun nameOf(outbound: JSONObject, remarks: String?, index: Int, count: Int): String = when {
        remarks.isNullOrEmpty() -> outbound.optString("tag").ifEmpty { outbound.optString("remarks").trim() }
        count == 1 -> remarks
        else -> "$remarks · ${index + 1}"
    }

    // ------------------------------------------------------------- parsing

    /** JSON as Xray reads it: comments and trailing commas allowed. */
    internal fun parseJson(text: String): Any {
        val trimmed = text.trim()
        val first = runCatching { parseAny(trimmed) }
        first.getOrNull()?.let { return it }
        // Xray accepts comments and trailing commas; org.json does not.
        val cleaned = stripComments(trimmed)
        // With nothing stripped a second parse could only fail the same way,
        // after another pass over a body that can run to megabytes.
        val retry = if (cleaned == trimmed) first else runCatching { parseAny(cleaned) }
        return retry.getOrElse {
            throw ProxyError.InvalidUrl("Not valid JSON: ${it.message}")
        }
    }

    private fun parseAny(text: String): Any =
        if (text.startsWith("[")) JSONArray(text) else JSONObject(text)

    /** Removes `//` and `/* */` comments outside strings and trailing commas. */
    internal fun stripComments(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        var inString = false
        // Where the last comma outside a string landed in `out`, while only
        // whitespace (or comments, which are not copied) has followed it. A
        // closing bracket arriving then makes it a trailing comma. Done in
        // the walk rather than with a regex afterwards so a `,}` inside a
        // password is left alone.
        var pendingComma = -1
        while (i < text.length) {
            val c = text[i]
            when {
                inString -> {
                    out.append(c)
                    if (c == '\\' && i + 1 < text.length) { out.append(text[i + 1]); i++ }
                    else if (c == '"') inString = false
                }
                c == '"' -> { inString = true; pendingComma = -1; out.append(c) }
                c == '/' && i + 1 < text.length && text[i + 1] == '/' -> {
                    while (i < text.length && text[i] != '\n') i++
                    continue
                }
                c == '/' && i + 1 < text.length && text[i + 1] == '*' -> {
                    val end = text.indexOf("*/", i + 2)
                    i = if (end < 0) text.length else end + 2
                    continue
                }
                c == ',' -> { pendingComma = out.length; out.append(c) }
                (c == '}' || c == ']') && pendingComma >= 0 -> {
                    out.deleteCharAt(pendingComma)
                    pendingComma = -1
                    out.append(c)
                }
                c.isWhitespace() -> out.append(c)
                else -> { pendingComma = -1; out.append(c) }
            }
            i++
        }
        return out.toString()
    }

    /** The outbounds of one config, and the name its `remarks` gives them. */
    private class Document(val outbounds: List<JSONObject>, val remarks: String?)

    private fun collectDocuments(root: Any): List<Document> = when (root) {
        is JSONArray -> {
            val items = (0 until root.length()).mapNotNull { root.optJSONObject(it) }
            val configs = items.filter { it.has("outbounds") }.map(::documentOf)
            val bare = items.filter { it.has("protocol") }
            if (bare.isEmpty()) configs else configs + Document(bare, null)
        }
        is JSONObject -> when {
            root.has("outbounds") -> listOf(documentOf(root))
            root.has("protocol") -> listOf(Document(listOf(root), null))
            // v2rayNG exports a profile as {"outbound": {...}} in some places.
            root.has("outbound") -> listOf(Document(listOfNotNull(root.optJSONObject("outbound")), remarksOf(root)))
            else -> emptyList()
        }
        else -> emptyList()
    }

    private fun documentOf(config: JSONObject): Document {
        val arr = config.optJSONArray("outbounds")
        val outbounds = arr?.let { (0 until it.length()).mapNotNull { i -> it.optJSONObject(i) } } ?: emptyList()
        return Document(outbounds, remarksOf(config))
    }

    private fun remarksOf(config: JSONObject): String? =
        config.optString("remarks").trim().takeIf { it.isNotEmpty() }

    private fun dialerProxyOf(outbound: JSONObject): String? =
        outbound.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy")
            ?.takeIf { it.isNotEmpty() }

    // ---------------------------------------------------------- conversion

    private fun convert(outbound: JSONObject, byTag: Map<String, JSONObject>, name: String, depth: Int): ProxyConfiguration {
        if (depth > 8) throw ProxyError.InvalidUrl("dialerProxy chain is too deep or circular")
        val protocol = outbound.optString("protocol").lowercase()
        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject()

        // What this outbound dials through.
        var fragment: String? = null
        var chain: List<ProxyConfiguration>? = null
        dialerProxyOf(outbound)?.let { tag ->
            val hop = byTag[tag] ?: throw ProxyError.InvalidUrl("dialerProxy '$tag' is not defined")
            when (hop.optString("protocol").lowercase()) {
                "freedom" -> fragment = fragmentParam(hop)
                in PROXY_PROTOCOLS -> {
                    val entry = convert(hop, byTag, tag, depth + 1)
                    if (entry.outboundProtocol.isLayer3) {
                        throw ProxyError.InvalidUrl("dialerProxy '$tag' is WireGuard, which cannot carry another proxy")
                    }
                    chain = (entry.chain ?: emptyList()) + entry.withChain(null)
                }
                else -> {}
            }
        }

        val config = when (protocol) {
            // WireGuard has no link of its own worth round-tripping through;
            // it is stored as the INI a link would have become anyway.
            "wireguard" -> wireGuardConfig(outbound, name)
            else -> ProxyConfiguration.fromUrl(
                when (protocol) {
                    "vless" -> vlessLink(outbound, stream, name, fragment)
                    "vmess" -> vmessLink(outbound, stream, name)
                    "trojan" -> trojanLink(outbound, stream, name, fragment)
                    "shadowsocks" -> shadowsocksLink(outbound, name)
                    "socks" -> socksLink(outbound, name)
                    "http" -> httpLink(outbound, stream, name)
                    "hysteria", "hysteria2" -> hysteriaLink(outbound, stream, name)
                    else -> throw ProxyError.InvalidUrl("$protocol outbounds are not supported")
                }
            )
        }
        if (chain.isNullOrEmpty()) return config
        if (config.outboundProtocol.isLayer3) {
            throw ProxyError.InvalidUrl("WireGuard is a whole interface and cannot be dialled through another proxy")
        }
        return config.withChain(chain)
    }

    private fun firstServer(outbound: JSONObject, key: String): JSONObject =
        outbound.optJSONObject("settings")?.optJSONArray(key)?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("${outbound.optString("protocol")}: settings.$key is empty")

    private fun hostPort(server: JSONObject): String {
        val address = server.optString("address").ifEmpty { throw ProxyError.InvalidUrl("server address is missing") }
        val port = server.optInt("port", 0)
        if (port !in 1..65535) throw ProxyError.InvalidUrl("server port is missing")
        val host = if (address.contains(':') && !address.startsWith("[")) "[$address]" else address
        return "$host:$port"
    }

    /** The query a share link would carry for these stream settings. */
    private fun streamParams(stream: JSONObject, fragment: String?): MutableMap<String, String> {
        val params = LinkedHashMap<String, String>()
        val network = stream.optString("network", "tcp").lowercase().let {
            when (it) {
                "splithttp" -> "xhttp"
                "h2", "http" -> "http"
                else -> it
            }
        }
        val security = stream.optString("security", "none").lowercase()
        params["type"] = network
        params["security"] = security

        when (network) {
            "ws" -> stream.optJSONObject("wsSettings")?.let { ws ->
                ws.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                (ws.optString("host").takeIf { it.isNotEmpty() }
                    ?: ws.optJSONObject("headers")?.optString("Host")?.takeIf { it.isNotEmpty() })
                    ?.let { params["host"] = it }
            }
            "httpupgrade" -> stream.optJSONObject("httpupgradeSettings")?.let { hu ->
                hu.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                hu.optString("host").takeIf { it.isNotEmpty() }?.let { params["host"] = it }
            }
            "xhttp" -> (stream.optJSONObject("xhttpSettings") ?: stream.optJSONObject("splithttpSettings"))?.let { x ->
                x.optString("path").takeIf { it.isNotEmpty() }?.let { params["path"] = it }
                x.optString("host").takeIf { it.isNotEmpty() }?.let { params["host"] = it }
                x.optString("mode").takeIf { it.isNotEmpty() }?.let { params["mode"] = it }
                x.optJSONObject("extra")?.let { params["extra"] = it.toString() }
            }
            "grpc", "gun" -> stream.optJSONObject("grpcSettings")?.let { g ->
                params["type"] = "grpc"
                g.optString("serviceName").takeIf { it.isNotEmpty() }?.let { params["serviceName"] = it }
                g.optString("authority").takeIf { it.isNotEmpty() }?.let { params["authority"] = it }
                if (g.optBoolean("multiMode", false)) params["mode"] = "multi"
                g.optString("user_agent").takeIf { it.isNotEmpty() }?.let { params["userAgent"] = it }
            }
            "tcp", "raw" -> {
                params["type"] = "tcp"
                val header = (stream.optJSONObject("tcpSettings") ?: stream.optJSONObject("rawSettings"))
                    ?.optJSONObject("header")?.optString("type")
                if (header != null && header != "none" && header.isNotEmpty()) {
                    throw ProxyError.InvalidUrl("tcp header type '$header' is not supported")
                }
            }
            else -> throw ProxyError.InvalidUrl("$network transport is not supported")
        }

        when (security) {
            "tls" -> stream.optJSONObject("tlsSettings")?.let { tls ->
                tlsParams(tls, params)
                if (tls.optBoolean("allowInsecure", false)) params["allowInsecure"] = "1"
            }
            "reality" -> stream.optJSONObject("realitySettings")?.let { r ->
                r.optString("serverName").takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
                r.optString("fingerprint").takeIf { it.isNotEmpty() }?.let { params["fp"] = it }
                r.optString("publicKey").takeIf { it.isNotEmpty() }?.let { params["pbk"] = it }
                r.optString("shortId").takeIf { it.isNotEmpty() }?.let { params["sid"] = it }
                r.optString("spiderX").takeIf { it.isNotEmpty() }?.let { params["spx"] = it }
            }
        }
        if (fragment != null && security == "tls") params["fragment"] = fragment
        // FinalMask travels as the link's `fm=`, the same document a share
        // link from the same panel carries, so its fragment settings land on
        // the server exactly as they would from the link.
        stream.optJSONObject("finalmask")?.takeIf { it.length() > 0 }?.let { params["fm"] = it.toString() }
        return params
    }

    /**
     * The TLS fields every protocol's link spells the same way. Certificate
     * pinning comes from `pinnedPeerCertSha256` and `verifyPeerCertByName`,
     * which Xray 26 has instead of `allowInsecure`; the caller adds the
     * insecure flag under the name its link uses.
     */
    private fun tlsParams(tls: JSONObject, params: MutableMap<String, String>) {
        tls.optString("serverName").takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
        tls.optString("fingerprint").takeIf { it.isNotEmpty() }?.let { params["fp"] = it }
        stringList(tls.opt("alpn")).takeIf { it.isNotEmpty() }?.let { params["alpn"] = it.joinToString(",") }
        stringList(tls.opt("pinnedPeerCertSha256")).takeIf { it.isNotEmpty() }?.let { params["pcs"] = it.joinToString(",") }
        tls.optString("verifyPeerCertByName").takeIf { it.isNotEmpty() }?.let { params["vcn"] = it }
    }

    /** A JSON string, comma-separated string or array of strings, as a list. */
    internal fun stringList(value: Any?): List<String> = when (value) {
        is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it)?.takeIf { v -> v != JSONObject.NULL }?.toString()?.trim() }
            .filter { it.isNotEmpty() }
        is String -> value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        else -> emptyList()
    }

    /** Xray's freedom `fragment` block as the link's `fragment=` value. */
    private fun fragmentParam(freedom: JSONObject): String? {
        val f = freedom.optJSONObject("settings")?.optJSONObject("fragment") ?: return null
        val length = f.optString("length").ifEmpty { "100-200" }
        val interval = f.optString("interval").ifEmpty { "10-20" }
        return "$length,$interval,tlshello"
    }

    /**
     * Hysteria's bandwidth as whole Mbps.
     *
     * A number is already Mbps, as in sing-box's `up_mbps` and Clash's `up`;
     * a string may carry Hysteria's own unit (`100 mbps`, `1 gbps`,
     * `500kbps`, bits per second throughout). Null for absent, zero or
     * unreadable: zero means "let the congestion controller decide", and
     * null is how the model says that.
     */
    internal fun bandwidthMbps(value: Any?): Int? {
        val mbps = when (value) {
            is Number -> value.toDouble()
            is String -> {
                val match = Regex("""^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z/]*)\s*$""").find(value) ?: return null
                val amount = match.groupValues[1].toDouble()
                when (match.groupValues[2].lowercase().removeSuffix("/s").removeSuffix("ps")) {
                    "", "m", "mb", "mbit" -> amount
                    "b", "bit" -> amount / 1_000_000
                    "k", "kb", "kbit" -> amount / 1_000
                    "g", "gb", "gbit" -> amount * 1_000
                    "t", "tb", "tbit" -> amount * 1_000_000
                    else -> return null
                }
            }
            else -> return null
        }
        if (mbps <= 0) return null
        return maxOf(1, Math.round(mbps).toInt())
    }

    private fun query(params: Map<String, String>): String =
        params.entries.joinToString("&") { (k, v) -> "$k=${encode(v)}" }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    private fun vlessLink(outbound: JSONObject, stream: JSONObject, name: String, fragment: String?): String {
        val server = firstServer(outbound, "vnext")
        val user = server.optJSONArray("users")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("vless: no user in vnext")
        val id = user.optString("id").ifEmpty { throw ProxyError.InvalidUrl("vless: user id is missing") }
        val params = streamParams(stream, fragment)
        params["encryption"] = user.optString("encryption").ifEmpty { "none" }
        user.optString("flow").takeIf { it.isNotEmpty() }?.let { params["flow"] = it }
        if (outbound.optJSONObject("mux")?.optBoolean("enabled", false) == false) params["mux"] = "false"
        return "vless://${encode(id)}@${hostPort(server)}?${query(params)}#${encode(name.ifEmpty { hostPort(server) })}"
    }

    private fun vmessLink(outbound: JSONObject, stream: JSONObject, name: String): String {
        val server = firstServer(outbound, "vnext")
        val user = server.optJSONArray("users")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("vmess: no user in vnext")
        val params = streamParams(stream, null)
        // The link has no spelling for Reality; written as `tls: ""` the
        // outbound would import as plaintext VMess and never connect.
        if (params["security"] == "reality") throw ProxyError.InvalidUrl("vmess: Reality is not supported")
        val json = JSONObject()
            .put("v", "2")
            .put("ps", name.ifEmpty { hostPort(server) })
            .put("add", server.optString("address"))
            .put("port", server.optInt("port"))
            .put("id", user.optString("id"))
            .put("aid", user.optInt("alterId", 0))
            .put("scy", user.optString("security").ifEmpty { "auto" })
            .put("net", params["type"] ?: "tcp")
            .put("type", "none")
            .put("host", params["host"] ?: "")
            .put("path", params["path"] ?: params["serviceName"] ?: "")
            .put("tls", if (params["security"] == "tls") "tls" else "")
            .put("sni", params["sni"] ?: "")
            .put("fp", params["fp"] ?: "")
            .put("alpn", params["alpn"] ?: "")
        if (params["allowInsecure"] == "1") json.put("allowInsecure", "1")
        params["pcs"]?.let { json.put("pcs", it) }
        params["vcn"]?.let { json.put("vcn", it) }
        return "vmess://" + Base64.getEncoder().encodeToString(json.toString().toByteArray(Charsets.UTF_8))
    }

    private fun trojanLink(outbound: JSONObject, stream: JSONObject, name: String, fragment: String?): String {
        val server = firstServer(outbound, "servers")
        val password = server.optString("password").ifEmpty { throw ProxyError.InvalidUrl("trojan: password is missing") }
        val params = streamParams(stream, fragment)
        if (params["security"] == "none") params["security"] = "tls"
        return "trojan://${encode(password)}@${hostPort(server)}?${query(params)}#${encode(name.ifEmpty { hostPort(server) })}"
    }

    private fun shadowsocksLink(outbound: JSONObject, name: String): String {
        val server = firstServer(outbound, "servers")
        val method = server.optString("method").ifEmpty { throw ProxyError.InvalidUrl("shadowsocks: method is missing") }
        val password = server.optString("password")
        val userInfo = Base64.getUrlEncoder().withoutPadding().encodeToString("$method:$password".toByteArray(Charsets.UTF_8))
        return "ss://$userInfo@${hostPort(server)}#${encode(name.ifEmpty { hostPort(server) })}"
    }

    private fun socksLink(outbound: JSONObject, name: String): String {
        val server = firstServer(outbound, "servers")
        val user = server.optJSONArray("users")?.optJSONObject(0)
        val auth = user?.let { "${encode(it.optString("user"))}:${encode(it.optString("pass"))}@" } ?: ""
        return "socks5://$auth${hostPort(server)}#${encode(name.ifEmpty { hostPort(server) })}"
    }

    /**
     * An HTTPS proxy as the `https://user:pass@host:port` link the naive
     * parser reads. That link has no query — a `?sni=` would be read as part
     * of the port — so the server name has to be the host itself, and one
     * that differs is refused rather than silently dropped.
     */
    private fun httpLink(outbound: JSONObject, stream: JSONObject, name: String): String {
        val server = firstServer(outbound, "servers")
        if (stream.optString("security", "none") != "tls") {
            throw ProxyError.InvalidUrl("http: only an HTTPS proxy (security tls) is supported")
        }
        val user = server.optJSONArray("users")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("http: a user and password are required")
        stream.optJSONObject("tlsSettings")?.optString("serverName")
            ?.takeIf { it.isNotEmpty() && !it.equals(server.optString("address"), ignoreCase = true) }
            ?.let { throw ProxyError.InvalidUrl("http: a server name ($it) different from the address is not supported") }
        return "https://${encode(user.optString("user"))}:${encode(user.optString("pass"))}@${hostPort(server)}#${encode(name.ifEmpty { hostPort(server) })}"
    }

    /**
     * Xray's `hysteria` outbound (Hysteria2, `version: 2`) as a `hysteria2://`
     * link.
     *
     * The server sits in `settings` itself (`address`, `port`), or in
     * `settings.servers[0]` in configs written by tools that treat it like
     * Trojan. The password is `hysteriaSettings.auth` in the stream settings;
     * Salamander comes from FinalMask's `udp` list, which is where Xray moved
     * it from Hysteria's own `obfs` block.
     */
    private fun hysteriaLink(outbound: JSONObject, stream: JSONObject, name: String): String {
        val settings = outbound.optJSONObject("settings") ?: JSONObject()
        val hysteria = stream.optJSONObject("hysteriaSettings") ?: JSONObject()
        val version = hysteria.optInt("version", settings.optInt("version", 2))
        if (version != 2) throw ProxyError.InvalidUrl("hysteria: version $version is not supported, only Hysteria2")

        val server = settings.takeIf { it.optString("address").isNotEmpty() }
            ?: settings.optJSONArray("servers")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("hysteria: server address is missing")
        val auth = hysteria.optString("auth")
            .ifEmpty { settings.optString("password") }
            .ifEmpty { settings.optString("auth") }
            .ifEmpty { server.optString("password") }
            .ifEmpty { throw ProxyError.InvalidUrl("hysteria: auth is missing") }

        val params = LinkedHashMap<String, String>()
        stream.optJSONObject("tlsSettings")?.let { tls ->
            tlsParams(tls, params)
            if (tls.optBoolean("allowInsecure", false)) params["insecure"] = "1"
        }
        stream.optJSONObject("finalmask")?.optJSONArray("udp")?.let { masks ->
            for (i in 0 until masks.length()) {
                val mask = masks.optJSONObject(i) ?: continue
                if (mask.optString("type") != "salamander") continue
                val password = mask.optJSONObject("settings")?.optString("password")?.takeIf { it.isNotEmpty() } ?: continue
                params["obfs"] = "salamander"
                params["obfs-password"] = password
                break
            }
        }
        bandwidthMbps(hysteria.opt("up"))?.let { params["upmbps"] = it.toString() }
        bandwidthMbps(hysteria.opt("down"))?.let { params["downmbps"] = it.toString() }

        val q = if (params.isEmpty()) "" else "?${query(params)}"
        return "hysteria2://${encode(auth)}@${hostPort(server)}$q#${encode(name.ifEmpty { hostPort(server) })}"
    }

    /** Xray's `wireguard` outbound, as the wg-quick INI the profile is stored as. */
    private fun wireGuardConfig(outbound: JSONObject, name: String): ProxyConfiguration {
        val settings = outbound.optJSONObject("settings")
            ?: throw ProxyError.InvalidUrl("wireguard: settings are missing")
        val peer = settings.optJSONArray("peers")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("wireguard: no peer")
        val endpointText = peer.optString("endpoint")
        val (host, port) = WireGuardIni.splitEndpoint(endpointText)
            ?: throw ProxyError.InvalidUrl("wireguard: peer endpoint '$endpointText' is not host:port")
        val ini = WireGuardIni.build(
            privateKey = settings.optString("secretKey"),
            addresses = stringList(settings.opt("address")),
            peer = WireGuardIni.Peer(
                publicKey = peer.optString("publicKey"),
                endpointHost = host,
                endpointPort = port,
                presharedKey = peer.optString("preSharedKey").takeIf { it.isNotEmpty() },
                allowedIps = stringList(peer.opt("allowedIPs")),
                keepalive = peer.optInt("keepAlive", 0)
            ),
            mtu = settings.optInt("mtu", 0).takeIf { it > 0 },
            reserved = WireGuardIni.reservedFromJson(settings.opt("reserved"))
        )
        return ProxyConfiguration.fromWireGuardConfig(ini, name.ifEmpty { WireGuardIni.endpoint(host, port) })
    }
}
