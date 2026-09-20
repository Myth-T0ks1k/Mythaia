package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.util.Base64

/**
 * Imports Xray / v2ray JSON: a whole config (`{"outbounds": [...]}`, the
 * shape v2rayNG's "custom config" and every panel export use), one outbound
 * object, or an array of outbounds.
 *
 * Each outbound becomes the share link it is equivalent to and goes through
 * the same link parser as a pasted `vless://`, so the two paths cannot
 * disagree about what a field means. `sockopt.dialerProxy` is honoured: a
 * `freedom` outbound with `fragment` settings becomes the server's
 * ClientHello fragmentation, and another proxy outbound becomes the entry
 * hop of a chain.
 */
object XrayJsonImporter {

    private val PROXY_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http")

    /** Whether [text] is worth handing to [parse]: a JSON object or array. */
    fun looksLikeJson(text: String): Boolean {
        val t = text.trimStart()
        return (t.startsWith("{") || t.startsWith("[")) && (t.contains("\"protocol\"") || t.contains("\"outbounds\""))
    }

    /** One config per usable outbound. Throws [ProxyError.InvalidUrl] when nothing usable is there. */
    fun parse(text: String): List<ProxyConfiguration> {
        val root = parseRoot(text)
        val outbounds = collectOutbounds(root)
        if (outbounds.isEmpty()) throw ProxyError.InvalidUrl("No outbounds found in the JSON")

        val byTag = outbounds.filter { it.optString("tag").isNotEmpty() }.associateBy { it.getString("tag") }
        val errors = ArrayList<String>()
        val configurations = ArrayList<ProxyConfiguration>()
        for (outbound in outbounds) {
            val protocol = outbound.optString("protocol").lowercase()
            if (protocol !in PROXY_PROTOCOLS) continue
            // A hop that only exists to carry another outbound is imported
            // as part of that outbound's chain, not as a server of its own.
            if (outbounds.any { dialerProxyOf(it) == outbound.optString("tag") && it !== outbound }) continue
            try {
                configurations += convert(outbound, byTag, depth = 0)
            } catch (e: ProxyError) {
                errors += "${outbound.optString("tag").ifEmpty { protocol }}: ${e.message}"
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

    // ------------------------------------------------------------- parsing

    private fun parseRoot(text: String): Any {
        val trimmed = text.trim()
        runCatching { return parseAny(trimmed) }
        // Xray accepts comments and trailing commas; org.json does not.
        val cleaned = stripComments(trimmed)
        return runCatching { parseAny(cleaned) }.getOrElse {
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
        while (i < text.length) {
            val c = text[i]
            when {
                inString -> {
                    out.append(c)
                    if (c == '\\' && i + 1 < text.length) { out.append(text[i + 1]); i++ }
                    else if (c == '"') inString = false
                }
                c == '"' -> { inString = true; out.append(c) }
                c == '/' && i + 1 < text.length && text[i + 1] == '/' -> {
                    while (i < text.length && text[i] != '\n') i++
                    continue
                }
                c == '/' && i + 1 < text.length && text[i + 1] == '*' -> {
                    val end = text.indexOf("*/", i + 2)
                    i = if (end < 0) text.length else end + 2
                    continue
                }
                else -> out.append(c)
            }
            i++
        }
        return Regex(",(\\s*[}\\]])").replace(out.toString(), "$1")
    }

    private fun collectOutbounds(root: Any): List<JSONObject> = when (root) {
        is JSONArray -> (0 until root.length()).mapNotNull { root.optJSONObject(it) }.filter { it.has("protocol") }
        is JSONObject -> when {
            root.has("outbounds") -> root.optJSONArray("outbounds")?.let { arr ->
                (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }
            } ?: emptyList()
            root.has("protocol") -> listOf(root)
            // v2rayNG exports a profile as {"outbound": {...}} in some places.
            root.has("outbound") -> listOfNotNull(root.optJSONObject("outbound"))
            else -> emptyList()
        }
        else -> emptyList()
    }

    private fun dialerProxyOf(outbound: JSONObject): String? =
        outbound.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy")
            ?.takeIf { it.isNotEmpty() }

    // ---------------------------------------------------------- conversion

    private fun convert(outbound: JSONObject, byTag: Map<String, JSONObject>, depth: Int): ProxyConfiguration {
        if (depth > 8) throw ProxyError.InvalidUrl("dialerProxy chain is too deep or circular")
        val protocol = outbound.optString("protocol").lowercase()
        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject()
        val name = outbound.optString("tag").ifEmpty { outbound.optString("remarks") }

        // What this outbound dials through.
        var fragment: String? = null
        var chain: List<ProxyConfiguration>? = null
        dialerProxyOf(outbound)?.let { tag ->
            val hop = byTag[tag] ?: throw ProxyError.InvalidUrl("dialerProxy '$tag' is not defined")
            when (hop.optString("protocol").lowercase()) {
                "freedom" -> fragment = fragmentParam(hop)
                in PROXY_PROTOCOLS -> {
                    val entry = convert(hop, byTag, depth + 1)
                    chain = (entry.chain ?: emptyList()) + entry.withChain(null)
                }
                else -> {}
            }
        }

        val link = when (protocol) {
            "vless" -> vlessLink(outbound, stream, name, fragment)
            "vmess" -> vmessLink(outbound, stream, name)
            "trojan" -> trojanLink(outbound, stream, name, fragment)
            "shadowsocks" -> shadowsocksLink(outbound, name)
            "socks" -> socksLink(outbound, name)
            "http" -> httpLink(outbound, stream, name)
            else -> throw ProxyError.InvalidUrl("$protocol outbounds are not supported")
        }
        val config = ProxyConfiguration.fromUrl(link)
        return if (chain.isNullOrEmpty()) config else config.withChain(chain)
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
                tls.optString("serverName").takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
                tls.optString("fingerprint").takeIf { it.isNotEmpty() }?.let { params["fp"] = it }
                tls.optJSONArray("alpn")?.let { a -> params["alpn"] = (0 until a.length()).joinToString(",") { a.optString(it) } }
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
        return params
    }

    /** Xray's freedom `fragment` block as the link's `fragment=` value. */
    private fun fragmentParam(freedom: JSONObject): String? {
        val f = freedom.optJSONObject("settings")?.optJSONObject("fragment") ?: return null
        val length = f.optString("length").ifEmpty { "100-200" }
        val interval = f.optString("interval").ifEmpty { "10-20" }
        return "$length,$interval,tlshello"
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

    private fun httpLink(outbound: JSONObject, stream: JSONObject, name: String): String {
        val server = firstServer(outbound, "servers")
        if (stream.optString("security", "none") != "tls") {
            throw ProxyError.InvalidUrl("http: only an HTTPS proxy (security tls) is supported")
        }
        val user = server.optJSONArray("users")?.optJSONObject(0)
            ?: throw ProxyError.InvalidUrl("http: a user and password are required")
        val params = LinkedHashMap<String, String>()
        stream.optJSONObject("tlsSettings")?.optString("serverName")?.takeIf { it.isNotEmpty() }?.let { params["sni"] = it }
        val q = if (params.isEmpty()) "" else "?${query(params)}"
        return "https://${encode(user.optString("user"))}:${encode(user.optString("pass"))}@${hostPort(server)}$q#${encode(name.ifEmpty { hostPort(server) })}"
    }
}
