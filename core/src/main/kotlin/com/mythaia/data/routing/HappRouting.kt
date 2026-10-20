package com.mythaia.data.routing

import com.mythaia.vpn.util.decodeBase64Lenient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.util.Base64

/**
 * Happ's routing links and profile JSON.
 *
 * ```
 * happ://routing/add/{base64 JSON}     add the profile
 * happ://routing/onadd/{base64 JSON}   add it and turn it on
 * happ://routing/off                   turn routing profiles off
 * ```
 *
 * A subscription sends the same link in its `routing` header, in a
 * `#routing:` body line, or as a line of the body on its own.
 */
object HappRouting {

    sealed class Command {
        data class Add(val profile: RoutingProfile, val activate: Boolean) : Command()
        object Off : Command()
    }

    const val PREFIX = "happ://routing/"
    const val DEFAULT_NAME = "Routing"

    private const val MAX_JSON = 1024 * 1024
    private const val MAX_RULES = 20_000
    private const val MAX_RULE_LENGTH = 1024
    private const val MAX_NAME = 60
    private const val MAX_HOSTS = 1000

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /** Whether [text] is one of the links above. */
    fun isLink(text: String): Boolean = text.trim().startsWith(PREFIX, ignoreCase = true)

    /**
     * The command in [link], or null when it is not a routing link or its
     * profile does not parse. [fallbackName] names a profile that has no
     * `Name` (Happ's default profile has none).
     */
    fun parseLink(link: String, fallbackName: String? = null): Command? {
        val trimmed = link.trim()
        if (!isLink(trimmed)) return null
        val rest = trimmed.substring(PREFIX.length)
        val action = rest.substringBefore('/').substringBefore('?').lowercase()
        val payload = rest.substringAfter('/', "")
        return when (action) {
            "off" -> Command.Off
            "add", "onadd" -> {
                val profile = parsePayload(payload, fallbackName) ?: return null
                Command.Add(profile, activate = action == "onadd")
            }
            else -> null
        }
    }

    /**
     * A subscription's `routing` value: one of the links, or — leniently —
     * the profile itself, as base64 or JSON, which then is added and turned on.
     */
    fun parseSubscriptionValue(value: String, fallbackName: String? = null): Command? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        if (isLink(trimmed)) return parseLink(trimmed, fallbackName)
        return parsePayload(trimmed, fallbackName)?.let { Command.Add(it, activate = true) }
    }

    /** Base64 (either alphabet, padded or not, percent-encoded or not) or plain JSON. */
    private fun parsePayload(payload: String, fallbackName: String?): RoutingProfile? {
        val text = payload.trim().substringBefore('#').let { p ->
            if ('%' in p) runCatching { java.net.URLDecoder.decode(p.replace("+", "%2B"), "UTF-8") }.getOrDefault(p) else p
        }.trim()
        if (text.isEmpty() || text.length > MAX_JSON * 2) return null
        if (text.startsWith("{")) return parseJson(text, fallbackName)
        for (urlSafe in booleanArrayOf(false, true)) {
            val decoded = runCatching { String(decodeBase64Lenient(text, urlSafe), Charsets.UTF_8) }.getOrNull() ?: continue
            if (decoded.trimStart().startsWith("{")) parseJson(decoded, fallbackName)?.let { return it }
        }
        return null
    }

    /**
     * A profile from Happ's JSON. Keys are matched case-insensitively and
     * flags may be strings ("true") or booleans; lists may be arrays or one
     * comma-separated string. Null when [text] is not a JSON object.
     */
    fun parseJson(text: String, fallbackName: String? = null): RoutingProfile? {
        if (text.length > MAX_JSON) return null
        val root = runCatching { json.parseToJsonElement(text) }.getOrNull() as? JsonObject ?: return null
        val fields = root.entries.associate { (k, v) -> k.lowercase() to v }

        fun string(key: String): String? = (fields[key.lowercase()] as? JsonPrimitive)
            ?.takeIf { it !is JsonNull }?.content?.trim()?.takeIf { it.isNotEmpty() }
        fun flag(key: String, default: Boolean): Boolean {
            val value = string(key)?.lowercase() ?: return default
            return when (value) {
                "true", "1", "yes", "on" -> true
                "false", "0", "no", "off" -> false
                else -> default
            }
        }
        fun list(key: String): List<String> {
            val raw: List<String> = when (val element = fields[key.lowercase()]) {
                is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p !is JsonNull }?.content }
                is JsonPrimitive -> if (element is JsonNull) emptyList() else element.content.split(',', '\n')
                else -> emptyList()
            }
            return raw.asSequence().map { it.trim() }
                .filter { it.isNotEmpty() && it.length <= MAX_RULE_LENGTH }
                .distinct().take(MAX_RULES).toList()
        }
        fun dns(prefix: String): RoutingProfile.Dns? {
            val type = string("${prefix}DNSType") ?: return null
            return RoutingProfile.Dns(
                type = type,
                domain = string("${prefix}DNSDomain"),
                ip = string("${prefix}DNSIP")
            )
        }
        fun https(key: String): String? = string(key)?.takeIf { it.startsWith("https://", ignoreCase = true) && it.length <= 2048 }

        val hosts = (fields["dnshosts"] as? JsonObject)?.entries?.asSequence()
            ?.mapNotNull { (host, address) ->
                val first = when (address) {
                    is JsonArray -> (address.firstOrNull() as? JsonPrimitive)?.content
                    is JsonPrimitive -> if (address is JsonNull) null else address.content
                    else -> null
                }?.trim()
                val name = host.trim().lowercase().trimEnd('.')
                if (name.isEmpty() || first.isNullOrEmpty() || IpRanges.parseAddress(first) == null) null else name to first
            }
            ?.take(MAX_HOSTS)?.toMap().orEmpty()

        val strategy = when (string("DomainStrategy")?.lowercase()) {
            "asis" -> RoutingProfile.STRATEGY_AS_IS
            "ipondemand" -> RoutingProfile.STRATEGY_IP_ON_DEMAND
            else -> RoutingProfile.STRATEGY_IP_IF_NON_MATCH
        }

        return RoutingProfile(
            name = (string("Name") ?: fallbackName?.trim()?.takeIf { it.isNotEmpty() } ?: DEFAULT_NAME).take(MAX_NAME),
            globalProxy = flag("GlobalProxy", default = true),
            directSites = list("DirectSites"),
            directIp = list("DirectIp"),
            proxySites = list("ProxySites"),
            proxyIp = list("ProxyIp"),
            blockSites = list("BlockSites"),
            blockIp = list("BlockIp"),
            domainStrategy = strategy,
            dnsHosts = hosts,
            fakeDns = flag("FakeDNS", default = false),
            remoteDns = dns("Remote"),
            domesticDns = dns("Domestic"),
            geoipUrl = https("Geoipurl"),
            geositeUrl = https("Geositeurl"),
            lastUpdated = string("LastUpdated")?.toLongOrNull()?.let { if (it > 100_000_000_000L) it / 1000 else it }?.takeIf { it > 0 }
        )
    }

    /** [profile] as Happ's JSON, the keys spelt as Happ spells them. */
    fun toJson(profile: RoutingProfile): String {
        val obj = buildJsonObject {
            put("Name", profile.name)
            put("GlobalProxy", profile.globalProxy.toString())
            profile.remoteDns?.let { dns ->
                put("RemoteDNSType", dns.type)
                put("RemoteDNSDomain", dns.domain ?: "")
                put("RemoteDNSIP", dns.ip ?: "")
            }
            profile.domesticDns?.let { dns ->
                put("DomesticDNSType", dns.type)
                put("DomesticDNSDomain", dns.domain ?: "")
                put("DomesticDNSIP", dns.ip ?: "")
            }
            put("Geoipurl", profile.geoipUrl ?: "")
            put("Geositeurl", profile.geositeUrl ?: "")
            put("LastUpdated", profile.lastUpdated?.toString() ?: "")
            putJsonObject("DnsHosts") { profile.dnsHosts.forEach { (k, v) -> put(k, v) } }
            putJsonArray("DirectSites") { profile.directSites.forEach { add(JsonPrimitive(it)) } }
            putJsonArray("DirectIp") { profile.directIp.forEach { add(JsonPrimitive(it)) } }
            putJsonArray("ProxySites") { profile.proxySites.forEach { add(JsonPrimitive(it)) } }
            putJsonArray("ProxyIp") { profile.proxyIp.forEach { add(JsonPrimitive(it)) } }
            putJsonArray("BlockSites") { profile.blockSites.forEach { add(JsonPrimitive(it)) } }
            putJsonArray("BlockIp") { profile.blockIp.forEach { add(JsonPrimitive(it)) } }
            put("DomainStrategy", profile.domainStrategy)
            put("FakeDNS", profile.fakeDns.toString())
        }
        return obj.toString()
    }

    /** The link that adds [profile] (and turns it on with [activate]), for sharing it on. */
    fun toLink(profile: RoutingProfile, activate: Boolean = false): String =
        PREFIX + (if (activate) "onadd/" else "add/") +
            Base64.getEncoder().encodeToString(toJson(profile).toByteArray(Charsets.UTF_8))
}
