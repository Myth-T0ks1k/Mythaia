package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import java.io.ByteArrayOutputStream

/**
 * The address and country the internet sees through a server.
 *
 * "Connected" says the tunnel is up; this says where it comes out, which is
 * what people actually check (and what tells a working server from one
 * whose exit is the user's own country). ip-api.com over plain HTTP: no key,
 * no TLS to the destination, a few hundred bytes.
 */
object ExitIpProbe {

    data class ExitInfo(val ip: String, val countryCode: String?, val country: String?)

    private const val HOST = "ip-api.com"
    private const val PATH = "/json/?fields=status,query,countryCode,country"
    private const val TIMEOUT_MS = 10_000L

    /** Dials through [config] itself, so the answer is that server's exit whatever the split tunnel says. */
    suspend fun throughServer(config: ProxyConfiguration): ExitInfo? = withContext(Dispatchers.IO) {
        if (config.outboundProtocol.isLayer3 || !config.chain.isNullOrEmpty()) return@withContext null
        withTimeoutOrNull(TIMEOUT_MS) {
            runCatching {
                val resolved = if (config.resolvedIP != null || DnsCache.isIpAddress(config.serverAddress)) config
                else DnsCache.resolveHost(config.serverAddress)?.let { config.copy(resolvedIP = it) } ?: config
                val connection = ProxyClientFactory.connect(resolved, HOST, 80)
                try {
                    connection.send(request())
                    val out = ByteArrayOutputStream()
                    while (out.size() < 16 * 1024) {
                        val chunk = connection.receive() ?: break
                        out.write(chunk)
                        if (parse(out.toByteArray()) != null) break
                    }
                    parse(out.toByteArray())
                } finally {
                    connection.cancel()
                }
            }.getOrNull()
        }
    }

    /** Through whatever route this process has — the tunnel, for an app inside it. */
    suspend fun throughDefaultRoute(): ExitInfo? = withContext(Dispatchers.IO) {
        withTimeoutOrNull(TIMEOUT_MS) {
            runCatching {
                val connection = java.net.URL("http://$HOST$PATH").openConnection(java.net.Proxy.NO_PROXY)
                    as java.net.HttpURLConnection
                connection.connectTimeout = 8_000
                connection.readTimeout = 8_000
                try {
                    parseBody(connection.inputStream.bufferedReader().readText())
                } finally {
                    connection.disconnect()
                }
            }.getOrNull()
        }
    }

    private fun request(): ByteArray =
        "GET $PATH HTTP/1.1\r\nHost: $HOST\r\nUser-Agent: Mythaia\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)

    /** The answer once the whole JSON body is in, else null. */
    internal fun parse(response: ByteArray): ExitInfo? {
        val text = String(response, Charsets.UTF_8)
        val start = text.indexOf('{')
        val end = text.lastIndexOf('}')
        if (start < 0 || end <= start) return null
        return parseBody(text.substring(start, end + 1))
    }

    internal fun parseBody(body: String): ExitInfo? {
        val json = runCatching { JSONObject(body) }.getOrNull() ?: return null
        if (json.optString("status") == "fail") return null
        val ip = json.optString("query").takeIf { it.isNotBlank() } ?: return null
        return ExitInfo(
            ip = ip,
            countryCode = json.optString("countryCode").takeIf { it.length == 2 },
            country = json.optString("country").takeIf { it.isNotBlank() }
        )
    }
}
