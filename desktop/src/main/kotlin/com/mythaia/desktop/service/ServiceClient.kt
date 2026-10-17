package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.vpn.util.MythaiaLogger
import java.io.IOException

/** The window's side of the pipe or socket. Every call is one short connection. */
object ServiceClient {
    private val logger = MythaiaLogger("ServiceClient")
    private val transport: ServiceTransport by lazy { ServiceTransports.forThisSystem() }

    /** Whether the service is up and answering. */
    fun isAvailable(): Boolean = runCatching { ping() != null }.getOrDefault(false)

    fun ping(): ServiceProtocol.Response? = send(ServiceProtocol.Request("ping"), timeoutMs = 1_500)

    fun status(logSince: Long): ServiceProtocol.Response? = send(ServiceProtocol.Request("status", logSince = logSince), timeoutMs = 3_000)

    @Throws(IOException::class)
    fun start(settings: DesktopSettings, configuration: ProxyConfiguration, rules: List<RouteRule>): ServiceProtocol.Response =
        require(send(ServiceProtocol.Request("start", settings, configuration, rules), timeoutMs = 30_000))

    @Throws(IOException::class)
    fun switchTo(configuration: ProxyConfiguration): ServiceProtocol.Response =
        require(send(ServiceProtocol.Request("switch", configuration = configuration), timeoutMs = 15_000))

    @Throws(IOException::class)
    fun updateRouting(settings: DesktopSettings, rules: List<RouteRule>): ServiceProtocol.Response =
        require(send(ServiceProtocol.Request("routing", settings = settings, rules = rules), timeoutMs = 5_000))

    fun stop(): ServiceProtocol.Response? = send(ServiceProtocol.Request("stop"), timeoutMs = 20_000)

    private fun require(response: ServiceProtocol.Response?): ServiceProtocol.Response {
        val r = response ?: throw IOException("service is not answering")
        if (!r.ok) throw IOException(r.error ?: r.lastError ?: "service refused")
        return r
    }

    private fun send(request: ServiceProtocol.Request, timeoutMs: Long): ServiceProtocol.Response? {
        val line = ServiceProtocol.json.encodeToString(ServiceProtocol.Request.serializer(), request)
        val reply = try {
            transport.exchange(line, timeoutMs)
        } catch (e: Exception) {
            logger.debug("${transport.address}: ${e.message}")
            null
        } ?: return null
        return runCatching { ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), reply) }
            .onFailure { logger.warning("Bad service reply: ${it.message}") }
            .getOrNull()
    }
}
