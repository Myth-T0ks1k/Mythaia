package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.vpn.util.MythaiaLogger
import java.io.IOException

/** The window's side of the pipe. Every call is one short connection. */
object ServiceClient {
    private val logger = MythaiaLogger("ServiceClient")

    /** The pipe the calls go to; tests point it at a pipe of their own. */
    @Volatile
    internal var pipeName: String = ServiceProtocol.PIPE_NAME

    /** No answer: the service is not there, or never got to the request. */
    class NoAnswer(message: String) : IOException(message)

    /** Whether the service is up and answering. */
    fun isAvailable(): Boolean = runCatching { ping() != null }.getOrDefault(false)

    fun ping(): ServiceProtocol.Response? = send(ServiceProtocol.Request("ping"), timeoutMs = 1_500)

    fun status(logSince: Long): ServiceProtocol.Response? = send(ServiceProtocol.Request("status", logSince = logSince), timeoutMs = 3_000)

    /**
     * Starts the tunnel. The service answers one request at a time, and on
     * a slow PC (the adapter, DNS, routes) a start can take longer than
     * [timeoutMs]; giving up then left a tunnel running that the window did
     * not know about. So a start the service took but did not answer is
     * followed by status requests for up to [settleMs]: a tunnel that came
     * up with [configuration] is adopted as if the start had answered, and
     * anything else ends in an [IOException]. [NoAnswer] means the service
     * said nothing at all; a tunnel it may still bring up is then the
     * caller's to stop.
     */
    @Throws(IOException::class)
    fun start(
        settings: DesktopSettings,
        configuration: ProxyConfiguration,
        rules: List<RouteRule>,
        timeoutMs: Long = START_TIMEOUT_MS,
        settleMs: Long = LATE_START_WAIT_MS
    ): ServiceProtocol.Response {
        val reply = try {
            exchange(ServiceProtocol.Request("start", settings, configuration, rules), timeoutMs)
        } catch (e: NamedPipe.NoReply) {
            logger.warning("No answer to start within $timeoutMs ms; asking the service what it did")
            val status = awaitStatus(settleMs) ?: throw NoAnswer("service is not answering")
            return when (lateStartVerdict(status, configuration)) {
                LateStart.ADOPT -> status.also { logger.info("The service finished starting late; its tunnel is used") }
                LateStart.OTHER -> throw IOException("the service runs another tunnel")
                LateStart.FAILED -> throw IOException(status.lastError ?: "the service did not start the tunnel")
            }
        }
        return require(reply)
    }

    internal enum class LateStart { ADOPT, OTHER, FAILED }

    /** What a start that went unanswered turned out to do, by the status that followed it. */
    internal fun lateStartVerdict(status: ServiceProtocol.Response, wanted: ProxyConfiguration): LateStart = when {
        status.running && status.configurationId == wanted.id.toString() -> LateStart.ADOPT
        status.running -> LateStart.OTHER
        else -> LateStart.FAILED
    }

    /**
     * Status, asked until the service answers or [waitMs] passes. While it
     * is still busy with an earlier request no pipe instance is listening,
     * so each try ends soon and the next follows.
     */
    private fun awaitStatus(waitMs: Long): ServiceProtocol.Response? {
        val deadline = System.nanoTime() + waitMs * 1_000_000
        while (true) {
            val left = (deadline - System.nanoTime()) / 1_000_000
            if (left <= 0) return null
            send(ServiceProtocol.Request("status"), timeoutMs = minOf(left, 3_000))?.let { return it }
            Thread.sleep(minOf(250, left))
        }
    }

    @Throws(IOException::class)
    fun switchTo(configuration: ProxyConfiguration): ServiceProtocol.Response =
        require(send(ServiceProtocol.Request("switch", configuration = configuration), timeoutMs = 15_000))

    @Throws(IOException::class)
    fun updateRouting(settings: DesktopSettings, rules: List<RouteRule>): ServiceProtocol.Response =
        require(send(ServiceProtocol.Request("routing", settings = settings, rules = rules), timeoutMs = 5_000))

    fun stop(): ServiceProtocol.Response? = send(ServiceProtocol.Request("stop"), timeoutMs = 20_000)

    private fun require(response: ServiceProtocol.Response?): ServiceProtocol.Response {
        val r = response ?: throw NoAnswer("service is not answering")
        if (!r.ok) throw IOException(r.error ?: r.lastError ?: "service refused")
        return r
    }

    private fun send(request: ServiceProtocol.Request, timeoutMs: Long): ServiceProtocol.Response? =
        try {
            exchange(request, timeoutMs)
        } catch (e: NamedPipe.NoReply) {
            logger.debug("pipe: ${e.message}")
            null
        }

    /**
     * [send], except that a request the service took and did not answer in
     * time ends in [NamedPipe.NoReply]: it may still be at work on it.
     */
    private fun exchange(request: ServiceProtocol.Request, timeoutMs: Long): ServiceProtocol.Response? {
        val line = ServiceProtocol.json.encodeToString(ServiceProtocol.Request.serializer(), request)
        val reply = try {
            NamedPipe.exchange(pipeName, line, timeoutMs)
        } catch (e: NamedPipe.NoReply) {
            throw e
        } catch (e: Exception) {
            logger.debug("pipe: ${e.message}")
            null
        } ?: return null
        return runCatching { ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), reply) }
            .onFailure { logger.warning("Bad service reply: ${it.message}") }
            .getOrNull()
    }

    /** How long a start is waited for before the service is asked what it did. */
    private const val START_TIMEOUT_MS = 30_000L

    /** How long, after that, the service gets to answer a status request. */
    private const val LATE_START_WAIT_MS = 60_000L
}
