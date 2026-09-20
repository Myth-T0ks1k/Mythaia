package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.tun.TunEngine
import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** What the service can be asked to drive; the real one wraps [TunEngine], tests use a fake. */
interface TunControl {
    val isRunning: Boolean
    val statusName: String
    val configuration: ProxyConfiguration?
    val lastError: String?
    val stats: TrafficStats
    fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings)
    fun start(settings: DesktopSettings, configuration: ProxyConfiguration)
    fun switchTo(configuration: ProxyConfiguration)
    fun stop()
}

class LocalTunControl(private val engine: TunEngine) : TunControl {
    override val isRunning: Boolean get() = engine.isRunning
    override val statusName: String get() = engine.status.value.name
    override val configuration: ProxyConfiguration? get() = engine.configuration
    override val lastError: String? get() = engine.lastError.value
    override val stats: TrafficStats get() = engine.stats
    override fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings) = engine.updateRouting(rules, settings)
    override fun start(settings: DesktopSettings, configuration: ProxyConfiguration) = engine.start(settings, configuration)
    override fun switchTo(configuration: ProxyConfiguration) = engine.switchTo(configuration)
    override fun stop() = engine.stop()
}

/**
 * The service's request loop: accepts one window connection at a time on
 * the named pipe and answers each line. Log lines are kept in a ring so the
 * window can show what the service did.
 */
class ServiceCore(private val control: TunControl, private val pipeName: String = ServiceProtocol.PIPE_NAME) {
    private val logger = MythaiaLogger("Service")
    private val running = AtomicBoolean(false)
    private val logSeq = AtomicLong(0)
    private val logs = ArrayDeque<ServiceProtocol.LogEntry>()
    private val logLock = Any()

    fun record(level: MythaiaLogger.Level, text: String) {
        synchronized(logLock) {
            logs.addLast(ServiceProtocol.LogEntry(logSeq.incrementAndGet(), System.currentTimeMillis(), level.name, text))
            while (logs.size > MAX_LOGS) logs.removeFirst()
        }
    }

    /** Serves until [stop]; each client connection is one or more request lines. */
    fun serve() {
        running.set(true)
        logger.info("Listening on $pipeName")
        while (running.get()) {
            val connection = try {
                NamedPipe.accept(pipeName)
            } catch (e: Exception) {
                if (running.get()) {
                    logger.error("Pipe accept failed: ${e.message}")
                    Thread.sleep(500)
                }
                continue
            }
            connection.use { client ->
                while (running.get()) {
                    val line = client.readLine() ?: break
                    val reply = handle(line)
                    try {
                        client.writeLine(reply)
                    } catch (e: Exception) {
                        break
                    }
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        runCatching { control.stop() }
        // Unblock accept() by connecting once.
        runCatching { NamedPipe.exchange(pipeName, """{"cmd":"ping"}""", 500) }
    }

    /** The reply line for one request line. */
    fun handle(line: String): String {
        val request = try {
            ServiceProtocol.json.decodeFromString(ServiceProtocol.Request.serializer(), line)
        } catch (e: Exception) {
            return encode(ServiceProtocol.Response(ok = false, error = "bad request: ${e.message}"))
        }
        val response = try {
            when (request.cmd) {
                "ping", "status" -> status(ok = true, since = request.logSince)
                "routing" -> {
                    val settings = request.settings ?: throw IllegalArgumentException("settings missing")
                    control.updateRouting(request.rules.orEmpty(), settings)
                    status(ok = true, since = request.logSince)
                }
                "start" -> {
                    val settings = request.settings ?: throw IllegalArgumentException("settings missing")
                    val configuration = request.configuration ?: throw IllegalArgumentException("configuration missing")
                    control.updateRouting(request.rules.orEmpty(), settings)
                    control.start(settings, configuration)
                    status(ok = true, since = request.logSince)
                }
                "switch" -> {
                    val configuration = request.configuration ?: throw IllegalArgumentException("configuration missing")
                    control.switchTo(configuration)
                    status(ok = true, since = request.logSince)
                }
                "stop" -> {
                    control.stop()
                    status(ok = true, since = request.logSince)
                }
                else -> ServiceProtocol.Response(ok = false, error = "unknown command ${request.cmd}")
            }
        } catch (e: Exception) {
            logger.error("${request.cmd}: ${e.message}")
            status(ok = false, since = request.logSince, error = e.message ?: e.javaClass.simpleName)
        }
        return encode(response)
    }

    private fun status(ok: Boolean, since: Long, error: String? = null): ServiceProtocol.Response {
        val entries = synchronized(logLock) { logs.filter { it.seq > since }.toList() }
        return ServiceProtocol.Response(
            ok = ok,
            error = error,
            running = control.isRunning,
            status = control.statusName,
            configurationId = control.configuration?.id?.toString(),
            up = control.stats.up.get(),
            down = control.stats.down.get(),
            connections = control.stats.connections.get(),
            lastError = control.lastError,
            logs = entries
        )
    }

    private fun encode(response: ServiceProtocol.Response): String =
        ServiceProtocol.json.encodeToString(ServiceProtocol.Response.serializer(), response)

    companion object {
        private const val MAX_LOGS = 400
    }
}
