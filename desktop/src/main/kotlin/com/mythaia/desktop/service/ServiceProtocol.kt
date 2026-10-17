package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * What the window and the service say to each other: one JSON object per
 * line, over the named pipe `\\.\pipe\MythaiaService` on Windows and the
 * Unix socket [SOCKET_PATH] on macOS ([ServiceTransport]). The service holds
 * no configuration of its own; every start carries the settings, the server
 * and the rules it is to use.
 */
object ServiceProtocol {
    const val PIPE_NAME = "\\\\.\\pipe\\MythaiaService"

    /** The macOS daemon's socket, in a directory only root can write to. */
    const val SOCKET_PATH = "/var/run/mythaia/service.sock"

    /** The group whose members may connect to [SOCKET_PATH]: every account that signs in on a Mac. */
    const val SOCKET_GROUP = "staff"
    const val SERVICE_NAME = "MythaiaService"
    const val DISPLAY_NAME = "Mythaia Pro Service"
    const val VERSION = 1

    val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    @Serializable
    data class Request(
        /** `status`, `start`, `switch`, `stop`, `routing`, `ping`. */
        val cmd: String,
        val settings: DesktopSettings? = null,
        val configuration: ProxyConfiguration? = null,
        val rules: List<RouteRule>? = null,
        /** Log lines after this sequence number are returned. */
        val logSince: Long = 0
    )

    @Serializable
    data class LogEntry(val seq: Long, val time: Long, val level: String, val text: String)

    @Serializable
    data class Response(
        val ok: Boolean,
        val error: String? = null,
        val version: Int = VERSION,
        /** The service's Mythaia Pro version, so the window can tell an outdated copy; absent before 1.1.2. */
        val appVersion: String? = null,
        val running: Boolean = false,
        val status: String = "STOPPED",
        val configurationId: String? = null,
        val up: Long = 0,
        val down: Long = 0,
        val connections: Int = 0,
        val lastError: String? = null,
        val logs: List<LogEntry> = emptyList()
    )
}
