package com.mythaia.desktop.service

import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.tun.TunEngine
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.util.LogBackend
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Winsvc
import java.io.File
import java.io.PrintWriter
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/**
 * The process behind "Mythaia Pro.exe --service": a Windows service that
 * owns the TUN tunnel so the window never needs administrator rights. It
 * keeps no settings of its own — the window sends everything with each
 * start — and logs to ProgramData.
 */
object MythaiaService {
    private val logger = MythaiaLogger("ServiceMain")
    private var core: ServiceCore? = null
    private var statusHandle: Winsvc.SERVICE_STATUS_HANDLE? = null

    /** Entry for `--service` (under the service control manager). */
    fun runUnderScm(): Nothing {
        prepare()
        val entries = Winsvc.SERVICE_TABLE_ENTRY().toArray(2)
        @Suppress("UNCHECKED_CAST")
        val table = entries as Array<Winsvc.SERVICE_TABLE_ENTRY>
        table[0].lpServiceName = ServiceProtocol.SERVICE_NAME
        table[0].lpServiceProc = Winsvc.SERVICE_MAIN_FUNCTION { _, _ -> serviceMain() }
        table[0].write()
        if (!Advapi32.INSTANCE.StartServiceCtrlDispatcher(table)) {
            logger.error("StartServiceCtrlDispatcher failed: ${com.sun.jna.platform.win32.Kernel32.INSTANCE.GetLastError()}")
            exitProcess(1)
        }
        exitProcess(0)
    }

    /** Entry for `--service-console`: the same loop in a plain process, for testing. */
    fun runInConsole(): Nothing {
        prepare()
        val service = createCore()
        Runtime.getRuntime().addShutdownHook(Thread { service.stop() })
        service.serve()
        exitProcess(0)
    }

    private fun prepare() {
        val dataDir = AppPaths.programData.apply { mkdirs() }
        AppPaths.overrideDataDir = dataDir
        MythaiaLogger.backend = FileLog(File(dataDir, "service.log"))
        lockDown(dataDir)
        AppPaths.nativeLibrary()?.let { System.setProperty("mythaia.native.library", it.absolutePath) }
        runCatching { NativeBridge.nativeQuicVersion() }
        runCatching { TunEngine.cleanupLeftovers() }
        logger.info("Service starting (elevated=${TunEngine.isElevated()}, wintun=${TunEngine.isAvailable()})")
    }

    /**
     * ProgramData lets every local user create files and folders, and what
     * this directory holds — the route snapshot above all — is acted on as
     * SYSTEM. So it is owned by SYSTEM and writable by SYSTEM and
     * administrators only, with inheritance cut and any permissions the
     * creator of the folder gave themselves reset first. SIDs, not names:
     * the names are localised. A failure is logged and left at that — the
     * snapshot's owner check does not depend on this.
     */
    private fun lockDown(dir: File) {
        val path = dir.absolutePath
        val steps = listOf(
            listOf("icacls", path, "/setowner", "*S-1-5-18", "/q"),
            listOf("icacls", path, "/reset", "/q"),
            listOf("icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/q")
        )
        for (argv in steps) {
            val result = com.mythaia.desktop.tun.WindowsNet.run(argv)
            if (!result.ok) {
                logger.error("Could not secure $path (${argv[2]}): ${result.output.lineSequence().firstOrNull { it.isNotBlank() } ?: "exit ${result.exitCode}"}")
                return
            }
        }
    }

    private fun createCore(): ServiceCore {
        val engine = TunEngine(TrafficStats())
        val service = ServiceCore(LocalTunControl(engine))
        val fileLog = MythaiaLogger.backend
        // Every log line also goes to the ring the window reads.
        MythaiaLogger.backend = object : LogBackend {
            override fun log(level: MythaiaLogger.Level, category: String, message: String) {
                fileLog.log(level, category, message)
                service.record(level, "[$category] $message")
            }
            override fun debug(category: String, message: String) = fileLog.debug(category, message)
        }
        core = service
        return service
    }

    private fun serviceMain() {
        val handle = Advapi32.INSTANCE.RegisterServiceCtrlHandlerEx(
            ServiceProtocol.SERVICE_NAME,
            Winsvc.HandlerEx { control, _, _, _ -> onControl(control) },
            null
        )
        statusHandle = handle
        report(Winsvc.SERVICE_START_PENDING)
        val service = try {
            createCore()
        } catch (e: Throwable) {
            logger.error("Service init failed: ${e.message}")
            report(Winsvc.SERVICE_STOPPED, exitCode = 1)
            return
        }
        report(Winsvc.SERVICE_RUNNING)
        thread(name = "service-pipe", isDaemon = false) {
            try {
                service.serve()
            } finally {
                report(Winsvc.SERVICE_STOPPED)
            }
        }
    }

    private fun onControl(control: Int): Int {
        when (control) {
            Winsvc.SERVICE_CONTROL_STOP, Winsvc.SERVICE_CONTROL_SHUTDOWN -> {
                report(Winsvc.SERVICE_STOP_PENDING)
                thread { core?.stop() }
            }
            Winsvc.SERVICE_CONTROL_INTERROGATE -> report(Winsvc.SERVICE_RUNNING)
        }
        return 0 // NO_ERROR
    }

    private fun report(state: Int, exitCode: Int = 0) {
        val handle = statusHandle ?: return
        val status = Winsvc.SERVICE_STATUS()
        status.dwServiceType = 0x00000010 // SERVICE_WIN32_OWN_PROCESS
        status.dwCurrentState = state
        status.dwControlsAccepted = if (state == Winsvc.SERVICE_RUNNING) Winsvc.SERVICE_ACCEPT_STOP or Winsvc.SERVICE_ACCEPT_SHUTDOWN else 0
        status.dwWin32ExitCode = exitCode
        status.dwWaitHint = if (state == Winsvc.SERVICE_START_PENDING || state == Winsvc.SERVICE_STOP_PENDING) 10_000 else 0
        Advapi32.INSTANCE.SetServiceStatus(handle, status)
    }

    private class FileLog(private val file: File) : LogBackend {
        private val stamp = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
        private var writer: PrintWriter? = null

        @Synchronized
        private fun write(tag: String, category: String, message: String) {
            try {
                if (file.length() > 2L * 1024 * 1024) {
                    writer?.close(); writer = null
                    File(file.parentFile, "service.1.log").let { it.delete(); file.renameTo(it) }
                }
                val w = writer ?: PrintWriter(java.io.BufferedWriter(java.io.FileWriter(file, Charsets.UTF_8, true)), true).also { writer = it }
                w.println("${LocalDateTime.now().format(stamp)} $tag [$category] $message")
            } catch (_: Exception) {
            }
        }

        override fun log(level: MythaiaLogger.Level, category: String, message: String) = write(level.name.uppercase().padEnd(7), category, message)
        override fun debug(category: String, message: String) = write("DEBUG  ", category, message)
    }

    @Suppress("unused")
    private val unused: Pointer? = null
}
