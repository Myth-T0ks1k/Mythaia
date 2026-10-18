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
    private val status = ServiceStatusTracker()

    /**
     * Entry for `--service` (under the service control manager). SCM gives
     * a starting service 30 seconds to call the dispatcher, and on a slow
     * boot the JVM alone takes much of that; when the folder permissions,
     * the native library and the route cleanup came first as well, the start
     * failed with error 1053. So the dispatcher is called at once, and the
     * rest happens in [serviceMain] behind START_PENDING.
     */
    fun runUnderScm(): Nothing {
        val entries = Winsvc.SERVICE_TABLE_ENTRY().toArray(2)
        @Suppress("UNCHECKED_CAST")
        val table = entries as Array<Winsvc.SERVICE_TABLE_ENTRY>
        table[0].lpServiceName = ServiceProtocol.SERVICE_NAME
        table[0].lpServiceProc = Winsvc.SERVICE_MAIN_FUNCTION { _, _ -> serviceMain() }
        table[0].write()
        if (!Advapi32.INSTANCE.StartServiceCtrlDispatcher(table)) {
            val error = com.sun.jna.platform.win32.Kernel32.INSTANCE.GetLastError()
            // Started some other way than by SCM (1063 when run from a
            // console): only the log is set up, so a copy started by hand
            // cannot clean up the routes of the tunnel the real service runs.
            openLog()
            logger.error("StartServiceCtrlDispatcher failed: $error")
            exitProcess(1)
        }
        exitProcess(0)
    }

    /** Entry for `--service-console`: the same loop in a plain process, for testing. */
    fun runInConsole(): Nothing {
        openLog()
        prepareEngine()
        val service = createCore()
        Runtime.getRuntime().addShutdownHook(Thread { service.stop() })
        service.serve()
        exitProcess(0)
    }

    /** The data folder in ProgramData, locked down, and the log in it. */
    private fun openLog() {
        val dataDir = AppPaths.programData.apply { mkdirs() }
        AppPaths.overrideDataDir = dataDir
        MythaiaLogger.backend = FileLog(File(dataDir, "service.log"))
        lockDown(dataDir)
    }

    /** The native library, and whatever a previous run left on the network; [progress] after each step. */
    private fun prepareEngine(progress: () -> Unit = {}) {
        AppPaths.nativeLibrary()?.let { System.setProperty("mythaia.native.library", com.mythaia.desktop.NativeLoading.loadablePath(it)) }
        runCatching { NativeBridge.nativeQuicVersion() }
        progress()
        runCatching { TunEngine.cleanupLeftovers() }
        progress()
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
        // SCM hears from the service first; each step after this one moves
        // the checkpoint on, so a slow boot reads as progress, not a hang.
        report(Winsvc.SERVICE_START_PENDING)
        val service = try {
            openLog()
            report(Winsvc.SERVICE_START_PENDING)
            prepareEngine { report(Winsvc.SERVICE_START_PENDING) }
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
            // SCM keeps the last status reported; answering RUNNING here
            // while still starting would be a lie.
            Winsvc.SERVICE_CONTROL_INTERROGATE -> Unit
        }
        return 0 // NO_ERROR
    }

    private fun report(state: Int, exitCode: Int = 0) {
        val handle = statusHandle ?: return
        val next = status.next(state, exitCode)
        val win = Winsvc.SERVICE_STATUS()
        win.dwServiceType = 0x00000010 // SERVICE_WIN32_OWN_PROCESS
        win.dwCurrentState = next.state
        win.dwControlsAccepted = next.controlsAccepted
        win.dwWin32ExitCode = next.exitCode
        win.dwCheckPoint = next.checkPoint
        win.dwWaitHint = next.waitHintMs
        Advapi32.INSTANCE.SetServiceStatus(handle, win)
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

/**
 * The fields of each status report. A pending state carries a wait hint and
 * a checkpoint that grows with every report of that state, which is how SCM
 * tells a slow start from a hung one; a settled state carries neither, and
 * only RUNNING accepts stop and shutdown.
 */
internal class ServiceStatusTracker {
    data class Report(val state: Int, val controlsAccepted: Int, val exitCode: Int, val checkPoint: Int, val waitHintMs: Int)

    private var state = 0
    private var checkPoint = 0

    @Synchronized
    fun next(state: Int, exitCode: Int = 0): Report {
        val pending = state == Winsvc.SERVICE_START_PENDING || state == Winsvc.SERVICE_STOP_PENDING
        checkPoint = when {
            !pending -> 0
            state == this.state -> checkPoint + 1
            else -> 1
        }
        this.state = state
        return Report(
            state = state,
            controlsAccepted = if (state == Winsvc.SERVICE_RUNNING) Winsvc.SERVICE_ACCEPT_STOP or Winsvc.SERVICE_ACCEPT_SHUTDOWN else 0,
            exitCode = exitCode,
            checkPoint = checkPoint,
            waitHintMs = if (pending) PENDING_WAIT_HINT_MS else 0
        )
    }

    companion object {
        /** Each step of the start (icacls, the native library, the route cleanup) reports within this. */
        const val PENDING_WAIT_HINT_MS = 30_000
    }
}
