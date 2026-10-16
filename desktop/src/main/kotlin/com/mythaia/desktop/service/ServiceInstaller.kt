package com.mythaia.desktop.service

import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.tun.Elevation
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.platform.win32.ShellAPI
import com.sun.jna.platform.win32.W32Service
import com.sun.jna.platform.win32.W32ServiceManager
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinError
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.platform.win32.Winsvc
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import java.io.File

/**
 * Registers the service and starts it, or removes it. Both need an
 * administrator token, so the app starts its own launcher once more,
 * elevated, with [INSTALL_ARG] or [UNINSTALL_ARG] — the one time Windows
 * asks for permission — and that process talks to the service control
 * manager directly. No shell sits in between: the launcher's path reaches
 * CreateService as it is, with its spaces and non-Latin letters.
 */
object ServiceInstaller {
    const val INSTALL_ARG = "--install-service"
    const val UNINSTALL_ARG = "--uninstall-service"

    /** How an [install] or [uninstall] went. */
    enum class Outcome { DONE, DECLINED, FAILED, NO_LAUNCHER }

    private val logger = MythaiaLogger("ServiceInstaller")

    private const val DESCRIPTION = "Mythaia Pro tunnel service (TUN mode without administrator prompts)"
    private const val SERVICE_NO_CHANGE = -1
    private const val SEE_MASK_NOCLOSEPROCESS = 0x40
    private const val SEE_MASK_NOASYNC = 0x100
    private const val HELPER_TIMEOUT_MS = 120_000
    private const val STOP_TIMEOUT_MS = 15_000L

    /** Whether the service is registered with the service control manager. */
    fun isInstalled(): Boolean = runCatching {
        val manager = W32ServiceManager()
        manager.open(Winsvc.SC_MANAGER_CONNECT)
        try {
            val service = manager.openService(ServiceProtocol.SERVICE_NAME, Winsvc.SERVICE_QUERY_STATUS)
            service.close()
            true
        } finally {
            manager.close()
        }
    }.getOrDefault(false)

    /** The launcher the service must point at; null when running from Gradle. */
    fun launcher(): File? = AppPaths.launcherExe()

    /** Registers and starts the service from an elevated copy of the launcher. */
    fun install(): Outcome {
        launcher() ?: return Outcome.NO_LAUNCHER
        val outcome = runElevated(INSTALL_ARG)
        if (outcome != Outcome.DONE) return outcome
        return if (isInstalled()) Outcome.DONE else Outcome.FAILED
    }

    /** Stops and deletes the service from an elevated copy of the app. */
    fun uninstall(): Outcome {
        val outcome = runElevated(UNINSTALL_ARG)
        if (outcome != Outcome.DONE) return outcome
        return if (isInstalled()) Outcome.FAILED else Outcome.DONE
    }

    /**
     * Runs in the elevated process: creates the service, or points an
     * existing one (from another folder or version) at this launcher, then
     * starts it. Returns 0 or the Win32 error that stopped it.
     */
    fun installHere(): Int {
        val exe = launcher() ?: return WinError.ERROR_FILE_NOT_FOUND.also { logger.error("No installed launcher to register") }
        val binPath = "\"${exe.absolutePath}\" --service"
        val advapi = Advapi32.INSTANCE
        val manager = advapi.OpenSCManager(null, null, Winsvc.SC_MANAGER_ALL_ACCESS)
            ?: return failure("OpenSCManager")
        try {
            var created = true
            val handle = advapi.CreateService(
                manager, ServiceProtocol.SERVICE_NAME, ServiceProtocol.DISPLAY_NAME, Winsvc.SERVICE_ALL_ACCESS,
                WinNT.SERVICE_WIN32_OWN_PROCESS, WinNT.SERVICE_AUTO_START, WinNT.SERVICE_ERROR_NORMAL,
                binPath, null, null, null, null, null
            ) ?: run {
                val error = Native.getLastError()
                if (error != WinError.ERROR_SERVICE_EXISTS) return failure("CreateService", error)
                created = false
                advapi.OpenService(manager, ServiceProtocol.SERVICE_NAME, Winsvc.SERVICE_ALL_ACCESS)
            } ?: return failure("OpenService")
            val service = W32Service(handle)
            try {
                if (!created) {
                    runCatching { service.stopService(STOP_TIMEOUT_MS) }
                        .onFailure { logger.warning("Could not stop the old service: ${it.message}") }
                    val changed = advapiEx.ChangeServiceConfigW(
                        handle, SERVICE_NO_CHANGE, WinNT.SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                        WString(binPath), null, null, null, null, null, WString(ServiceProtocol.DISPLAY_NAME)
                    )
                    if (!changed) return failure("ChangeServiceConfig")
                }
                advapi.ChangeServiceConfig2(
                    handle, Winsvc.SERVICE_CONFIG_DESCRIPTION,
                    Winsvc.SERVICE_DESCRIPTION().apply { lpDescription = DESCRIPTION }
                )
                runCatching {
                    service.setFailureActions(listOf(restartAfter(2_000), restartAfter(5_000)), 60, null, null)
                }.onFailure { logger.warning("Could not set the restart policy: ${it.message}") }
                if (!advapi.StartService(handle, 0, null)) {
                    val error = Native.getLastError()
                    if (error != WinError.ERROR_SERVICE_ALREADY_RUNNING) return failure("StartService", error)
                }
                logger.info("Service ${if (created) "registered" else "updated"}: $binPath")
                return 0
            } finally {
                service.close()
            }
        } finally {
            advapi.CloseServiceHandle(manager)
        }
    }

    /** Runs in the elevated process: stops and deletes the service. Returns 0 or a Win32 error. */
    fun uninstallHere(): Int {
        val advapi = Advapi32.INSTANCE
        val manager = advapi.OpenSCManager(null, null, Winsvc.SC_MANAGER_CONNECT)
            ?: return failure("OpenSCManager")
        try {
            val handle = advapi.OpenService(
                manager, ServiceProtocol.SERVICE_NAME,
                Winsvc.SERVICE_STOP or Winsvc.SERVICE_QUERY_STATUS or WinNT.DELETE
            ) ?: run {
                val error = Native.getLastError()
                return if (error == WinError.ERROR_SERVICE_DOES_NOT_EXIST) 0 else failure("OpenService", error)
            }
            val service = W32Service(handle)
            try {
                runCatching { service.stopService(STOP_TIMEOUT_MS) }
                    .onFailure { logger.warning("Could not stop the service: ${it.message}") }
                if (!advapi.DeleteService(handle)) {
                    val error = Native.getLastError()
                    if (error != WinError.ERROR_SERVICE_MARKED_FOR_DELETE) return failure("DeleteService", error)
                }
                logger.info("Service removed")
                return 0
            } finally {
                service.close()
            }
        } finally {
            advapi.CloseServiceHandle(manager)
        }
    }

    /**
     * Starts this app again with [argument] through ShellExecuteEx "runas"
     * (the UAC prompt) and waits for it to finish.
     */
    private fun runElevated(argument: String): Outcome {
        val (file, args) = try {
            Elevation.launchCommand(listOf(argument))
        } catch (e: Exception) {
            logger.error("Cannot build the elevated command: ${e.message}")
            return Outcome.FAILED
        }
        val info = ShellAPI.SHELLEXECUTEINFO().apply {
            cbSize = size()
            fMask = SEE_MASK_NOCLOSEPROCESS or SEE_MASK_NOASYNC
            lpVerb = "runas"
            lpFile = file
            lpParameters = args.joinToString(" ") { commandLineArg(it) }
            nShow = WinUser.SW_HIDE
        }
        if (!Shell32.INSTANCE.ShellExecuteEx(info)) {
            val error = Native.getLastError()
            if (error == WinError.ERROR_CANCELLED) {
                logger.info("The administrator prompt was declined")
                return Outcome.DECLINED
            }
            logger.warning("Could not start the elevated helper (error $error)")
            return Outcome.FAILED
        }
        val process = info.hProcess ?: return Outcome.FAILED.also { logger.warning("The elevated helper gave no process handle") }
        try {
            if (Kernel32.INSTANCE.WaitForSingleObject(process, HELPER_TIMEOUT_MS) != WinBase.WAIT_OBJECT_0) {
                logger.warning("The elevated helper did not finish in ${HELPER_TIMEOUT_MS / 1000} s")
                return Outcome.FAILED
            }
            val code = IntByReference()
            Kernel32.INSTANCE.GetExitCodeProcess(process, code)
            if (code.value != 0) {
                logger.warning("The elevated helper exited with ${code.value}")
                return Outcome.FAILED
            }
            return Outcome.DONE
        } finally {
            Kernel32.INSTANCE.CloseHandle(process)
        }
    }

    /**
     * One argument for a Windows command line, as CommandLineToArgvW reads
     * it back: quoted when it has spaces or quotes, backslashes doubled only
     * where they precede a quote.
     */
    internal fun commandLineArg(text: String): String {
        if (text.isNotEmpty() && text.none { it == ' ' || it == '\t' || it == '"' }) return text
        val out = StringBuilder("\"")
        var backslashes = 0
        for (c in text) {
            when (c) {
                '\\' -> backslashes++
                '"' -> {
                    repeat(backslashes * 2 + 1) { out.append('\\') }
                    out.append('"')
                    backslashes = 0
                }
                else -> {
                    repeat(backslashes) { out.append('\\') }
                    out.append(c)
                    backslashes = 0
                }
            }
        }
        repeat(backslashes * 2) { out.append('\\') }
        return out.append('"').toString()
    }

    private fun restartAfter(delayMs: Int) = Winsvc.SC_ACTION().apply {
        type = Winsvc.SC_ACTION_RESTART
        delay = delayMs
    }

    private fun failure(call: String, error: Int = Native.getLastError()): Int {
        logger.error("$call failed (error $error)")
        return if (error == 0) -1 else error
    }

    @Suppress("FunctionName")
    private interface Advapi32Ex : StdCallLibrary {
        fun ChangeServiceConfigW(
            service: Winsvc.SC_HANDLE, serviceType: Int, startType: Int, errorControl: Int,
            binaryPathName: WString?, loadOrderGroup: WString?, tagId: Pointer?, dependencies: WString?,
            serviceStartName: WString?, password: WString?, displayName: WString?
        ): Boolean
    }

    private val advapiEx: Advapi32Ex by lazy { Native.load("advapi32", Advapi32Ex::class.java) }
}
