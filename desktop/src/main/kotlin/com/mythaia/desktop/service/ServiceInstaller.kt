package com.mythaia.desktop.service

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.platform.win32.W32ServiceManager
import com.sun.jna.platform.win32.Winsvc
import java.io.File

/**
 * Registers the service with `sc` from one elevated helper run — the one
 * time Windows asks for permission — and starts it. Removal is the reverse.
 */
object ServiceInstaller {
    private val logger = MythaiaLogger("ServiceInstaller")

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

    /** Registers and starts the service through an elevated `cmd`. Returns false when the prompt was refused or no launcher exists. */
    fun install(): Boolean {
        val exe = launcher() ?: return false
        val bin = "\\\"${exe.absolutePath}\\\" --service"
        val script = listOf(
            "sc create ${ServiceProtocol.SERVICE_NAME} binPath= \"$bin\" start= auto DisplayName= \"${ServiceProtocol.DISPLAY_NAME}\"",
            "sc description ${ServiceProtocol.SERVICE_NAME} \"Mythaia Pro tunnel service (TUN mode without administrator prompts)\"",
            "sc failure ${ServiceProtocol.SERVICE_NAME} reset= 60 actions= restart/2000/restart/5000",
            "sc start ${ServiceProtocol.SERVICE_NAME}"
        ).joinToString(" & ")
        return runElevated(script)
    }

    fun uninstall(): Boolean {
        val script = "sc stop ${ServiceProtocol.SERVICE_NAME} & sc delete ${ServiceProtocol.SERVICE_NAME}"
        return runElevated(script)
    }

    private fun runElevated(script: String): Boolean {
        val escaped = script.replace("'", "''")
        val command = "Start-Process -FilePath cmd.exe -ArgumentList '/c $escaped' -Verb RunAs -Wait -WindowStyle Hidden"
        return try {
            val process = ProcessBuilder("powershell", "-NoProfile", "-NonInteractive", "-Command", command)
                .redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            val code = process.waitFor()
            if (code != 0) logger.warning("Elevated command failed ($code): ${output.trim().take(300)}")
            code == 0
        } catch (e: Exception) {
            logger.error("Could not run the elevated command: ${e.message}")
            false
        }
    }
}
