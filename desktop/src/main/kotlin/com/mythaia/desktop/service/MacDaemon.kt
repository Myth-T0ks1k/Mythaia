package com.mythaia.desktop.service

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The macOS counterpart of the Windows service: a LaunchDaemon that runs
 * the app's own launcher with `--service` as root, so TUN mode needs no
 * password once it is installed.
 *
 * As on Windows since 1.1.2, the daemon never runs the copy the user
 * started, which any program under the user's account could replace: the
 * installer copies the bundle to [SERVICE_DIR], owned by root and writable
 * by root only, and the plist points there. Links in the bundle are copied
 * as the files they point to, so nothing in the copy leads back to a place
 * the user can write.
 *
 * Installing, updating and removing each take one administrator password:
 * `osascript` runs a fixed shell script `with administrator privileges`.
 * Every path in it is quoted for the shell and the whole for AppleScript.
 */
object MacDaemon {
    const val LABEL = "com.mythaia.desktop.service"
    const val PLIST = "/Library/LaunchDaemons/$LABEL.plist"
    /** Root's: the daemon's snapshot and log, and the copy of the app below it. */
    const val BASE_DIR = "/Library/Application Support/Mythaia"
    const val SERVICE_DIR = "$BASE_DIR/Service"

    /**
     * The copy's folder. The bundle's layout inside, which is all the
     * launcher goes by, but no `.app` on the name: Launch Services registers
     * every `.app` it finds, and a second Mythaia Pro would turn up in
     * Spotlight and Launchpad and could be picked to open mythaia:// links.
     */
    const val APP_NAME = "Mythaia Pro Service"
    const val LOG_FILE = "$BASE_DIR/service.log"
    /** What the JVM itself prints before the app's log is open (a launcher that cannot start, say). */
    const val STDERR_FILE = "$BASE_DIR/service.stderr.log"

    /** Copying the bundle (some 200 MB) is the slow part. */
    private const val HELPER_TIMEOUT_SEC = 300L

    private val logger = MythaiaLogger("MacDaemon")

    /** Whether the daemon's plist is in place. */
    fun isInstalled(): Boolean = File(PLIST).isFile

    /**
     * Copies the running bundle to [SERVICE_DIR], writes the plist and
     * (re)starts the daemon. [onStarted] runs just before macOS asks for the
     * password.
     */
    fun install(prompt: String, onStarted: () -> Unit = {}): ServiceInstaller.Outcome {
        val bundle = AppPaths.appBundle() ?: return ServiceInstaller.Outcome.NO_LAUNCHER
        val launcher = AppPaths.launcherExe()?.name ?: return ServiceInstaller.Outcome.NO_LAUNCHER
        runCatching(onStarted)
        val outcome = runAsAdministrator(installScript(bundle.absolutePath, launcher), prompt)
        if (outcome != ServiceInstaller.Outcome.DONE) return outcome
        return if (isInstalled()) ServiceInstaller.Outcome.DONE else ServiceInstaller.Outcome.FAILED
    }

    /** Stops the daemon (which puts the network back) and removes it and its copy of the app. */
    fun uninstall(prompt: String): ServiceInstaller.Outcome {
        val outcome = runAsAdministrator(uninstallScript(), prompt)
        if (outcome != ServiceInstaller.Outcome.DONE) return outcome
        return if (isInstalled()) ServiceInstaller.Outcome.FAILED else ServiceInstaller.Outcome.DONE
    }

    /** The launcher inside the daemon's copy of the bundle. */
    internal fun launcherPath(launcherName: String): String = "$SERVICE_DIR/$APP_NAME/Contents/MacOS/$launcherName"

    /**
     * The LaunchDaemon: started at boot and when bootstrapped, restarted
     * after a crash but not after a clean exit, given time on shutdown to
     * put the routes and DNS back before launchd kills it.
     */
    internal fun plist(executable: String): String = """
        |<?xml version="1.0" encoding="UTF-8"?>
        |<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        |<plist version="1.0">
        |<dict>
        |    <key>Label</key>
        |    <string>$LABEL</string>
        |    <key>ProgramArguments</key>
        |    <array>
        |        <string>${xml(executable)}</string>
        |        <string>--service</string>
        |    </array>
        |    <key>RunAtLoad</key>
        |    <true/>
        |    <key>KeepAlive</key>
        |    <dict>
        |        <key>SuccessfulExit</key>
        |        <false/>
        |    </dict>
        |    <key>ThrottleInterval</key>
        |    <integer>5</integer>
        |    <key>ExitTimeOut</key>
        |    <integer>30</integer>
        |    <key>ProcessType</key>
        |    <string>Interactive</string>
        |    <key>StandardErrorPath</key>
        |    <string>${xml(STDERR_FILE)}</string>
        |</dict>
        |</plist>
        |""".trimMargin()

    /**
     * The root shell script behind [install]. The bundle is staged as
     * `.new` beside the old copy and swapped in, so a failed copy never
     * leaves the daemon half-written; the old daemon is stopped first, since
     * it may be running from the folder being replaced.
     */
    internal fun installScript(sourceBundle: String, launcherName: String): String {
        val app = "$SERVICE_DIR/$APP_NAME"
        val executable = launcherPath(launcherName)
        return listOf(
            "set -e",
            "label=${q(LABEL)}",
            "plist=${q(PLIST)}",
            "app=${q(app)}",
            "/bin/launchctl bootout \"system/\$label\" 2>/dev/null || true",
            "for d in ${q(BASE_DIR)} ${q(SERVICE_DIR)}; do",
            "  if [ -L \"\$d\" ]; then /bin/rm -f \"\$d\"; fi",
            "  /bin/mkdir -p \"\$d\"",
            "  /usr/sbin/chown root:wheel \"\$d\"",
            "  /bin/chmod 755 \"\$d\"",
            "done",
            "/bin/rm -rf \"\$app.new\"",
            "/bin/cp -RL ${q(sourceBundle)} \"\$app.new\"",
            "/usr/sbin/chown -R root:wheel \"\$app.new\"",
            "/bin/chmod -R go-w \"\$app.new\"",
            "/usr/bin/xattr -dr com.apple.quarantine \"\$app.new\" 2>/dev/null || true",
            "/bin/rm -rf \"\$app\"",
            "/bin/mv \"\$app.new\" \"\$app\"",
            "[ -x ${q(executable)} ]",
            "printf '%s' ${q(plist(executable))} > \"\$plist.new\"",
            "/usr/sbin/chown root:wheel \"\$plist.new\"",
            "/bin/chmod 644 \"\$plist.new\"",
            "/bin/mv -f \"\$plist.new\" \"\$plist\"",
            "/bin/launchctl enable \"system/\$label\" 2>/dev/null || true",
            "/bin/launchctl bootstrap system \"\$plist\" || { /bin/sleep 2; /bin/launchctl bootstrap system \"\$plist\"; }"
        ).joinToString("\n")
    }

    /** The root shell script behind [uninstall]. The daemon's log stays, as ProgramData's does on Windows. */
    internal fun uninstallScript(): String = listOf(
        "label=${q(LABEL)}",
        "/bin/launchctl bootout \"system/\$label\" 2>/dev/null || true",
        "/bin/rm -f ${q(PLIST)}",
        "/bin/rm -rf ${q(SERVICE_DIR)}",
        "/bin/rm -rf ${q(ServiceProtocol.SOCKET_PATH.substringBeforeLast('/'))}"
    ).joinToString("\n")

    /** `do shell script` for [script] with the password prompt [prompt], as an AppleScript source line. */
    internal fun appleScript(script: String, prompt: String): String =
        "do shell script \"${appleString(script)}\" with prompt \"${appleString(prompt)}\" with administrator privileges"

    /** An AppleScript string literal's body: backslashes and quotes escaped, line breaks as `\n`. */
    internal fun appleString(text: String): String =
        text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", "\\n")

    /** One shell word: single-quoted, with any single quote closed, escaped and reopened. */
    internal fun q(text: String): String = "'" + text.replace("'", "'\\''") + "'"

    private fun xml(text: String): String =
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;")

    /** Runs [script] as root through osascript (the password dialog) and waits for it. */
    private fun runAsAdministrator(script: String, prompt: String): ServiceInstaller.Outcome {
        val output = File.createTempFile("mythaia-admin", ".log")
        try {
            val process = ProcessBuilder("/usr/bin/osascript", "-e", appleScript(script, prompt))
                .redirectErrorStream(true)
                .redirectOutput(output)
                .start()
            runCatching { process.outputStream.close() }
            if (!process.waitFor(HELPER_TIMEOUT_SEC, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                logger.warning("The administrator script did not finish in $HELPER_TIMEOUT_SEC s")
                return ServiceInstaller.Outcome.FAILED
            }
            val text = runCatching { output.readText() }.getOrDefault("").trim()
            return when {
                process.exitValue() == 0 -> ServiceInstaller.Outcome.DONE
                // "User canceled. (-128)": the password dialog was dismissed.
                text.contains("(-128)") -> {
                    logger.info("The administrator prompt was declined")
                    ServiceInstaller.Outcome.DECLINED
                }
                else -> {
                    logger.warning("The administrator script failed: ${text.lineSequence().lastOrNull { it.isNotBlank() } ?: "exit ${process.exitValue()}"}")
                    ServiceInstaller.Outcome.FAILED
                }
            }
        } catch (e: Exception) {
            logger.warning("Could not run osascript: ${e.message}")
            return ServiceInstaller.Outcome.FAILED
        } finally {
            output.delete()
        }
    }
}
