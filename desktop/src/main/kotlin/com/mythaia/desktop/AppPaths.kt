package com.mythaia.desktop

import java.io.File

/** Where the desktop app keeps its files: `%APPDATA%\Mythaia`. */
object AppPaths {
    val dataDir: File by lazy {
        val base = System.getenv("APPDATA")?.takeIf { it.isNotBlank() }
            ?: System.getProperty("user.home")
        File(base, "Mythaia").apply { mkdirs() }
    }

    val configs: File get() = File(dataDir, "configs.json")
    val subscriptions: File get() = File(dataDir, "subscriptions.json")
    val settings: File get() = File(dataDir, "settings.json")
    val rules: File get() = File(dataDir, "rules.json")
    val chains: File get() = File(dataDir, "chains.json")
    val importRequest: File get() = File(dataDir, "import.request")
    val proxySnapshot: File get() = File(dataDir, "system-proxy-before.json")
    val geoIp: File get() = File(dataDir, "geoip.mmdb")
    val logDir: File get() = File(dataDir, "logs").apply { mkdirs() }
    val instanceLock: File get() = File(dataDir, "instance.lock")
    val showRequest: File get() = File(dataDir, "show.request")

    /**
     * The packaged app's resources directory (the Compose plugin puts
     * `desktop/resources/<os>-<arch>` there), or null in a plain JVM run.
     */
    val resourcesDir: File?
        get() = System.getProperty("compose.application.resources.dir")
            ?.let { File(it) }?.takeIf { it.isDirectory }

    /** The JNI library, wherever this run keeps it; null when it is nowhere to be found. */
    fun nativeLibrary(): File? {
        val name = "mythaia_native.dll"
        val candidates = buildList {
            System.getProperty("mythaia.native.library")?.let { add(File(it)) }
            System.getenv("MYTHAIA_NATIVE")?.let { add(File(it)) }
            resourcesDir?.let { add(File(it, name)) }
            val cwd = File(System.getProperty("user.dir"))
            add(File(cwd, "desktop/resources/windows-x64/$name"))
            add(File(cwd, "resources/windows-x64/$name"))
            add(File(cwd, "desktop/native/out/$name"))
            add(File(cwd, name))
        }
        return candidates.firstOrNull { it.isFile }
    }

    /** The installed launcher, or null when running from Gradle. */
    fun launcherExe(): File? =
        System.getProperty("jpackage.app-path")?.let { File(it) }?.takeIf { it.isFile }
}
