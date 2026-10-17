package com.mythaia.desktop

import java.io.File

/**
 * Where the desktop app keeps its files: `%APPDATA%\Mythaia` on Windows,
 * `~/Library/Application Support/Mythaia` on macOS.
 */
object AppPaths {
    /** Set before first use to move the data directory (the service keeps its files in ProgramData). */
    @Volatile
    var overrideDataDir: File? = null

    val dataDir: File by lazy {
        overrideDataDir?.let { return@lazy it.apply { mkdirs() } }
        val home = System.getProperty("user.home")
        val base = when {
            Platform.isMac -> File(home, "Library/Application Support")
            else -> System.getenv("APPDATA")?.takeIf { it.isNotBlank() }?.let { File(it) } ?: File(home)
        }
        File(base, "Mythaia").apply { mkdirs() }
    }

    /** Where the service, running as SYSTEM, keeps its snapshot and log. */
    val programData: File
        get() = File(System.getenv("ProgramData") ?: "C:/ProgramData", "Mythaia")

    val configs: File get() = File(dataDir, "configs.json")
    val subscriptions: File get() = File(dataDir, "subscriptions.json")
    val settings: File get() = File(dataDir, "settings.json")
    val rules: File get() = File(dataDir, "rules.json")
    val chains: File get() = File(dataDir, "chains.json")
    val importRequest: File get() = File(dataDir, "import.request")
    val proxySnapshot: File get() = File(dataDir, "system-proxy-before.json")
    /**
     * The routes TUN mode added, so a crash can be cleaned up on the next
     * start. `v2` holds route data; the earlier `tun-routes.json` held
     * command lines and is never read again.
     */
    val tunRouteSnapshot: File get() = File(dataDir, "tun-routes-v2.json")
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
        val name = Platform.nativeLibraryName
        val folder = Platform.resourceFolder
        val candidates = buildList {
            System.getProperty("mythaia.native.library")?.let { add(File(it)) }
            System.getenv("MYTHAIA_NATIVE")?.let { add(File(it)) }
            resourcesDir?.let { add(File(it, name)) }
            val cwd = File(System.getProperty("user.dir"))
            add(File(cwd, "desktop/resources/$folder/$name"))
            add(File(cwd, "resources/$folder/$name"))
            add(File(cwd, "desktop/native/out/$name"))
            add(File(cwd, name))
        }
        return candidates.firstOrNull { it.isFile }
    }

    /** The Wintun driver DLL (see desktop/native/fetch-wintun.cmd), wherever this run keeps it; null when absent. */
    fun wintunLibrary(): File? {
        val name = "wintun.dll"
        val candidates = buildList {
            System.getProperty("mythaia.wintun.library")?.let { add(File(it)) }
            System.getenv("MYTHAIA_WINTUN")?.let { add(File(it)) }
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

    /** The `.app` bundle the launcher sits in on macOS (`…/Mythaia Pro.app`), or null. */
    fun appBundle(): File? {
        val exe = launcherExe() ?: return null
        // Contents/MacOS/<launcher>
        return exe.parentFile?.parentFile?.parentFile?.takeIf { it.name.endsWith(".app") }
    }
}
