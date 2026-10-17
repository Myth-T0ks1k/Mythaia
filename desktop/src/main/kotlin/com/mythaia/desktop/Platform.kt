package com.mythaia.desktop

/**
 * Which desktop system this run is on. The app is one code base for Windows
 * and macOS; the differences are the system proxy, launch at login, URL
 * scheme registration, the native library's file name, and TUN mode, which
 * exists only on Windows (Wintun and the service).
 */
object Platform {
    private val osName: String = System.getProperty("os.name").orEmpty()

    val isWindows: Boolean = osName.startsWith("Windows")
    val isMac: Boolean = osName.startsWith("Mac") || osName.startsWith("Darwin")

    /** TUN mode needs Wintun and the Windows service; elsewhere only proxy mode exists. */
    val supportsTun: Boolean get() = isWindows

    /** `arm64` or `x64`, as the packaged app names its resource folders. */
    val arch: String
        get() = when (System.getProperty("os.arch").orEmpty().lowercase()) {
            "aarch64", "arm64" -> "arm64"
            else -> "x64"
        }

    /** The folder the Compose plugin uses for this system's resources, e.g. `macos-arm64`. */
    val resourceFolder: String
        get() = when {
            isWindows -> "windows-$arch"
            isMac -> "macos-$arch"
            else -> "linux-$arch"
        }

    /** The JNI library's file name on this system. */
    val nativeLibraryName: String
        get() = when {
            isWindows -> "mythaia_native.dll"
            isMac -> "libmythaia_native.dylib"
            else -> "libmythaia_native.so"
        }
}
