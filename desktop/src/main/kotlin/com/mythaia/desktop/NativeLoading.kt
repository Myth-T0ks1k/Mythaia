package com.mythaia.desktop

import java.io.File
import java.nio.charset.Charset
import java.util.concurrent.TimeUnit

/**
 * How the app's native code is found and loaded.
 *
 * JNA's own native part (jnidispatch.dll) ships next to the other DLLs in
 * the app's resources: left in the jar, JNA unpacks it into %TEMP% on first
 * use, and where antivirus or AppLocker blocks DLLs there, every registry,
 * Wintun and service call failed.
 *
 * The JVM hands DLL paths to Windows in the process's ANSI code page
 * (`sun.jnu.encoding`), so a letter that code page cannot spell (a Turkmen
 * ň under a Russian system locale, say) makes the load fail. The launcher
 * runs with UTF-8 as its code page (desktop/launcher/utf8-codepage.manifest),
 * which makes every path spellable on Windows 10 1903 and later; on older
 * systems the 8.3 short form of the path stands in where one exists.
 */
object NativeLoading {
    private const val JNA_DISPATCH = "jnidispatch.dll"

    /**
     * Points JNA at the shipped jnidispatch.dll and stops it unpacking a copy
     * into %TEMP%. Must run before anything touches JNA. Returns the folder
     * used, or null when there is none (tests, a build without the file): JNA
     * then unpacks as before.
     */
    fun configureJna(): File? {
        val cwd = File(System.getProperty("user.dir"))
        val candidates = buildList {
            System.getProperty("jna.boot.library.path")?.split(File.pathSeparatorChar)
                ?.filter { it.isNotBlank() }?.forEach { add(File(it)) }
            AppPaths.resourcesDir?.let(::add)
            add(File(cwd, "desktop/resources/windows-x64"))
            add(File(cwd, "resources/windows-x64"))
        }
        val dir = candidates.firstOrNull { File(it, JNA_DISPATCH).isFile } ?: return null
        System.setProperty("jna.boot.library.path", loadablePath(dir))
        System.setProperty("jna.nosys", "true")
        System.setProperty("jna.nounpack", "true")
        return dir
    }

    /**
     * Skia's DLL folder (`skiko.library.path`, the app folder in a packaged
     * app) in a form the JVM can load from; a no-op where it already is.
     */
    fun fixSkikoPath() {
        val dir = System.getProperty("skiko.library.path")?.let(::File)?.takeIf { it.isDirectory } ?: return
        val loadable = loadablePath(dir)
        if (loadable != dir.path) System.setProperty("skiko.library.path", loadable)
    }

    /** Whether the JVM's file-name code page can spell [path]. */
    fun spellable(path: String, encoding: String? = System.getProperty("sun.jnu.encoding")): Boolean {
        val charset = encoding?.let { runCatching { Charset.forName(it) }.getOrNull() } ?: return true
        return charset.newEncoder().canEncode(path)
    }

    /**
     * [file]'s path as the JVM can load it: the path itself when the code
     * page spells it, else its 8.3 short form when that does. Failing both,
     * the path itself, so the error names the real file.
     */
    fun loadablePath(file: File, encoding: String? = System.getProperty("sun.jnu.encoding")): String {
        val path = file.absolutePath
        if (spellable(path, encoding)) return path
        val short = shortPath(path) ?: return path
        return if (spellable(short, encoding) && File(short).exists()) short else path
    }

    /**
     * The 8.3 form of [path], from cmd's `%~s` (not JNA, which may be the
     * very library being located). Null when the volume keeps no short
     * names, in which case cmd hands back letters it cannot print.
     */
    internal fun shortPath(path: String): String? {
        if (!System.getProperty("os.name").orEmpty().startsWith("Windows")) return null
        return try {
            // Through the environment, so no character in the path is ever parsed as syntax.
            val builder = ProcessBuilder("cmd.exe", "/d", "/c", "for %I in (\"%MYTHAIA_SHORT_PATH%\") do @echo %~sI")
                .redirectErrorStream(true)
            builder.environment()["MYTHAIA_SHORT_PATH"] = path
            val process = builder.start()
            process.outputStream.close()
            val bytes = process.inputStream.readBytes()
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return null
            }
            if (bytes.any { it < 0 }) return null
            String(bytes, Charsets.US_ASCII).trim().takeIf { it.length > 2 && it[1] == ':' }
        } catch (e: Exception) {
            null
        }
    }
}
