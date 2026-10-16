package com.mythaia.desktop.service

import java.io.File
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes

/**
 * The service's own copy of the app, under Program Files.
 *
 * The service runs as LocalSystem. Pointed at the copy the user starts —
 * a portable folder on the Desktop, a per-user install in AppData — it
 * would run files that any program under the user's account can replace,
 * and the next service start would run that program as SYSTEM. Program
 * Files is writable by administrators only, so the elevated installer
 * copies the image there and the service runs from that copy.
 */
object ServiceImage {
    const val FOLDER = "Mythaia Pro Service"

    /** The parts of a jpackage image besides the launcher itself. */
    private val PARTS = listOf("app", "runtime")
    private const val RETRY_MS = 10_000L

    /** `%ProgramFiles%\Mythaia Pro Service`. */
    fun directory(): File =
        File(System.getenv("ProgramFiles")?.takeIf { it.isNotBlank() } ?: "C:\\Program Files", FOLDER)

    /**
     * Copies the image [launcher] belongs to — the launcher, `app` and
     * `runtime` — into [target] and returns the launcher there. The copy is
     * built beside it as `<name>.new` and swapped in, so a failed copy never
     * leaves a half-written folder behind. Links and junctions in the source
     * are skipped: the copy runs elevated and must not pull in files the user
     * could not read. A service running from [target] must be stopped first.
     */
    fun deploy(launcher: File, target: File): File {
        val source = launcher.absoluteFile.parentFile
        val targetLauncher = File(target, launcher.name)
        if (sameFile(source, target)) return targetLauncher
        val staging = sibling(target, ".new")
        val old = sibling(target, ".old")
        deleteTree(staging.toPath())
        deleteTree(old.toPath())

        Files.createDirectories(staging.toPath())
        Files.copy(launcher.toPath(), File(staging, launcher.name).toPath())
        for (part in PARTS) {
            val dir = File(source, part)
            if (!dir.isDirectory) throw IOException("$dir is missing")
            copyTree(dir.toPath(), File(staging, part).toPath())
        }

        if (Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) retrying { Files.move(target.toPath(), old.toPath()) }
        try {
            retrying { Files.move(staging.toPath(), target.toPath()) }
        } catch (e: IOException) {
            runCatching { if (!target.exists() && old.exists()) Files.move(old.toPath(), target.toPath()) }
            throw e
        }
        // A file the old service still holds stays until the next install clears it.
        runCatching { deleteTree(old.toPath()) }
        return targetLauncher
    }

    /** Deletes [target] and any staging folders left beside it. */
    fun remove(target: File) {
        for (dir in listOf(target, sibling(target, ".new"), sibling(target, ".old"))) {
            retrying { deleteTree(dir.toPath()) }
        }
    }

    private fun copyTree(from: Path, to: Path) {
        val realFrom = from.toRealPath()
        Files.walkFileTree(from, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (dir != from && isLink(dir, from, realFrom)) return FileVisitResult.SKIP_SUBTREE
                Files.createDirectories(to.resolve(from.relativize(dir).toString()))
                return FileVisitResult.CONTINUE
            }

            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (!attrs.isSymbolicLink && !attrs.isDirectory) {
                    Files.copy(file, to.resolve(from.relativize(file).toString()), StandardCopyOption.REPLACE_EXISTING)
                }
                return FileVisitResult.CONTINUE
            }
        })
    }

    /** Deletes a folder tree; a link or junction inside is removed itself, never what it points to. */
    internal fun deleteTree(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isSymbolicLink(root)) {
            Files.delete(root)
            return
        }
        val realRoot = root.toRealPath()
        Files.walkFileTree(root, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult {
                if (dir != root && isLink(dir, root, realRoot)) {
                    Files.delete(dir)
                    return FileVisitResult.SKIP_SUBTREE
                }
                return FileVisitResult.CONTINUE
            }

            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
                writable(file)
                Files.delete(file)
                return FileVisitResult.CONTINUE
            }

            override fun postVisitDirectory(dir: Path, exc: IOException?): FileVisitResult {
                if (exc != null) throw exc
                writable(dir)
                Files.delete(dir)
                return FileVisitResult.CONTINUE
            }
        })
    }

    /**
     * Java reports a junction as a plain folder; its real path, though,
     * leaves the tree it was found in.
     */
    private fun isLink(dir: Path, root: Path, realRoot: Path): Boolean {
        if (Files.isSymbolicLink(dir)) return true
        val expected = realRoot.resolve(root.relativize(dir).toString())
        return runCatching { dir.toRealPath() != expected }.getOrDefault(true)
    }

    /** jpackage marks its files read-only, which Windows refuses to delete. */
    private fun writable(path: Path) {
        runCatching { Files.setAttribute(path, "dos:readonly", false, LinkOption.NOFOLLOW_LINKS) }
    }

    private fun sameFile(a: File, b: File): Boolean =
        runCatching { Files.isSameFile(a.toPath(), b.toPath()) }.getOrDefault(false)

    private fun sibling(dir: File, suffix: String) = File(dir.absoluteFile.parentFile, dir.name + suffix)

    /** Retries [block] for a while: the stopped service's process can hold its files a moment longer. */
    private fun retrying(block: () -> Unit) {
        val deadline = System.currentTimeMillis() + RETRY_MS
        while (true) {
            try {
                block()
                return
            } catch (e: IOException) {
                if (System.currentTimeMillis() > deadline) throw e
                Thread.sleep(250)
            }
        }
    }
}
