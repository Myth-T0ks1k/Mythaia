package com.mythaia.data.update

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URI

/**
 * A release version — "1.3.1", "v1.4.0", "2.0.0-beta.1" — ordered the way a
 * person reads it: number by number, and a pre-release before its release.
 */
data class AppVersion(val parts: List<Int>, val preRelease: String? = null) : Comparable<AppVersion> {

    override fun compareTo(other: AppVersion): Int {
        for (i in 0 until maxOf(parts.size, other.parts.size)) {
            val a = parts.getOrElse(i) { 0 }
            val b = other.parts.getOrElse(i) { 0 }
            if (a != b) return a.compareTo(b)
        }
        return when {
            preRelease == other.preRelease -> 0
            preRelease == null -> 1
            other.preRelease == null -> -1
            else -> preRelease.compareTo(other.preRelease)
        }
    }

    override fun toString(): String = parts.joinToString(".") + (preRelease?.let { "-$it" } ?: "")

    companion object {
        /** Null for anything that is not a dotted version, so a stray tag is never "newer". */
        fun parse(text: String): AppVersion? {
            val trimmed = text.trim().removePrefix("v").removePrefix("V")
            val core = trimmed.substringBefore('+').substringBefore('-')
            val pre = trimmed.substringBefore('+').substringAfter('-', "").ifEmpty { null }
            if (core.isEmpty()) return null
            val parts = core.split('.').map { part ->
                if (part.isEmpty() || part.length > 6 || !part.all { it in '0'..'9' }) return null
                part.toInt()
            }
            if (parts.size > 4) return null
            return AppVersion(parts, pre)
        }
    }
}

/** One file attached to a release. [sha256] is GitHub's own digest, when it gives one. */
data class ReleaseAsset(
    val name: String,
    val downloadUrl: String,
    val size: Long,
    val sha256: String?
)

data class Release(
    val tag: String,
    val version: AppVersion,
    val title: String,
    val notes: String,
    val pageUrl: String,
    val assets: List<ReleaseAsset>
) {
    fun asset(name: String): ReleaseAsset? = assets.firstOrNull { it.name == name }
}

/**
 * Where Mythaia's releases live, and how to read them.
 *
 * The update check asks GitHub's REST API for the latest published release
 * (drafts and pre-releases never count) and picks the file for this device by
 * the names the release script gives them. Every download is then checked
 * against the release's own SHA256SUMS.txt, and on Android against the
 * signing certificate too.
 */
object Releases {

    const val REPOSITORY = "Myth-T0ks1k/Mythaia"
    const val LATEST_API_URL = "https://api.github.com/repos/$REPOSITORY/releases/latest"
    const val LATEST_PAGE_URL = "https://github.com/$REPOSITORY/releases/latest"
    const val CHECKSUMS_ASSET = "SHA256SUMS.txt"

    /**
     * SHA-256 of the certificate the Android release APKs are signed with
     * (`apksigner verify --print-certs`). An APK signed with anything else is
     * not ours, whatever the checksum file says.
     */
    const val ANDROID_RELEASE_CERT_SHA256 = "d5d40ee51c5b2d73efed7870aa3e3fb473aba3f2d42371dac2b3fd29cfa67963"

    const val ANDROID_ARM64_SUFFIX = "-android-arm64-v8a.apk"
    const val ANDROID_UNIVERSAL_SUFFIX = "-android-universal.apk"
    const val WINDOWS_SETUP_SUFFIX = "-windows-x64-setup.exe"
    const val WINDOWS_PORTABLE_SUFFIX = "-windows-x64-portable.zip"

    /** The release download path every asset URL has to sit under. */
    private const val DOWNLOAD_PREFIX = "/$REPOSITORY/releases/download/"

    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private class ApiAsset(
        val name: String = "",
        @SerialName("browser_download_url") val url: String = "",
        val size: Long = 0,
        val digest: String? = null
    )

    @Serializable
    private class ApiRelease(
        @SerialName("tag_name") val tag: String = "",
        val name: String? = null,
        val body: String? = null,
        @SerialName("html_url") val pageUrl: String? = null,
        val draft: Boolean = false,
        val prerelease: Boolean = false,
        val assets: List<ApiAsset> = emptyList()
    )

    /**
     * Reads a `releases/latest` response.
     *
     * An asset whose URL is not a release download of this repository is
     * dropped rather than trusted: the update must come from where the
     * releases are published, not from wherever a response points.
     *
     * @throws IllegalArgumentException when it is not a usable release.
     */
    fun parse(body: String): Release {
        val api = try {
            json.decodeFromString<ApiRelease>(body)
        } catch (e: Exception) {
            throw IllegalArgumentException("Not a release: ${e.message}")
        }
        require(!api.draft && !api.prerelease) { "Not a published release" }
        val version = requireNotNull(AppVersion.parse(api.tag)) { "Unreadable version \"${api.tag}\"" }
        val assets = api.assets.filter { isReleaseDownload(it.url) }.map { asset ->
            ReleaseAsset(
                name = asset.name,
                downloadUrl = asset.url,
                size = asset.size,
                sha256 = asset.digest
                    ?.takeIf { it.startsWith("sha256:", ignoreCase = true) }
                    ?.substringAfter(':')
                    ?.lowercase()
                    ?.takeIf { isSha256(it) }
            )
        }
        return Release(
            tag = api.tag,
            version = version,
            title = api.name?.takeIf { it.isNotBlank() } ?: api.tag,
            notes = api.body.orEmpty(),
            pageUrl = api.pageUrl?.takeIf { it.startsWith("https://github.com/$REPOSITORY/") } ?: LATEST_PAGE_URL,
            assets = assets
        )
    }

    fun isReleaseDownload(url: String): Boolean = try {
        val uri = URI(url)
        uri.scheme == "https" && uri.host == "github.com" && uri.rawPath.orEmpty().startsWith(DOWNLOAD_PREFIX) &&
            uri.rawQuery == null
    } catch (_: Exception) {
        false
    }

    /**
     * Reads a `sha256sum` listing: `<hex> <name>` or `<hex> *<name>` per line.
     * File names map to lowercase hex; malformed lines are skipped.
     */
    fun parseChecksums(text: String): Map<String, String> {
        val sums = LinkedHashMap<String, String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val space = line.indexOfFirst { it == ' ' || it == '\t' }
            if (space <= 0) continue
            val hash = line.substring(0, space).lowercase()
            val name = line.substring(space).trim().removePrefix("*").trim()
            if (isSha256(hash) && name.isNotEmpty()) sums[name] = hash
        }
        return sums
    }

    fun isSha256(hex: String): Boolean = hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }

    /**
     * The APK for a device whose ABIs are [supportedAbis], most preferred
     * first (`Build.SUPPORTED_ABIS`): the slim arm64 build where that is the
     * device's own ABI, the universal one for everything else — and for an
     * arm64 device when a release has no slim build.
     */
    fun androidAsset(release: Release, supportedAbis: List<String>): ReleaseAsset? {
        val universal = release.assets.firstOrNull { it.name.endsWith(ANDROID_UNIVERSAL_SUFFIX) }
        if (supportedAbis.firstOrNull() == "arm64-v8a") {
            release.assets.firstOrNull { it.name.endsWith(ANDROID_ARM64_SUFFIX) }?.let { return it }
        }
        return universal
    }

    /**
     * The release notes as plain text for a dialog: Markdown marks and HTML
     * dropped, tables (the downloads list) and folded sections (the summary in
     * another language) left out, cut at a line boundary near [maxChars].
     */
    fun summary(notes: String, maxChars: Int = 1500): String {
        val out = StringBuilder()
        var folded = 0
        for (raw in notes.lineSequence()) {
            val line = raw.trim()
            if (line.startsWith("<details", ignoreCase = true)) folded++
            if (line.startsWith("</details", ignoreCase = true)) { folded = maxOf(0, folded - 1); continue }
            if (folded > 0 || line.startsWith("|")) continue
            val text = line
                .replace(Regex("<[^>]+>"), "")
                .replace(Regex("^#+\\s*"), "")
                .replace(Regex("^[-*]\\s+"), "• ")
                .replace(Regex("\\[([^\\]]+)]\\([^)]*\\)"), "$1")
                .replace("**", "")
                .replace("`", "")
                .trim()
            if (text.isEmpty()) {
                if (out.isNotEmpty() && !out.endsWith("\n\n")) out.append('\n')
                continue
            }
            if (out.length + text.length > maxChars) {
                out.append("…")
                break
            }
            out.append(text).append('\n')
        }
        return out.toString().trim()
    }

    /** The Windows installer, or the portable zip for a copy that was unpacked rather than installed. */
    fun windowsAsset(release: Release, portable: Boolean): ReleaseAsset? {
        val suffix = if (portable) WINDOWS_PORTABLE_SUFFIX else WINDOWS_SETUP_SUFFIX
        return release.assets.firstOrNull { it.name.endsWith(suffix) }
    }
}
