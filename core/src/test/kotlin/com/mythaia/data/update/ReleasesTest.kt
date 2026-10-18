package com.mythaia.data.update

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ReleasesTest {

    private fun v(text: String) = requireNotNull(AppVersion.parse(text)) { text }

    @Test
    fun `versions compare number by number`() {
        assertEquals(v("1.3.1"), v("v1.3.1"))
        assertTrue(v("1.10.0") > v("1.9.9"))
        assertTrue(v("2.0") > v("1.99.99"))
        assertEquals(0, v("1.3").compareTo(v("1.3.0")))
        assertTrue(v("1.4.0") > v("1.4.0-beta.1"))
        assertTrue(v("1.4.0-beta.1") > v("1.3.9"))
        assertEquals("1.4.0", v("v1.4.0").toString())
    }

    @Test
    fun `a tag that is not a version is never newer`() {
        for (bad in listOf("", "latest", "1..2", "v", "1.2.x", "1.2.3.4.5", "-1.0", "1.0 beta")) {
            assertNull(bad, AppVersion.parse(bad))
        }
    }

    private val release = """
        {
          "tag_name": "v1.4.0",
          "name": "Mythaia 1.4.0",
          "html_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/tag/v1.4.0",
          "draft": false,
          "prerelease": false,
          "body": "## Highlights\n- **Faster** start\n\n| File | Size |\n|---|---|\n| a.apk | 8 MB |\n<details><summary>Кратко</summary>\nКратко по-русски\n</details>\nSee the [changelog](https://example.com).",
          "assets": [
            {"name": "Mythaia-1.4.0-android-arm64-v8a.apk", "size": 7000000,
             "browser_download_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/Mythaia-1.4.0-android-arm64-v8a.apk",
             "digest": "sha256:${"ab".repeat(32)}"},
            {"name": "Mythaia-1.4.0-android-universal.apk", "size": 9000000,
             "browser_download_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/Mythaia-1.4.0-android-universal.apk"},
            {"name": "Mythaia-Pro-1.4.0-windows-x64-setup.exe", "size": 1,
             "browser_download_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/Mythaia-Pro-1.4.0-windows-x64-setup.exe"},
            {"name": "Mythaia-Pro-1.4.0-windows-x64-portable.zip", "size": 1,
             "browser_download_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/Mythaia-Pro-1.4.0-windows-x64-portable.zip"},
            {"name": "SHA256SUMS.txt", "size": 300,
             "browser_download_url": "https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/SHA256SUMS.txt"},
            {"name": "evil.apk", "size": 1, "browser_download_url": "https://example.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/evil.apk"},
            {"name": "other.apk", "size": 1, "browser_download_url": "https://github.com/someone/else/releases/download/v1/other.apk"},
            {"name": "plain.apk", "size": 1, "browser_download_url": "http://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.4.0/plain.apk"}
          ]
        }
    """.trimIndent()

    @Test
    fun `a release reads its version and only its own downloads`() {
        val parsed = Releases.parse(release)
        assertEquals(v("1.4.0"), parsed.version)
        assertEquals("Mythaia 1.4.0", parsed.title)
        assertEquals(
            listOf(
                "Mythaia-1.4.0-android-arm64-v8a.apk",
                "Mythaia-1.4.0-android-universal.apk",
                "Mythaia-Pro-1.4.0-windows-x64-setup.exe",
                "Mythaia-Pro-1.4.0-windows-x64-portable.zip",
                "SHA256SUMS.txt"
            ),
            parsed.assets.map { it.name }
        )
        assertEquals("ab".repeat(32), parsed.asset("Mythaia-1.4.0-android-arm64-v8a.apk")?.sha256)
        assertNull(parsed.asset("Mythaia-1.4.0-android-universal.apk")?.sha256)
    }

    @Test
    fun `drafts, pre-releases and junk are refused`() {
        for (body in listOf(
            release.replace("\"draft\": false", "\"draft\": true"),
            release.replace("\"prerelease\": false", "\"prerelease\": true"),
            release.replace("v1.4.0\",\n  \"name\"", "nightly\",\n  \"name\""),
            "<html>rate limited</html>"
        )) {
            try {
                Releases.parse(body)
                fail("accepted: ${body.take(40)}")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun `the arm64 APK for arm64 phones, the universal one for the rest`() {
        val parsed = Releases.parse(release)
        assertEquals("Mythaia-1.4.0-android-arm64-v8a.apk", Releases.androidAsset(parsed, listOf("arm64-v8a", "armeabi-v7a"))?.name)
        assertEquals("Mythaia-1.4.0-android-universal.apk", Releases.androidAsset(parsed, listOf("armeabi-v7a", "armeabi"))?.name)
        assertEquals("Mythaia-1.4.0-android-universal.apk", Releases.androidAsset(parsed, listOf("x86_64"))?.name)
        val noSlim = parsed.copy(assets = parsed.assets.filterNot { it.name.endsWith(Releases.ANDROID_ARM64_SUFFIX) })
        assertEquals("Mythaia-1.4.0-android-universal.apk", Releases.androidAsset(noSlim, listOf("arm64-v8a"))?.name)
        assertEquals("Mythaia-Pro-1.4.0-windows-x64-setup.exe", Releases.windowsAsset(parsed, portable = false)?.name)
        assertEquals("Mythaia-Pro-1.4.0-windows-x64-portable.zip", Releases.windowsAsset(parsed, portable = true)?.name)
    }

    @Test
    fun `checksum files read in both sha256sum styles`() {
        val a = "4f6147164c24dd3d87fd14ac2e7d3f5dd5d52e3c52a31a9c897b6709fe460aef"
        val b = "EBC83105DF38EE386E22D73D46E538F473BBD7D757AD8B27B7D0A8DB65842A82"
        val sums = Releases.parseChecksums("$a *Mythaia-1.3.0-android-arm64-v8a.apk\r\n$b  Mythaia-1.3.0-android-universal.apk\n# comment\nnot a line\n1234 short.apk\n")
        assertEquals(
            mapOf(
                "Mythaia-1.3.0-android-arm64-v8a.apk" to a,
                "Mythaia-1.3.0-android-universal.apk" to b.lowercase()
            ),
            sums
        )
    }

    @Test
    fun `the checksum file decides, and GitHub's digest must agree with it`() {
        val parsed = Releases.parse(release)
        val slim = parsed.asset("Mythaia-1.4.0-android-arm64-v8a.apk")!!
        val universal = parsed.asset("Mythaia-1.4.0-android-universal.apk")!!
        assertEquals("ab".repeat(32), UpdateClient.expectedSha256(slim, mapOf(slim.name to "ab".repeat(32))))
        assertEquals("cd".repeat(32), UpdateClient.expectedSha256(universal, mapOf(universal.name to "cd".repeat(32))))
        for (sums in listOf(emptyMap(), mapOf(slim.name to "cd".repeat(32)))) {
            try {
                UpdateClient.expectedSha256(slim, sums)
                fail("accepted $sums")
            } catch (_: UpdateException) {
            }
        }
    }

    @Test
    fun `release notes lose the table and the folded summary`() {
        val text = Releases.summary(Releases.parse(release).notes)
        assertEquals("Highlights\n• Faster start\n\nSee the changelog.", text)
        assertFalse(text.contains("Кратко"))
        assertTrue(Releases.summary("x".repeat(100) + "\n" + "y".repeat(100), maxChars = 150).endsWith("…"))
    }

    @Test
    fun `only release downloads of this repository count`() {
        assertTrue(Releases.isReleaseDownload("https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1.0.0/a.apk"))
        assertFalse(Releases.isReleaseDownload("https://github.com/Myth-T0ks1k/Mythaia/raw/main/a.apk"))
        assertFalse(Releases.isReleaseDownload("https://github.com.evil.com/Myth-T0ks1k/Mythaia/releases/download/v1/a.apk"))
        assertFalse(Releases.isReleaseDownload("https://github.com/Myth-T0ks1k/Mythaia/releases/download/v1/a.apk?x=1"))
        assertFalse(Releases.isReleaseDownload("not a url"))
    }
}
