package com.mythaia.desktop.store

import com.mythaia.data.model.ProxyConfiguration
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** The atomic write, the background writer, and what happens to the data when the file cannot be replaced. */
class DesktopStoreTest {

    @Test
    fun `a write replaces the file and leaves no temp behind`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val file = File(dir, "settings.json")
            val store = DesktopStore()
            store.write(file, "one")
            store.write(file, "two")
            assertEquals("two", file.readText())
            assertFalse(File(dir, "settings.json.tmp").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a file held open does not lose the new data`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val file = File(dir, "configs.json")
            val store = DesktopStore()
            store.write(file, "old")
            // Java opens without FILE_SHARE_DELETE on Windows, so the replace
            // is refused while this is open; elsewhere it simply succeeds.
            RandomAccessFile(file, "r").use {
                store.write(file, "new")
            }
            val temp = File(dir, "configs.json.tmp")
            assertTrue("new text in the file or kept in the temp", file.readText() == "new" || temp.readText() == "new")
            // Once nothing holds it, the next write goes through and tidies up.
            store.write(file, "newer")
            assertEquals("newer", file.readText())
            assertFalse(temp.exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `saves return at once and a burst is written once, newest last`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val file = File(dir, "configs.json")
            val store = DesktopStore()
            val writing = CountDownLatch(1)
            val release = CountDownLatch(1)
            val encodes = AtomicInteger()
            // The writer is stuck on a slow first save, as on a 30 MB list.
            store.save(file) {
                encodes.incrementAndGet()
                writing.countDown()
                release.await(10, TimeUnit.SECONDS)
                "first"
            }
            assertTrue(writing.await(5, TimeUnit.SECONDS))
            val began = System.nanoTime()
            for (i in 1..50) store.save(file) { encodes.incrementAndGet(); "save $i" }
            val tookMs = (System.nanoTime() - began) / 1_000_000
            assertTrue("saves waited for the writer: $tookMs ms", tookMs < 1_000)
            assertFalse("flush must report a writer that has not finished", store.flush(50))

            release.countDown()
            assertTrue(store.flush(10_000))
            assertEquals("save 50", file.readText())
            assertEquals("the 49 saves in between are never encoded", 2, encodes.get())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a save that fails to encode does not stop the writer`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val store = DesktopStore()
            store.save(File(dir, "settings.json")) { throw IllegalStateException("boom") }
            store.save(File(dir, "rules.json")) { "[]" }
            assertTrue(store.flush(10_000))
            assertEquals("[]", File(dir, "rules.json").readText())
            assertFalse(File(dir, "settings.json").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `the server list is stored compact and reads back the same, old files too`() {
        val configs = listOf(
            "vless://${UUID.randomUUID()}@1.2.3.4:443?security=reality&sni=www.example.com&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde&sid=6ba85179&fp=chrome&type=grpc&serviceName=svc#reality",
            "vless://${UUID.randomUUID()}@cdn.example.com:443?security=tls&type=ws&path=%2Fws&host=front.example.com#ws",
            "trojan://secret@5.6.7.8:443?sni=t.example.com#trojan",
            "ss://YWVzLTI1Ni1nY206cGFzcw@9.9.9.9:8388#ss",
            "hysteria2://auth@10.0.0.1:443?sni=h.example.com&obfs=salamander&obfs-password=x#hy2"
        ).map { ProxyConfiguration.fromUrl(it) }
        val store = DesktopStore()
        val oldForm = Json { ignoreUnknownKeys = true; encodeDefaults = true; prettyPrint = true; isLenient = true }
        val serializer = ListSerializer(ProxyConfiguration.serializer())

        val text = store.encodeConfigurations(configs)
        assertFalse("no indentation", text.contains('\n'))
        val pretty = oldForm.encodeToString(serializer, configs)
        assertTrue("compact ${text.length} vs pretty ${pretty.length}", text.length * 3 < pretty.length)
        // Compared through the full form, which spells out every field.
        assertEquals(pretty, oldForm.encodeToString(serializer, store.decodeConfigurations(text)))
        // A file an earlier version wrote reads as before.
        assertEquals(pretty, oldForm.encodeToString(serializer, store.decodeConfigurations(pretty)))
    }
}
