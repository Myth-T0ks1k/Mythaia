package com.mythaia.desktop.engine

import com.mythaia.vpn.NativeBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The JNI library this machine built loads and answers: its symbols are the
 * ones the Kotlin side declares, and the vendored C behaves (BLAKE3 against
 * its published empty-input digest, ngtcp2 reporting a version). Skipped
 * where no library was built, as on a plain Gradle checkout.
 */
class NativeLibraryTest {

    @Test
    fun `native library loads and answers`() {
        val path = System.getProperty("mythaia.native.library")
        assumeTrue("no native library built", path != null && File(path).isFile)
        assertTrue("native library failed to load", NativeBridge.isLoaded)

        val digest = NativeBridge.nativeBlake3Hash(ByteArray(0)).joinToString("") { "%02x".format(it) }
        assertEquals("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", digest)

        assertTrue(NativeBridge.nativeQuicVersion().isNotBlank())
    }
}
