package com.mythaia.vpn

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The QUIC stack against RFC 9001's own worked example.
 *
 * This has to be an instrumented test. The vendored ngtcp2 and its mbedTLS
 * backend are arm64 native code, so a desktop JVM has nothing to load — which
 * is why none of it appears in the unit suite, and why "it compiles" was the
 * strongest thing that could be said about the crypto until this ran.
 */
@RunWith(AndroidJUnit4::class)
class QuicCryptoTest {

    @Test
    fun rfc9001AppendixAMatchesByteForByte() {
        // Null means every intermediate agreed with the RFC; anything else
        // names the first step that did not, with both values.
        val failure = NativeBridge.nativeQuicSelfTest()
        assertNull(failure, failure)
    }

    @Test
    fun theVendoredVersionIsTheOneWeThinkItIs() {
        val version = NativeBridge.nativeQuicVersion()
        assertNotNull(version)
        // UPSTREAM_MAP.md pins this; a mismatch means someone upgraded the
        // vendor tree without walking the upgrade procedure.
        assertTrue("unexpected ngtcp2 version: $version", version == "1.25.0")
    }
}
