package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The identifiers are checked against RFC 9000 §18.2 written out by hand, and
 * the algorithm numbers against the vendored `ngtcp2.h`. Neither is derived
 * from the code under test: a table that only agrees with itself would let a
 * transposed identifier through, and a peer's response to a parameter it does
 * not recognise is to ignore it silently.
 */
class QuicTuningTest {

    private val presets: List<Pair<String, QuicTuning>> = listOf(
        "naive" to QuicTuning.NAIVE,
        "nowhere" to QuicTuning.NOWHERE,
        "hysteria/brutal" to QuicTuning.hysteria(HysteriaCongestionControl.BRUTAL, 100),
        "hysteria/bbr" to QuicTuning.hysteria(HysteriaCongestionControl.BBR, 0)
    )

    private fun QuicTuning.valueOf(id: Int): Long? =
        advertisedParameters.first { it.id == id }.value

    // MARK: - RFC 9000 §18.2

    @Test
    fun `the transport parameter identifiers are the ones the RFC assigns`() {
        assertEquals(0x01, QuicTransportParameterId.MAX_IDLE_TIMEOUT)
        assertEquals(0x04, QuicTransportParameterId.INITIAL_MAX_DATA)
        assertEquals(0x05, QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL)
        assertEquals(0x06, QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
        assertEquals(0x07, QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_UNI)
        assertEquals(0x08, QuicTransportParameterId.INITIAL_MAX_STREAMS_BIDI)
        assertEquals(0x09, QuicTransportParameterId.INITIAL_MAX_STREAMS_UNI)
        assertEquals(0x0c, QuicTransportParameterId.DISABLE_ACTIVE_MIGRATION)
    }

    @Test
    fun `each field is advertised under its own identifier`() {
        // 0x00, 0x02, 0x03, 0x0a, 0x0b, 0x0d..0x10 exist in the registry but
        // are either server-only or left to ngtcp2's defaults, so they are not
        // expected here.
        for ((name, tuning) in presets) {
            assertEquals(name, tuning.maxIdleTimeoutMillis, tuning.valueOf(0x01))
            assertEquals(name, tuning.initialMaxData, tuning.valueOf(0x04))
            assertEquals(name, tuning.initialMaxStreamDataBidiLocal, tuning.valueOf(0x05))
            assertEquals(name, tuning.initialMaxStreamDataBidiRemote, tuning.valueOf(0x06))
            assertEquals(name, tuning.initialMaxStreamDataUni, tuning.valueOf(0x07))
            assertEquals(name, tuning.initialMaxStreamsBidi, tuning.valueOf(0x08))
            assertEquals(name, tuning.initialMaxStreamsUni, tuning.valueOf(0x09))
        }
    }

    @Test
    fun `max_idle_timeout goes out in milliseconds, not ngtcp2's nanoseconds`() {
        // RFC 9000 §18.2 states the parameter in milliseconds; ngtcp2 keeps
        // every duration in nanoseconds. Every preset idles at 30 seconds.
        for ((name, tuning) in presets) {
            assertEquals(name, 30_000_000_000L, tuning.maxIdleTimeoutNanos)
            assertEquals(name, 30_000L, tuning.valueOf(0x01))
        }
    }

    @Test
    fun `disable_active_migration is a presence, not a value`() {
        // Zero-length per RFC 9000 §18.2, so it is either there or it is not.
        for ((name, tuning) in presets) {
            assertFalse(name, tuning.disableActiveMigration)
            assertTrue(name, tuning.advertisedParameters.none { it.id == 0x0c })
        }

        val pinned = QuicTuning.NAIVE.copy(disableActiveMigration = true)
        val parameter = pinned.advertisedParameters.single { it.id == 0x0c }
        assertNull(parameter.value)
    }

    @Test
    fun `the local settings have no identifier because they never go on the wire`() {
        // The auto-tuning ceilings and the two client-side timers are ngtcp2
        // settings. Advertising a ceiling would tell the peer something QUIC
        // has no way to express, and no registry entry exists for one.
        //
        // Asserted on identity rather than on value: two unrelated settings can
        // legitimately hold the same number — NAIVE sets both maxStreamWindow
        // and initialMaxData to 64 MiB — and a value-membership check reads
        // that coincidence as a leak.
        val registered = setOf(
            QuicTransportParameterId.MAX_IDLE_TIMEOUT,
            QuicTransportParameterId.INITIAL_MAX_DATA,
            QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            QuicTransportParameterId.INITIAL_MAX_STREAM_DATA_UNI,
            QuicTransportParameterId.INITIAL_MAX_STREAMS_BIDI,
            QuicTransportParameterId.INITIAL_MAX_STREAMS_UNI,
            QuicTransportParameterId.DISABLE_ACTIVE_MIGRATION
        )
        for ((name, tuning) in presets) {
            for (parameter in tuning.advertisedParameters) {
                assertTrue(
                    "$name advertises unregistered id 0x%x".format(parameter.id),
                    registered.contains(parameter.id)
                )
            }
        }
    }

    @Test
    fun `every advertised value fits the varint the parameter is written as`() {
        for ((name, tuning) in presets) {
            for (parameter in tuning.advertisedParameters) {
                val value = parameter.value ?: continue
                assertTrue("$name/${parameter.id}", value in 0..QuicVarInt.MAX)
                // Round-trips through the encoding RFC 9000 §16 defines.
                val encoded = QuicVarInt.encode(value)
                assertEquals("$name/${parameter.id}", value, QuicVarInt.decode(encoded)?.value)
            }
        }
    }

    @Test
    fun `the stream cap is the one the RFC derives from the stream ID space`() {
        // 2^60, because a stream ID is the count shifted left two places plus
        // two type bits and has to stay inside a 62-bit varint.
        assertEquals(1_152_921_504_606_846_976L, QuicTuning.MAX_STREAMS)
        assertEquals(QuicVarInt.MAX, QuicTuning.MAX_STREAMS * 4 - 1)
    }

    @Test
    fun `a stream count past the cap is refused rather than truncated`() {
        try {
            QuicTuning.NAIVE.copy(initialMaxStreamsBidi = QuicTuning.MAX_STREAMS + 1)
            throw AssertionError("expected a refusal")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    // MARK: - ngtcp2 algorithm numbers

    @Test
    fun `the congestion control numbers are ngtcp2's own`() {
        // ngtcp2.h: NGTCP2_CC_ALGO_RENO 0x00, CUBIC 0x01, BBR 0x02.
        assertEquals(0x00, QuicCongestionControl.Reno.ngtcp2Algorithm)
        assertEquals(0x01, QuicCongestionControl.Cubic.ngtcp2Algorithm)
        assertEquals(0x02, QuicCongestionControl.Bbr.ngtcp2Algorithm)
    }

    @Test
    fun `Brutal starts ngtcp2 on CUBIC because it replaces the controller later`() {
        val brutal = QuicCongestionControl.Brutal(initialBytesPerSecond = 1)
        assertEquals(0x01, brutal.ngtcp2Algorithm)
    }

    // MARK: - Presets

    @Test
    fun `naive advertises the values the reference does`() {
        val mib = 1024L * 1024L
        val tuning = QuicTuning.NAIVE
        assertEquals(QuicCongestionControl.Cubic, tuning.congestionControl)
        assertEquals(64 * mib, tuning.maxStreamWindow)
        assertEquals(128 * mib, tuning.maxWindow)
        assertEquals(64 * mib, tuning.initialMaxData)
        assertEquals(16 * mib, tuning.initialMaxStreamDataBidiLocal)
        assertEquals(16 * mib, tuning.initialMaxStreamDataBidiRemote)
        assertEquals(16 * mib, tuning.initialMaxStreamDataUni)
        assertEquals(1024L, tuning.initialMaxStreamsBidi)
        assertEquals(100L, tuning.initialMaxStreamsUni)
        assertEquals(10_000_000_000L, tuning.handshakeTimeoutNanos)
        assertEquals(15_000_000_000L, tuning.keepAliveTimeoutNanos)
    }

    @Test
    fun `nowhere grants the peer no streams at all`() {
        val tuning = QuicTuning.NOWHERE
        assertEquals(QuicCongestionControl.Bbr, tuning.congestionControl)
        assertEquals(4L * 1024 * 1024, tuning.initialMaxStreamDataBidiLocal)
        // Nothing the peer could open, so nothing funded for it to open with.
        assertEquals(0L, tuning.initialMaxStreamsBidi)
        assertEquals(0L, tuning.initialMaxStreamsUni)
        assertEquals(0L, tuning.initialMaxStreamDataBidiRemote)
        assertEquals(0L, tuning.initialMaxStreamDataUni)
    }

    @Test
    fun `hysteria BBR asks ngtcp2 for BBR and leaves the windows room to grow`() {
        val mib = 1024L * 1024L
        val tuning = QuicTuning.hysteria(HysteriaCongestionControl.BBR, uploadMbps = 50)
        assertEquals(QuicCongestionControl.Bbr, tuning.congestionControl)
        assertEquals(16 * mib, tuning.maxStreamWindow)
        assertEquals(32 * mib, tuning.maxWindow)
        assertEquals(8 * mib, tuning.initialMaxData)
        assertEquals(2 * mib, tuning.initialMaxStreamDataBidiLocal)
        assertEquals(1024L, tuning.initialMaxStreamsBidi)
        assertEquals(16L, tuning.initialMaxStreamsUni)
    }

    @Test
    fun `hysteria Brutal keeps the windows small and paces to the declared rate`() {
        val mib = 1024L * 1024L
        val tuning = QuicTuning.hysteria(HysteriaCongestionControl.BRUTAL, uploadMbps = 100)
        assertEquals(2 * mib, tuning.maxStreamWindow)
        assertEquals(4 * mib, tuning.maxWindow)
        assertEquals(4 * mib, tuning.initialMaxData)
        assertEquals(2 * mib, tuning.initialMaxStreamDataBidiRemote)
        assertEquals(16L, tuning.initialMaxStreamsUni)
    }

    @Test
    fun `megabits per second become bytes per second`() {
        // 100 Mb/s is 100_000_000 bits, which is 12_500_000 bytes.
        val rate = { mbps: Int ->
            (QuicTuning.hysteria(HysteriaCongestionControl.BRUTAL, mbps).congestionControl
                as QuicCongestionControl.Brutal).initialBytesPerSecond
        }
        assertEquals(12_500_000L, rate(100))
        assertEquals(125_000L, rate(1))
        assertEquals(1_250_000_000L, rate(10_000))
        // Absent or nonsensical bandwidth opens at zero rather than wrapping;
        // the server's Hysteria-CC-RX corrects it after authentication.
        assertEquals(0L, rate(0))
        assertEquals(0L, rate(-1))
        assertEquals(0L, rate(Int.MIN_VALUE))
    }

    // MARK: - Invariants that hold across every preset

    @Test
    fun `a ceiling is never below the window it is meant to cap`() {
        for ((name, tuning) in presets) {
            assertTrue(name, tuning.maxWindow >= tuning.initialMaxData)
            assertTrue(name, tuning.maxStreamWindow >= tuning.initialMaxStreamDataBidiLocal)
            assertTrue(name, tuning.maxStreamWindow >= tuning.initialMaxStreamDataBidiRemote)
            assertTrue(name, tuning.maxStreamWindow >= tuning.initialMaxStreamDataUni)
        }
    }

    @Test
    fun `the connection window is never smaller than a single stream's`() {
        // Otherwise a stream could never reach the limit it was granted.
        for ((name, tuning) in presets) {
            assertTrue(name, tuning.initialMaxData >= tuning.initialMaxStreamDataBidiLocal)
            assertTrue(name, tuning.initialMaxData >= tuning.initialMaxStreamDataBidiRemote)
            assertTrue(name, tuning.initialMaxData >= tuning.initialMaxStreamDataUni)
            assertTrue(name, tuning.maxWindow >= tuning.maxStreamWindow)
        }
    }

    @Test
    fun `the keepalive fires before the idle timeout can expire`() {
        for ((name, tuning) in presets) {
            assertTrue(name, tuning.keepAliveTimeoutNanos < tuning.maxIdleTimeoutNanos)
            assertTrue(name, tuning.handshakeTimeoutNanos < tuning.maxIdleTimeoutNanos)
        }
    }

    @Test
    fun `migration is left available on every preset`() {
        // Advertising disable_active_migration would rule out surviving a
        // Wi-Fi to cellular handover.
        for ((name, tuning) in presets) {
            assertFalse(name, tuning.disableActiveMigration)
        }
    }
}
