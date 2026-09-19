package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The TLS-1.3-shaped record header and the two-byte length prefix.
 *
 * The expected bytes are written from the wire layout the reference fixes — the
 * `0x17 0x03 0x03` prefix and a big-endian length — not read back from the
 * encoder. The decode bounds matter for more than tidiness: a length below the
 * tag-plus-one minimum or above the TLS maximum is exactly the noise a rejected
 * 0-RTT server sends, and rejecting it here is what lets the read path tell a
 * rejection from a real record.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessRecordFramingTest {

    @Test
    fun `header encodes the fixed prefix and a big-endian length`() {
        // 0x1234 = 4660 across bytes 3 and 4.
        assertArrayEquals(
            byteArrayOf(0x17, 0x03, 0x03, 0x12, 0x34),
            VlessRecordHeader.encode(0x1234)
        )
    }

    @Test
    fun `header decode returns the encoded length`() {
        for (length in intArrayOf(17, 18, 1232, 8208, 16640)) {
            assertEquals(length, VlessRecordHeader.decode(VlessRecordHeader.encode(length)))
        }
    }

    @Test
    fun `header decode rejects a wrong prefix`() {
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessRecordHeader.decode(byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x20))
        }
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessRecordHeader.decode(byteArrayOf(0x17, 0x03, 0x01, 0x00, 0x20))
        }
    }

    @Test
    fun `header decode rejects lengths outside the TLS bounds`() {
        // 16 is below the 17-byte minimum (tag + one byte); 16641 is past the max.
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessRecordHeader.decode(byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x10))
        }
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessRecordHeader.decode(byteArrayOf(0x17, 0x03, 0x03, 0x41, 0x01))
        }
    }

    @Test
    fun `header decode rejects a header that is not five bytes`() {
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessRecordHeader.decode(byteArrayOf(0x17, 0x03, 0x03, 0x00))
        }
    }

    @Test
    fun `length prefix is big-endian and round-trips`() {
        assertArrayEquals(byteArrayOf(0x00, 0x20), VlessLengthPrefix.encode(32))
        assertArrayEquals(byteArrayOf(0x04.toByte(), 0xD2.toByte()), VlessLengthPrefix.encode(1234))
        assertEquals(1234, VlessLengthPrefix.decode(byteArrayOf(0x04.toByte(), 0xD2.toByte())))
        assertEquals(65535, VlessLengthPrefix.decode(byteArrayOf(0xFF.toByte(), 0xFF.toByte())))
    }
}
