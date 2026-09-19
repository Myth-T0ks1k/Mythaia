package com.mythaia.vpn.protocol.sudoku

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * How a profile resolves into carrier settings, and which shapes the dialler
 * refuses.
 *
 * The subtle parts are the two ways a key is read and which shapes are carried.
 * A hex key is both an account fingerprint (its raw private bytes) and, once run
 * through the base-point multiply, the shared pre-shared string; a passphrase is
 * neither and is used verbatim both ways. Getting that split wrong would either
 * leak the private key into the pre-shared string or fingerprint the wrong
 * account. The refusals are the second half: `on` multiplexing, a TLS carrier,
 * and the framed HTTP masks are not wired, and dialling them as if they were
 * would put Sudoku bytes onto a connection the server reads differently.
 *
 * Expectations are derived from the reference's own rules — a 32-byte key is
 * already the public key, the fingerprint is taken over the raw key bytes, a hint
 * travels only when more than one layout is configured — not from what the code
 * happens to produce.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuConnectionSettingsTest {

    @Test
    fun `a passphrase key is used verbatim as both the pre-shared string and the fingerprint source`() {
        val settings = SudokuConnectionSettings.of(
            serverHost = "server.example",
            serverPort = 8080,
            sudoku = SudokuConfiguration(key = "hunter2")
        )
        assertEquals("hunter2", settings.psk)
        assertArrayEquals("hunter2".toByteArray(Charsets.UTF_8), settings.keyFingerprintSource)
        assertFalse(settings.sendsTableHint)
    }

    @Test
    fun `a 32-byte hex key is already the public key and fingerprints over its raw bytes`() {
        // 64 hex chars -> 32 raw bytes, each 0x0a. A 32-byte key is a bare public
        // key, so the pre-shared string is its own lowercase hex, and the
        // fingerprint is taken over the raw bytes, not the hex text.
        val keyHex = "0a".repeat(32)
        val settings = SudokuConnectionSettings.of(
            serverHost = "server.example",
            serverPort = 8080,
            sudoku = SudokuConfiguration(key = keyHex)
        )
        assertEquals(keyHex, settings.psk)
        assertArrayEquals(ByteArray(32) { 0x0a }, settings.keyFingerprintSource)
    }

    @Test
    fun `more than one custom layout makes the client send a table hint and pick one layout`() {
        val tables = listOf("xxppvvvv", "ppxxvvvv")
        val settings = SudokuConnectionSettings.of(
            serverHost = "server.example",
            serverPort = 8080,
            sudoku = SudokuConfiguration(key = "k", customTables = tables)
        )
        assertTrue(settings.sendsTableHint)
        assertTrue(settings.selectedCustomTable in tables)
    }

    @Test
    fun `the legacy mask fronts the stream with a decoy POST by default`() {
        val settings = SudokuConnectionSettings.of(
            serverHost = "server.example",
            serverPort = 8080,
            sudoku = SudokuConfiguration(key = "k")
        )
        // Default config leaves httpmask on in legacy mode, so a decoy request is
        // written ahead of the obfuscated stream.
        val header = settings.legacyMaskHeader
        assertNotNull(header)
        val text = String(header!!, Charsets.US_ASCII)
        assertTrue(text.startsWith("POST /api HTTP/1.1\r\n"))
        assertTrue(text.contains("Host: server.example\r\n"))
        assertTrue(text.endsWith("\r\n\r\n"))
    }

    @Test
    fun `a disabled mask sends no decoy prefix`() {
        val settings = SudokuConnectionSettings.of(
            serverHost = "server.example",
            serverPort = 8080,
            sudoku = SudokuConfiguration(
                key = "k",
                httpMask = SudokuHttpMaskConfiguration(disable = true)
            )
        )
        assertNull(settings.legacyMaskHeader)
    }

    // MARK: - Carrier refusal

    @Test
    fun `the plain obfuscated carrier is dialable`() {
        assertNull(SudokuClient.carrierRefusal(SudokuConfiguration(key = "k")))
        assertNull(
            SudokuClient.carrierRefusal(
                SudokuConfiguration(key = "k", multiplex = SudokuMultiplex.AUTO)
            )
        )
        assertNull(
            SudokuClient.carrierRefusal(
                SudokuConfiguration(key = "k", httpMask = SudokuHttpMaskConfiguration(disable = true))
            )
        )
    }

    @Test
    fun `native multiplexing is refused`() {
        assertNotNull(
            SudokuClient.carrierRefusal(
                SudokuConfiguration(key = "k", multiplex = SudokuMultiplex.ON)
            )
        )
    }

    @Test
    fun `a TLS carrier is refused`() {
        assertNotNull(
            SudokuClient.carrierRefusal(
                SudokuConfiguration(key = "k", httpMask = SudokuHttpMaskConfiguration(tls = true))
            )
        )
    }

    @Test
    fun `the framed HTTP masks are refused`() {
        for (mode in listOf(SudokuHttpMaskMode.STREAM, SudokuHttpMaskMode.POLL, SudokuHttpMaskMode.AUTO, SudokuHttpMaskMode.WS)) {
            assertNotNull(
                "mode $mode should be refused",
                SudokuClient.carrierRefusal(
                    SudokuConfiguration(key = "k", httpMask = SudokuHttpMaskConfiguration(mode = mode))
                )
            )
        }
    }
}
