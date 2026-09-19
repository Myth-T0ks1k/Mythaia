package com.mythaia.vpn.protocol.sudoku

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * The pure handshake core, checked against bytes assembled independently from the
 * KIP wire format rather than against what the code emits.
 *
 * The three things worth pinning are the exact layout of the client hello — a
 * server that reads its fields at the wrong offsets authenticates nobody — the
 * classification of the reply into the three answers KIP actually has, and the
 * request frames that select a flow. Every expectation below is built from the
 * spec: the hello field order and the feature-flag constant, the server-hello
 * length and nonce-echo rule, and the SOCKS5 address form, so a transcription
 * error in the implementation would fail the test rather than be mirrored by it.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuHandshakeTest {

    private val magic = byteArrayOf(0x6B, 0x69, 0x70)

    private fun kipFrame(type: Int, payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(magic)
        out.write(type)
        out.write((payload.size ushr 8) and 0xFF)
        out.write(payload.size and 0xFF)
        out.write(payload)
        return out.toByteArray()
    }

    private fun bigEndian64(value: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) out[i] = ((value ushr (56 - 8 * i)) and 0xFF).toByte()
        return out
    }

    // MARK: - Client hello

    @Test
    fun `client hello lays fields out in the KIP-defined order`() {
        val fingerprintSource = "hunter2".toByteArray(Charsets.UTF_8)
        val timestamp = 0x1122334455667788L
        val nonce = ByteArray(16) { (it + 1).toByte() }
        val publicKey = ByteArray(32) { (0x40 + it).toByte() }

        // Spec layout: ts(8 BE) ‖ sha256(fingerprintSource)[:8] ‖ nonce(16) ‖
        // publicKey(32) ‖ featureFlags(4 BE = 0x0000001F). No table hint.
        val digest8 = MessageDigest.getInstance("SHA-256").digest(fingerprintSource).copyOf(8)
        val payload = ByteArrayOutputStream().apply {
            write(bigEndian64(timestamp))
            write(digest8)
            write(nonce)
            write(publicKey)
            write(byteArrayOf(0x00, 0x00, 0x00, 0x1F))
        }.toByteArray()
        assertEquals(68, payload.size)

        val expected = kipFrame(0x01, payload)
        val actual = SudokuHandshake.clientHelloFrame(fingerprintSource, timestamp, publicKey, nonce, null)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun `client hello appends the table hint when one is given`() {
        val fingerprintSource = "hunter2".toByteArray(Charsets.UTF_8)
        val timestamp = 1L
        val nonce = ByteArray(16) { 0x11 }
        val publicKey = ByteArray(32) { 0x22 }
        val hint = 0x0A0B0C0DL

        val digest8 = MessageDigest.getInstance("SHA-256").digest(fingerprintSource).copyOf(8)
        val payload = ByteArrayOutputStream().apply {
            write(bigEndian64(timestamp))
            write(digest8)
            write(nonce)
            write(publicKey)
            write(byteArrayOf(0x00, 0x00, 0x00, 0x1F))
            // Table hint is a 32-bit big-endian value right after the flags.
            write(byteArrayOf(0x0A, 0x0B, 0x0C, 0x0D))
        }.toByteArray()
        assertEquals(72, payload.size)

        val expected = kipFrame(0x01, payload)
        val actual = SudokuHandshake.clientHelloFrame(fingerprintSource, timestamp, publicKey, nonce, hint)
        assertArrayEquals(expected, actual)
    }

    // MARK: - Server hello classification

    private fun serverHelloPayload(nonce: ByteArray, serverPublicKey: ByteArray): ByteArray {
        // Spec: nonce echo(16) ‖ serverPublicKey(32) ‖ serverFlags(4).
        return nonce + serverPublicKey + byteArrayOf(0, 0, 0, 0)
    }

    @Test
    fun `a valid server hello is ready and yields the server public key`() {
        val nonce = ByteArray(16) { (it + 1).toByte() }
        val serverPublicKey = ByteArray(32) { (0x80 + it).toByte() }
        val payload = serverHelloPayload(nonce, serverPublicKey)

        val outcome = SudokuHandshake.classifyServerHello(0x02.toByte(), payload, nonce)
        assertTrue(outcome is SudokuHandshake.ServerHello.Ready)
        assertArrayEquals(serverPublicKey, (outcome as SudokuHandshake.ServerHello.Ready).publicKey)
    }

    @Test
    fun `a message that is not a server hello is rejected, not accepted`() {
        val nonce = ByteArray(16) { (it + 1).toByte() }
        val payload = serverHelloPayload(nonce, ByteArray(32) { 0x33 })

        // A client-hello type on the reply means the peer is not answering KIP.
        val outcome = SudokuHandshake.classifyServerHello(0x01.toByte(), payload, nonce)
        assertTrue(outcome is SudokuHandshake.ServerHello.Rejected)
        assertEquals(0x01.toByte(), (outcome as SudokuHandshake.ServerHello.Rejected).type)
    }

    @Test
    fun `a server hello whose nonce does not echo ours is malformed`() {
        val sentNonce = ByteArray(16) { (it + 1).toByte() }
        val otherNonce = ByteArray(16) { (it + 100).toByte() }
        val payload = serverHelloPayload(otherNonce, ByteArray(32) { 0x44 })

        assertThrows(SudokuError.ProtocolViolation::class.java) {
            SudokuHandshake.classifyServerHello(0x02.toByte(), payload, sentNonce)
        }
    }

    @Test
    fun `a server hello of the wrong length is malformed`() {
        val nonce = ByteArray(16) { (it + 1).toByte() }
        // 51 bytes: one short of the fixed 52-byte hello.
        val payload = nonce + ByteArray(32) { 0x55 } + byteArrayOf(0, 0, 0)

        assertThrows(SudokuError.ProtocolViolation::class.java) {
            SudokuHandshake.classifyServerHello(0x02.toByte(), payload, nonce)
        }
    }

    // MARK: - Request frames

    @Test
    fun `a TCP connect request carries the destination in SOCKS5 domain form`() {
        val name = "example.com".toByteArray(Charsets.UTF_8)
        // Spec: ATYP_DOMAIN(0x03) ‖ len(1) ‖ name ‖ port(2 BE); 443 = 0x01BB.
        val address = ByteArrayOutputStream().apply {
            write(0x03)
            write(name.size)
            write(name)
            write(0x01)
            write(0xBB)
        }.toByteArray()
        val expected = kipFrame(0x10, address)

        assertArrayEquals(expected, SudokuHandshake.connectTcpRequest("example.com", 443))
    }

    @Test
    fun `a UDP open request is an empty KIP frame of its own type`() {
        // magic ‖ 0x12 ‖ length 0.
        val expected = byteArrayOf(0x6B, 0x69, 0x70, 0x12, 0x00, 0x00)
        assertArrayEquals(expected, SudokuHandshake.openUdpRequest())
    }
}
