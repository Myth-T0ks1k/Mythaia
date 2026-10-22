package com.mythaia.vpn

import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

class UploadBackpressureTest {

    @Test
    fun `NioSocket applies natural backpressure on large upload burst without dropping or failing`() = runBlocking {
        val totalBytes = 1024 * 1024 // 1 MB (> 256 KB MAX_PENDING_SEND_BYTES and > 64 KB SO_SNDBUF)
        val payload = ByteArray(totalBytes) { (it * 31 + 7).toByte() }
        val received = ByteArrayOutputStream(totalBytes)

        val server = ServerSocket()
        server.reuseAddress = true
        server.receiveBufferSize = 16 * 1024
        server.bind(InetSocketAddress("127.0.0.1", 0))

        val readerThread = thread(isDaemon = true, name = "slow-upload-receiver") {
            server.accept().use { client ->
                client.receiveBufferSize = 16 * 1024
                val inp = client.getInputStream()
                val buf = ByteArray(8192)
                var readTotal = 0
                while (readTotal < totalBytes) {
                    val n = inp.read(buf)
                    if (n < 0) break
                    received.write(buf, 0, n)
                    readTotal += n
                    if (readTotal % (128 * 1024) == 0) {
                        Thread.sleep(5)
                    }
                }
                client.getOutputStream().write("ok:$readTotal".toByteArray())
                client.getOutputStream().flush()
            }
        }

        val socket = NioSocket()
        try {
            withTimeout(10_000) {
                socket.connect("127.0.0.1", server.localPort)
                var offset = 0
                val chunkSize = 64 * 1024
                while (offset < totalBytes) {
                    val end = minOf(offset + chunkSize, totalBytes)
                    socket.send(payload.copyOfRange(offset, end))
                    offset = end
                }
                val reply = socket.receive()
                assertEquals("ok:$totalBytes", String(reply!!))
            }
            readerThread.join(5_000)
            assertArrayEquals(payload, received.toByteArray())
        } finally {
            socket.forceCancel()
            server.close()
        }
    }

    @Test
    fun `TunnelConstants upload half-close timeout and pending buffer size prevent premature RST`() {
        assertTrue(
            "downlinkOnlyTimeoutMs must be >= 15s so half-closed uploads are not killed after 1s",
            TunnelConstants.downlinkOnlyTimeoutMs >= 15_000L
        )
        assertTrue(
            "tcpMaxPendingDataSize must cover lwIP TCP_WND (256 * 1460 = 373,760 bytes)",
            TunnelConstants.tcpMaxPendingDataSize >= 373_760
        )
    }
}
