package com.mythaia.vpn.protocol.tls

import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest

/**
 * "Allow insecure" and a pinned certificate, against a real TLS 1.3 server
 * ([TlsServer] with a leaf from a fresh, untrusted CA) over an in-memory pipe.
 *
 * What must hold: the untrusted certificate is refused by default; "allow
 * insecure" (per server or global) lets it through; and a pin decides on its
 * own — a wrong pin is refused even with "allow insecure" on, a right one is
 * accepted without it.
 */
class InsecureAndPinTest {

    private class Pipe(
        private val inbound: Channel<ByteArray>,
        private val outbound: Channel<ByteArray>
    ) : Transport {
        override suspend fun send(data: ByteArray) { outbound.send(data.copyOf()) }
        override fun sendAsync(data: ByteArray) { outbound.trySend(data.copyOf()) }
        override suspend fun receive(): ByteArray? = inbound.receiveCatching().getOrNull()
        override fun forceCancel() { inbound.close(); outbound.close() }

        companion object {
            fun pair(): Pair<Pipe, Pipe> {
                val a = Channel<ByteArray>(Channel.UNLIMITED)
                val b = Channel<ByteArray>(Channel.UNLIMITED)
                return Pipe(inbound = b, outbound = a) to Pipe(inbound = a, outbound = b)
            }
        }
    }

    private val host = "self-signed.example"
    private val leaves = MitmLeafCertificates(MitmCertificateAuthority.generate())
    private val rightPin = sha256Hex(leaves.leaf(host).certificateDer)
    private val wrongPin = "00".repeat(32)

    @After
    fun resetGlobal() {
        CertificatePolicy.setAllowInsecure(false)
    }

    /** Runs one handshake; true when the client accepted the server. */
    private fun connects(tls: TlsConfiguration): Boolean = runBlocking {
        val (clientSide, serverSide) = Pipe.pair()
        val server = async {
            runCatching {
                val first = serverSide.receive() ?: return@runCatching
                TlsServer(serverSide, leaves).handshake(first)
            }
        }
        val accepted = try {
            withTimeout(10_000) { TlsClient(tls).connect(clientSide) }
            true
        } catch (e: TlsError) {
            false
        } finally {
            clientSide.forceCancel()
        }
        server.await()
        accepted
    }

    private fun tls(insecure: Boolean = false, pins: List<String>? = null) = TlsConfiguration(
        serverName = host,
        alpn = listOf("h2", "http/1.1"),
        allowInsecure = insecure,
        pinnedCertSha256 = pins
    )

    @Test
    fun `an untrusted certificate is refused by default`() {
        assertTrue(!connects(tls()))
    }

    @Test
    fun `allow insecure on the server accepts it`() {
        assertTrue(connects(tls(insecure = true)))
    }

    @Test
    fun `the global allow insecure accepts it too`() {
        CertificatePolicy.setAllowInsecure(true)
        assertTrue(connects(tls()))
    }

    @Test
    fun `a right pin is enough without allow insecure`() {
        assertTrue(connects(tls(pins = listOf(rightPin))))
    }

    @Test
    fun `a wrong pin is refused even with allow insecure on the server`() {
        if (connects(tls(insecure = true, pins = listOf(wrongPin)))) {
            fail("allow insecure cancelled the pin")
        }
    }

    @Test
    fun `a wrong pin is refused even with the global allow insecure`() {
        CertificatePolicy.setAllowInsecure(true)
        if (connects(tls(pins = listOf(wrongPin)))) {
            fail("the global switch cancelled a server's pin")
        }
    }

    @Test
    fun `a right pin still connects with allow insecure on`() {
        assertTrue(connects(tls(insecure = true, pins = listOf(rightPin))))
    }

    private fun sha256Hex(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }
}
