package com.mythaia.desktop.engine

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlin.concurrent.thread

/**
 * The app's own TLS 1.3 client against the JDK's TLS server on loopback —
 * an independent peer, so a wire-format slip on our side shows up as a
 * handshake failure here rather than only on a real server.
 */
class TlsClientJsseTest {

    private fun serverContext(): SSLContext {
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            X500Name("CN=localhost"), BigInteger.valueOf(now), Date(now - 60_000), Date(now + 86_400_000),
            X500Name("CN=localhost"), keys.public
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keys.private)
        val certificate = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        val store = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        store.setKeyEntry("srv", keys.private, charArrayOf(), arrayOf(certificate))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, charArrayOf()) }
        return SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
    }

    private fun roundTrip(fingerprint: TlsFingerprint, fragment: FragmentSettings) = runBlocking {
        MythaiaLogger.debugEnabled = true
        FragmentPolicy.set(fragment)
        val server = serverContext().serverSocketFactory.createServerSocket(0) as SSLServerSocket
        server.enabledProtocols = arrayOf("TLSv1.3")
        val serverThread = thread(isDaemon = true) {
            runCatching {
                server.accept().use { s ->
                    val input = s.getInputStream()
                    val buffer = ByteArray(64)
                    val n = input.read(buffer)
                    println("server read $n bytes: " + buffer.copyOf(n).joinToString(" ") { "%02x".format(it) })
                    s.getOutputStream().write("pong:".toByteArray() + buffer.copyOf(n))
                    s.getOutputStream().flush()
                }
            }.onFailure { println("server side: $it") }
        }
        val client = TlsClient(
            TlsConfiguration(serverName = "localhost", allowInsecure = true, fingerprint = fingerprint, fragment = fragment)
        )
        val started = System.nanoTime()
        val connection = withTimeout(15_000) { client.connect("127.0.0.1", server.localPort) }
        println("$fingerprint fragment=${fragment.isEnabled}: handshake in ${(System.nanoTime() - started) / 1_000_000} ms")
        connection.send("ping".toByteArray())
        val answer = withTimeout(10_000) { connection.receive() }
        println("client got ${answer?.size} bytes: " + answer?.joinToString(" ") { "%02x".format(it) })
        assertEquals("pong:ping", String(answer!!))
        client.cancel()
        serverThread.join(2_000)
        server.close()
    }

    @Test
    fun `chrome fingerprint, no fragmentation`() = roundTrip(TlsFingerprint.CHROME_133, FragmentSettings(isEnabled = false))

    @Test
    fun `safari fingerprint, fragmented hello`() = roundTrip(TlsFingerprint.SAFARI_26, FragmentSettings(isEnabled = true, minLength = 3, maxLength = 3, minInterval = 1, maxInterval = 1, maxSplit = 2))

    @Test
    fun `chrome fingerprint, default fragmentation`() = roundTrip(TlsFingerprint.CHROME_133, FragmentSettings())
}
