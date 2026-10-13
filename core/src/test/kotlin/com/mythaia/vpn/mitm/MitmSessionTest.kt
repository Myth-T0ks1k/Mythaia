package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The session assembly, tested along the seams that do not need a live TLS
 * handshake.
 *
 * # Why not a full end-to-end interception
 *
 * A real [MitmSession.intercept] runs [com.mythaia.vpn.protocol.tls.TlsServer] to
 * completion, whose key schedule reaches `com.mythaia.vpn.NativeBridge` and its
 * `System.loadLibrary("mythaia_native")`. That library is not on the off-device
 * unit `java.library.path`, so a successful handshake cannot be stood up here —
 * the same gate `TlsServerHandshakeTest` documents. The happy-path interception
 * therefore belongs in the `androidTest` set.
 *
 * What is exercised here, all without the native loader:
 *
 *  - the h2/ALPN policy decision ([MitmSession.upstreamAlpns]) as a pure
 *    function;
 *  - a **client handshake failure** driving [MitmSession.intercept] to close the
 *    client transport and never dial — reached via a ClientHello that offers no
 *    TLS 1.3, an abort path `TlsServer` takes before any key derivation;
 *  - the **dial-and-bridge** half ([MitmSession.bridgeTerminatedClient]) over an
 *    in-memory client leg: a dial failure closes the client, and a successful
 *    dial runs the bridge asking upstream for the one ALPN the policy allows.
 *
 * Every expected value is derived here — the ALPN the policy must produce, the
 * fatal-alert content type from RFC 8446, the request and response the fake legs
 * themselves carry — never read back from the code under test.
 */
class MitmSessionTest {

    private val latin1 = StandardCharsets.ISO_8859_1

    // MARK: - ALPN / h2 policy

    @Test
    fun `the upstream ALPN is always the single http1_1, whatever the client negotiated`() {
        // The client leg only ever negotiates http/1.1 (that is all we offer), and
        // every other value must still fall back to it, because it is the only
        // protocol the HTTP/1.1 bridge can carry on the upstream leg.
        assertEquals(listOf("http/1.1"), MitmSession.upstreamAlpns("http/1.1"))
        assertEquals(listOf("http/1.1"), MitmSession.upstreamAlpns(null))
        assertEquals(listOf("http/1.1"), MitmSession.upstreamAlpns(""))
        assertEquals(listOf("http/1.1"), MitmSession.upstreamAlpns("h2"))
    }

    // MARK: - Handshake failure

    @Test
    fun `a client that cannot do TLS 1_3 is torn down and no upstream is dialed`() = runBlocking {
        val store = MitmRuleStore()
        val authority = store.generateAuthority()

        // A ClientHello that advertises only TLS 1.2: TlsServer aborts with a
        // protocol_version fatal alert before it reaches any native crypto.
        val clientHello = record(clientHello(supportedVersions = listOf(0x0303)))
        val clientTransport = FakeClientTransport()

        var dialCalled = false
        MitmSession.intercept(
            clientTransport = clientTransport,
            bufferedClientHello = clientHello,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet(),
            authority = authority,
            dialUpstream = { _, _, _ ->
                dialCalled = true
                throw AssertionError("dialUpstream must not run after a handshake failure")
            }
        )

        assertFalse("upstream must not be dialed", dialCalled)
        assertTrue("the client transport must be closed", clientTransport.cancelled)
        // TlsServer wrote a fatal alert (content type 0x15) before failing.
        val sent = clientTransport.sent()
        assertTrue("a fatal alert must have been written", sent.isNotEmpty())
        assertEquals("alert content type", 0x15, sent[0].toInt() and 0xFF)
    }

    // MARK: - Dial-and-bridge

    @Test
    fun `a dial failure closes the terminated client leg and runs no bridge`() = runBlocking {
        val client = FakeByteLeg(request("/page"), negotiatedAlpn = "http/1.1")

        var seenAlpn: List<String>? = null
        MitmSession.bridgeTerminatedClient(
            clientLeg = client,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet(),
            dialUpstream = { _, _, alpn ->
                seenAlpn = alpn
                throw RuntimeException("upstream unreachable")
            }
        )

        assertEquals("the dial asks upstream for http/1.1", listOf("http/1.1"), seenAlpn)
        assertTrue("the intercepted client leg must be closed on a dial failure", client.closed)
        // No response ever reached the client — the dial failed before the bridge ran.
        assertEquals(0, client.sent().size)
    }

    @Test
    fun `a successful dial bridges the exchange and asks upstream for http1_1`() = runBlocking {
        val client = FakeByteLeg(request("/page"), negotiatedAlpn = "http/1.1")
        val upstream = FakeByteLeg(response(body = "ok"), negotiatedAlpn = "http/1.1")

        var seenAlpn: List<String>? = null
        MitmSession.bridgeTerminatedClient(
            clientLeg = client,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet(),
            dialUpstream = { _, _, alpn ->
                seenAlpn = alpn
                upstream
            }
        )

        assertEquals("the dial asks upstream for http/1.1", listOf("http/1.1"), seenAlpn)

        // The request reached upstream and the response reached the client.
        val forwarded = Http1Codec().readRequest(FakeByteLeg(upstream.sent()))!!
        assertEquals("GET", forwarded.message.method)
        assertEquals("https://example.com/page", forwarded.message.url)

        val answered = Http1Codec().readResponse(
            FakeByteLeg(client.sent()), requestMethod = "GET", requestUrl = "https://example.com/page"
        )!!
        assertEquals(200, answered.message.status)
        assertEquals("ok", String(answered.message.body, latin1))

        // The bridge closed both legs when it finished.
        assertTrue("the client leg is closed after the exchange", client.closed)
        assertTrue("the upstream leg is closed after the exchange", upstream.closed)
    }

    // MARK: - ALPN dispatch (asserted through the bridge seams, no live handshake)

    @Test
    fun `a negotiated ALPN of h2 routes to the h2 bridge and pre-dials no upstream`() = runBlocking {
        val client = FakeByteLeg(ByteArray(0), negotiatedAlpn = "h2")
        var ranH1 = false
        var ranH2 = false
        var dialCalled = false
        MitmSession.bridgeTerminatedClient(
            clientLeg = client,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet(),
            dialUpstream = { _, _, _ -> dialCalled = true; FakeByteLeg(ByteArray(0)) },
            runH2Bridge = { _ -> ranH2 = true },
            runH1Bridge = { _, _ -> ranH1 = true }
        )
        assertTrue("h2 dispatches to the h2 bridge", ranH2)
        assertFalse("the h1 bridge must not run for an h2 client", ranH1)
        // The h2 bridge dials one leg per stream internally, so the session opens none.
        assertFalse("h2 dispatch must not pre-dial a single upstream leg", dialCalled)
    }

    @Test
    fun `a negotiated ALPN of http1_1 routes to the h1 bridge`() = runBlocking {
        val client = FakeByteLeg(ByteArray(0), negotiatedAlpn = "http/1.1")
        var ranH1 = false
        var ranH2 = false
        MitmSession.bridgeTerminatedClient(
            clientLeg = client,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet(),
            dialUpstream = { _, _, _ -> FakeByteLeg(ByteArray(0)) },
            runH2Bridge = { _ -> ranH2 = true },
            runH1Bridge = { _, _ -> ranH1 = true }
        )
        assertTrue("http/1.1 dispatches to the h1 bridge", ranH1)
        assertFalse("the h2 bridge must not run for an http/1.1 client", ranH2)
    }

    // MARK: - A rewritten origin is dialed through the session's dialer

    @Test
    fun `a transparent rewrite onto another host makes the h1 bridge dial that host through the session's dialer`() = runBlocking {
        val ruleSet = MitmRuleSet(
            name = "test", domainSuffixes = listOf("example.com"),
            rules = listOf(
                MitmRule(
                    HttpPhase.REQUEST,
                    "https://example\\.com/moved",
                    MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://other.example/landed"))
                )
            )
        )
        val client = FakeByteLeg(request("/moved"), negotiatedAlpn = "http/1.1")
        val home = FakeByteLeg(response(body = "home"), negotiatedAlpn = "http/1.1")
        val other = FakeByteLeg(response(body = "landed"), negotiatedAlpn = "http/1.1")
        val dials = ArrayList<String>()

        MitmSession.bridgeTerminatedClient(
            clientLeg = client,
            host = "example.com",
            port = 443,
            ruleSet = ruleSet,
            dialUpstream = { host, port, _ ->
                dials.add("$host:$port")
                if (host == "other.example") other else home
            }
        )

        // The session dials the SNI host up front; the bridge dials the rewritten origin on demand.
        assertEquals(listOf("example.com:443", "other.example:443"), dials)
        val forwarded = Http1Codec().readRequest(FakeByteLeg(other.sent()))!!
        assertEquals("https://other.example/landed", forwarded.message.url)
        assertEquals("nothing went to the SNI host for a request rewritten away from it", 0, home.sent().size)

        val answered = Http1Codec().readResponse(
            FakeByteLeg(client.sent()), requestMethod = "GET", requestUrl = "https://other.example/landed"
        )!!
        assertEquals("landed", String(answered.message.body, latin1))
        assertTrue("the rewritten-origin leg is closed with the connection", other.closed)
        assertTrue(home.closed)
    }

    // MARK: - Leaf cache

    @Test
    fun `the leaf cache is the shared store's for the shared CA and a private one otherwise`() {
        val shared = MitmRuleStore.shared
        val sharedAuthority = shared.generateAuthority()
        try {
            // The production case: the hook reads the CA off the shared store, so every
            // interception must reuse that store's cache (one leaf key, cached leaves).
            assertSame(shared.leafCertificates(), MitmSession.leafCertificatesFor(sharedAuthority))
            assertSame(
                "the same cache again on the next connection",
                MitmSession.leafCertificatesFor(sharedAuthority), MitmSession.leafCertificatesFor(sharedAuthority)
            )
            // A CA the shared store does not hold gets its own cache, never the shared one.
            val foreign = MitmRuleStore().generateAuthority()
            assertNotSame(shared.leafCertificates(), MitmSession.leafCertificatesFor(foreign))
        } finally {
            shared.clearAuthority()
        }
    }

    // MARK: - Rule sets and wire helpers

    private fun ruleSet(): MitmRuleSet =
        MitmRuleSet(name = "test", domainSuffixes = listOf("example.com"), rules = emptyList())

    private fun request(path: String): ByteArray =
        "GET $path HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray(latin1)

    private fun response(body: String): ByteArray {
        val bodyBytes = body.toByteArray(latin1)
        return ("HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain\r\n" +
            "Content-Length: ${bodyBytes.size}\r\n\r\n").toByteArray(latin1) + bodyBytes
    }

    // MARK: - Hand-rolled ClientHello (RFC 8446 §4.1.2), same shape as TlsServerHandshakeTest

    private fun u16(v: Int): ByteArray =
        byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun extension(type: Int, data: ByteArray): ByteArray = u16(type) + u16(data.size) + data

    private fun clientHello(
        supportedVersions: List<Int> = listOf(0x0304),
        cipherSuites: List<Int> = listOf(0x1301),
        signatureAlgorithms: List<Int> = listOf(0x0403),
        alpn: List<String> = emptyList(),
        x25519Key: ByteArray? = ByteArray(32) { 0x33 },
        serverName: String? = "example.com"
    ): ByteArray {
        val extensions = ArrayList<Byte>()

        if (supportedVersions.isNotEmpty()) {
            val list = supportedVersions.flatMap { u16(it).toList() }.toByteArray()
            extensions += extension(0x002B, byteArrayOf(list.size.toByte()) + list).toList()
        }
        if (x25519Key != null) {
            require(x25519Key.size == 32)
            val entry = u16(0x001D) + u16(32) + x25519Key
            extensions += extension(0x0033, u16(entry.size) + entry).toList()
        }
        if (signatureAlgorithms.isNotEmpty()) {
            val list = signatureAlgorithms.flatMap { u16(it).toList() }.toByteArray()
            extensions += extension(0x000D, u16(list.size) + list).toList()
        }
        if (alpn.isNotEmpty()) {
            val list = ArrayList<Byte>()
            for (p in alpn) {
                val bytes = p.toByteArray(Charsets.US_ASCII)
                list += bytes.size.toByte()
                list += bytes.toList()
            }
            extensions += extension(0x0010, u16(list.size) + list.toByteArray()).toList()
        }
        if (serverName != null) {
            val hostBytes = serverName.toByteArray(Charsets.US_ASCII)
            val entry = byteArrayOf(0x00) + u16(hostBytes.size) + hostBytes
            extensions += extension(0x0000, u16(entry.size) + entry).toList()
        }

        val suites = cipherSuites.flatMap { u16(it).toList() }.toByteArray()

        val body = ArrayList<Byte>()
        body += u16(0x0303).toList()               // legacy_version
        body += ByteArray(32) { 0x01 }.toList()    // random
        body += 32.toByte()                        // legacy_session_id length
        body += ByteArray(32) { 0x02 }.toList()    // legacy_session_id
        body += u16(suites.size).toList()
        body += suites.toList()
        body += 1.toByte()                         // compression_methods length
        body += 0x00.toByte()                      // null compression
        body += u16(extensions.size).toList()
        body += extensions

        val bodyBytes = body.toByteArray()
        val header = byteArrayOf(
            0x01,
            ((bodyBytes.size ushr 16) and 0xFF).toByte(),
            ((bodyBytes.size ushr 8) and 0xFF).toByte(),
            (bodyBytes.size and 0xFF).toByte()
        )
        return header + bodyBytes
    }

    /** Wraps a handshake message in a single plaintext TLS record (content type 0x16). */
    private fun record(message: ByteArray): ByteArray =
        byteArrayOf(0x16, 0x03, 0x03) + u16(message.size) + message

    // MARK: - Fakes

    /**
     * A client-facing [Transport] whose [receive] is already drained — the whole
     * ClientHello is handed to the session as the buffered bytes — that records
     * everything written and remembers whether it was force-cancelled.
     */
    private class FakeClientTransport : Transport {
        private val out = ByteArrayOutputStream()
        var cancelled = false
            private set

        override suspend fun send(data: ByteArray) { out.write(data) }
        override fun sendAsync(data: ByteArray) { out.write(data) }
        override suspend fun receive(): ByteArray? = null
        override fun forceCancel() { cancelled = true }

        fun sent(): ByteArray = out.toByteArray()
    }

    /**
     * An in-memory [MitmByteLeg] that replays [initial] once then reports EOF,
     * honours [prependToReceiveBuffer], records everything sent, exposes a
     * settable [negotiatedAlpn], and remembers when it was closed.
     */
    private class FakeByteLeg(
        initial: ByteArray,
        override val negotiatedAlpn: String? = null
    ) : MitmByteLeg {
        private var pending: ByteArray? = initial
        private var prepended: ByteArray = ByteArray(0)
        private val out = ByteArrayOutputStream()
        var closed = false
            private set

        override suspend fun receive(): ByteArray? {
            if (prepended.isNotEmpty()) {
                val buffered = prepended
                prepended = ByteArray(0)
                return buffered
            }
            val next = pending ?: return null
            pending = null
            return next
        }

        override suspend fun send(data: ByteArray) { out.write(data) }

        override fun prependToReceiveBuffer(data: ByteArray) {
            if (data.isEmpty()) return
            prepended = if (prepended.isEmpty()) data.copyOf() else prepended + data
        }

        override fun close() { closed = true }

        fun sent(): ByteArray = out.toByteArray()
    }
}
