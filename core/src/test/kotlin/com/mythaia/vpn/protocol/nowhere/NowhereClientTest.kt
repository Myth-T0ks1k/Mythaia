package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.quic.QuicStream
import com.mythaia.vpn.protocol.tls.TlsServer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The identity's flow-id leasing and the stream wrapper, tested against the
 * invariants the portal relies on rather than against how they are coded.
 *
 * Flow ids name a live flow to the portal, so the rules are not cosmetic: an id
 * is a 32-bit unsigned number, zero is reserved and never a flow, and an id must
 * not name two flows at once. The lease therefore hands out ids that climb, wrap
 * from the largest 32-bit value back to one rather than to the reserved zero, and
 * step over anything still leased. The expectations below are written from those
 * rules — the field width gives [NowhereClient.Identity.MAX_FLOW_ID], the reserved
 * value gives the skip of zero — not from the sequence this code happens to emit.
 *
 * The wrapper has two ways to corrupt a session if it is wrong: the payload a
 * fast portal packed behind READY must reach the caller before any inner read,
 * or the stream desynchronises; and the leased flow id must be returned exactly
 * once however the flow ends, since releasing zero times leaks an id and
 * releasing twice could free an id a later flow now holds.
 */
class NowhereClientTest {

    @After
    fun tearDown() {
        NowhereClient.shutdown()
    }

    // A one-byte-per-id search would take 2^32 leases to wrap, so the counter is
    // driven to the boundary directly. The assertions still come from the spec;
    // reflection only reaches a state that is otherwise billions of leases away.
    private fun setNextFlowId(identity: NowhereClient.Identity, value: Long) {
        val field = NowhereClient.Identity::class.java.getDeclaredField("nextFlowId")
        field.isAccessible = true
        field.setLong(identity, value)
    }

    // MARK: - Identity leasing

    @Test
    fun `the id ceiling is the largest value four bytes can carry`() {
        // 2^32 - 1: the flow id field is 32 bits wide on the wire.
        assertEquals(4294967295L, NowhereClient.Identity.MAX_FLOW_ID)
    }

    @Test
    fun `a fresh identity carries a sixteen byte random session id`() {
        val a = NowhereClient.Identity.fresh()
        val b = NowhereClient.Identity.fresh()
        assertEquals(NowhereProtocol.SESSION_ID_SIZE, a.sessionId.size)
        assertEquals(NowhereProtocol.SESSION_ID_SIZE, b.sessionId.size)
        // Two identities are two clients to the portal, so their ids must differ.
        assertFalse(a.sessionId.contentEquals(b.sessionId))
    }

    @Test
    fun `leases run upward from one and never hand out the reserved zero`() {
        val identity = NowhereClient.Identity.fresh()
        assertEquals(0, identity.leased)

        // The first thousand ids are exactly 1..1000, in order: climbing, unique
        // and never the reserved zero.
        val handed = (1..1000).map { identity.lease().flowId }
        assertEquals((1L..1000L).toList(), handed)
        assertEquals(1000, identity.leased)
        assertFalse(handed.contains(0L))
    }

    @Test
    fun `a released id is not reused while the counter is still climbing`() {
        // Freeing an id does not lower the counter; the next lease keeps going
        // upward, which is what keeps a just-freed id from being re-handed to a
        // flow the portal has not yet finished tearing down.
        val identity = NowhereClient.Identity.fresh()
        val first = identity.lease()
        val second = identity.lease()
        val third = identity.lease()
        assertEquals(listOf(1L, 2L, 3L), listOf(first.flowId, second.flowId, third.flowId))

        second.release()
        assertEquals(2, identity.leased)

        val next = identity.lease()
        assertEquals(4L, next.flowId)
    }

    @Test
    fun `releasing frees the slot and releasing twice is harmless`() {
        val identity = NowhereClient.Identity.fresh()
        val lease = identity.lease()
        assertEquals(1, identity.leased)

        lease.release()
        assertEquals(0, identity.leased)

        // Both the flow's own end and its owner's cancel may release, so a
        // second release must not drive the count negative or throw.
        lease.release()
        assertEquals(0, identity.leased)
    }

    @Test
    fun `outstanding leases with gaps never spuriously exhaust the space`() {
        // The search is bounded by the number of leases plus one, which is
        // enough to find a free id whenever one exists. Scattered releases in the
        // middle of a run must not fool it into reporting the space full.
        val identity = NowhereClient.Identity.fresh()
        val leases = (1..50).map { identity.lease() }
        listOf(10, 20, 30).forEach { leases[it - 1].release() }
        assertEquals(47, identity.leased)

        val next = identity.lease()
        assertEquals(51L, next.flowId)
        assertEquals(48, identity.leased)
    }

    @Test
    fun `the id wraps past the ceiling back to one, not to zero`() {
        val identity = NowhereClient.Identity.fresh()
        setNextFlowId(identity, NowhereClient.Identity.MAX_FLOW_ID)

        val ceiling = identity.lease()
        assertEquals(4294967295L, ceiling.flowId)

        // Zero is reserved, so the wrap lands on one.
        val wrapped = identity.lease()
        assertEquals(1L, wrapped.flowId)
    }

    @Test
    fun `on wrapping, a still-leased id is stepped over`() {
        val identity = NowhereClient.Identity.fresh()
        val one = identity.lease()
        assertEquals(1L, one.flowId)

        setNextFlowId(identity, NowhereClient.Identity.MAX_FLOW_ID)
        val ceiling = identity.lease()
        assertEquals(4294967295L, ceiling.flowId)

        // The counter has wrapped to one, but one is still leased, so the search
        // steps over it to the next free id.
        val next = identity.lease()
        assertEquals(2L, next.flowId)
    }

    @Test
    fun `a counter resting on zero skips to one`() {
        // Zero can only ever be a starting point, never a handed-out id, so a
        // counter that somehow rests on the reserved value still leases one.
        val identity = NowhereClient.Identity.fresh()
        setNextFlowId(identity, 0L)
        assertEquals(1L, identity.lease().flowId)
    }

    // MARK: - The stream wrapper

    /**
     * A scripted inner connection: it hands back the queued reads in order and
     * then end-of-stream, and it counts what the wrapper does to it so the tests
     * can prove the wrapper touched it only when it should.
     */
    private class FakeInner(private val reads: MutableList<ByteArray>) : ProxyConnection() {
        val sent = mutableListOf<ByteArray>()
        var receiveCalls = 0
            private set
        var cancelled = 0
            private set
        var connected = true

        override val isConnected: Boolean get() = connected

        override suspend fun sendRaw(data: ByteArray) {
            sent.add(data)
        }

        override fun sendRawAsync(data: ByteArray) {
            sent.add(data)
        }

        override suspend fun receiveRaw(): ByteArray? {
            receiveCalls++
            return if (reads.isEmpty()) null else reads.removeAt(0)
        }

        override fun cancel() {
            cancelled++
            connected = false
        }
    }

    private fun ascii(text: String) = text.toByteArray(Charsets.US_ASCII)

    @Test
    fun `pending bytes are handed out before the inner stream is touched`() = runBlocking {
        val inner = FakeInner(mutableListOf(ascii("first"), ascii("second")))
        val connection = NowhereStreamConnection(inner, ascii("early")) { }

        // The payload that rode in behind READY comes first, and the inner
        // stream is not read to produce it.
        assertArrayEquals(ascii("early"), connection.receiveRaw())
        assertEquals(0, inner.receiveCalls)

        // Only once the pending bytes are spent does the inner stream get read.
        assertArrayEquals(ascii("first"), connection.receiveRaw())
        assertEquals(1, inner.receiveCalls)
        assertArrayEquals(ascii("second"), connection.receiveRaw())
        assertEquals(2, inner.receiveCalls)
    }

    @Test
    fun `an empty pending buffer reads straight through to the inner stream`() = runBlocking {
        val inner = FakeInner(mutableListOf(ascii("hello")))
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { }

        assertArrayEquals(ascii("hello"), connection.receiveRaw())
        assertEquals(1, inner.receiveCalls)
    }

    @Test
    fun `cancel runs onClosed exactly once and cancels the inner once`() {
        val closes = AtomicInteger(0)
        val inner = FakeInner(mutableListOf())
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { closes.incrementAndGet() }

        connection.cancel()
        assertEquals(1, closes.get())
        assertEquals(1, inner.cancelled)

        // A second cancel is a no-op: the owner and the flow can both get here.
        connection.cancel()
        assertEquals(1, closes.get())
        assertEquals(1, inner.cancelled)
    }

    @Test
    fun `end of stream runs onClosed exactly once`() = runBlocking {
        val closes = AtomicInteger(0)
        val inner = FakeInner(mutableListOf(ascii("payload")))
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { closes.incrementAndGet() }

        assertArrayEquals(ascii("payload"), connection.receiveRaw())
        assertEquals(0, closes.get())

        // The inner stream ends, which must release the flow id exactly once.
        assertNull(connection.receiveRaw())
        assertEquals(1, closes.get())

        // Reading again stays at end-of-stream and does not release a second time.
        assertNull(connection.receiveRaw())
        assertEquals(1, closes.get())
    }

    @Test
    fun `a cancel after end of stream does not run onClosed again`() = runBlocking {
        val closes = AtomicInteger(0)
        val inner = FakeInner(mutableListOf())
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { closes.incrementAndGet() }

        assertNull(connection.receiveRaw())
        assertEquals(1, closes.get())

        // The far side already finished the flow, so the owner's later cancel
        // must not free the id a second time, nor cancel the inner again.
        connection.cancel()
        assertEquals(1, closes.get())
        assertEquals(0, inner.cancelled)
    }

    @Test
    fun `after cancel a read is end of stream and the inner is left alone`() = runBlocking {
        val inner = FakeInner(mutableListOf(ascii("unreadable")))
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { }

        connection.cancel()
        assertNull(connection.receiveRaw())
        assertEquals(0, inner.receiveCalls)
    }

    @Test
    fun `writes reach the inner until close and are dropped after it`() = runBlocking {
        val inner = FakeInner(mutableListOf())
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { }

        connection.sendRaw(ascii("live"))
        assertEquals(1, inner.sent.size)
        assertArrayEquals(ascii("live"), inner.sent[0])

        connection.cancel()
        connection.sendRaw(ascii("dropped"))
        connection.sendRawAsync(ascii("also-dropped"))
        assertEquals(1, inner.sent.size)
    }

    @Test
    fun `isConnected follows the inner stream until the wrapper is closed`() {
        val inner = FakeInner(mutableListOf())
        val connection = NowhereStreamConnection(inner, ByteArray(0)) { }

        assertTrue(connection.isConnected)
        inner.connected = false
        assertFalse(connection.isConnected)
        inner.connected = true
        assertTrue(connection.isConnected)

        connection.cancel()
        assertFalse(connection.isConnected)
    }

    @Test
    fun `the carrier reports TLS 1_3, which QUIC always is`() {
        val connection = NowhereStreamConnection(FakeInner(mutableListOf()), ByteArray(0)) { }
        assertEquals(TlsVersion.TLS13, connection.outerTlsVersion)
    }

    // MARK: - Stream-framed UDP wrapper

    @Test
    fun `UDP over stream frames outgoing packets with a two byte big endian length`() = runBlocking {
        val inner = FakeInner(mutableListOf())
        val udp = NowhereUdpStreamConnection(inner, ByteArray(0)) { }

        udp.sendRaw(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()))
        udp.sendRaw(ByteArray(300) { (it and 0xFF).toByte() })

        assertEquals(2, inner.sent.size)
        assertArrayEquals(
            byteArrayOf(0x00, 0x04, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()),
            inner.sent[0]
        )
        assertEquals(302, inner.sent[1].size)
        // 300 = 0x012C big-endian
        assertEquals(0x01, inner.sent[1][0].toInt() and 0xFF)
        assertEquals(0x2C, inner.sent[1][1].toInt() and 0xFF)
    }

    @Test
    fun `UDP over stream reassembles packets split across pending and chunked reads`() = runBlocking {
        // First packet ("abc", length 3) starts in pending with 1 byte of payload,
        // finishes in the first read chunk along with the first byte of the second
        // packet's length header ("hello", length 5 = 0x0005).
        val pending = byteArrayOf(0x00, 0x03, 'a'.code.toByte())
        val chunk1 = byteArrayOf('b'.code.toByte(), 'c'.code.toByte(), 0x00)
        val chunk2 = byteArrayOf(0x05, 'h'.code.toByte(), 'e'.code.toByte())
        val chunk3 = byteArrayOf('l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte())
        val closes = AtomicInteger(0)
        val inner = FakeInner(mutableListOf(chunk1, chunk2, chunk3))
        val udp = NowhereUdpStreamConnection(inner, pending) { closes.incrementAndGet() }

        assertArrayEquals(ascii("abc"), udp.receiveRaw())
        assertArrayEquals(ascii("hello"), udp.receiveRaw())
        assertNull(udp.receiveRaw())
        assertEquals(1, closes.get())
    }

    @Test
    fun `UDP over stream rejects a truncated trailing packet at EOF`() = runBlocking {
        // Claims 4 bytes (0x0004), delivers 2 before EOF.
        val inner = FakeInner(mutableListOf(byteArrayOf(0x00, 0x04, 0x11, 0x22)))
        val closes = AtomicInteger(0)
        val udp = NowhereUdpStreamConnection(inner, ByteArray(0)) { closes.incrementAndGet() }

        assertThrows(NowhereError.ProtocolViolation::class.java) {
            runBlocking { udp.receiveRaw() }
        }
        assertEquals(1, closes.get())
    }

    // MARK: - TLS 1.3 carrier wire format & asymmetric flows

    private class InMemoryTransportPair {
        private val clientToServer = Channel<ByteArray>(Channel.UNLIMITED)
        private val serverToClient = Channel<ByteArray>(Channel.UNLIMITED)

        val clientSide: Transport = Endpoint(clientToServer, serverToClient)
        val serverSide: Transport = Endpoint(serverToClient, clientToServer)

        private class Endpoint(
            private val tx: Channel<ByteArray>,
            private val rx: Channel<ByteArray>
        ) : Transport {
            override suspend fun send(data: ByteArray) {
                tx.trySend(data.copyOf())
            }

            override fun sendAsync(data: ByteArray) {
                tx.trySend(data.copyOf())
            }

            override suspend fun receive(): ByteArray? = rx.receiveCatching().getOrNull()

            override fun forceCancel() {
                tx.close()
                rx.close()
            }
        }
    }

    private fun independentAuthFrame(
        secretKey: String,
        transportByte: Byte,
        exporter: ByteArray,
        sessionId: ByteArray
    ): ByteArray {
        val salt = MessageDigest.getInstance("SHA-256")
            .digest("nowhere/now/1/auth-root".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val authRoot = mac.doFinal(secretKey.toByteArray(Charsets.UTF_8))

        mac.init(SecretKeySpec(authRoot, "HmacSHA256"))
        val authKey = mac.doFinal("authentication".toByteArray(Charsets.UTF_8) + byteArrayOf(0x01))

        mac.init(SecretKeySpec(authKey, "HmacSHA256"))
        mac.update(byteArrayOf(transportByte))
        mac.update(exporter)
        mac.update(sessionId)
        val tag = mac.doFinal().copyOfRange(0, 16)
        return sessionId + tag
    }

    private val leafCertificates by lazy {
        MitmLeafCertificates(MitmCertificateAuthority.generate())
    }

    @Test
    fun `TLS carrier authenticates with exporter bound TLS_TCP frame and duplex TCP flow header`() = runBlocking {
        val pair = InMemoryTransportPair()
        val config = ProxyConfiguration(
            id = UUID.fromString("00000000-0000-4000-8000-000000000101"),
            name = "nowhere-tls",
            serverAddress = "198.51.100.10",
            serverPort = 443u,
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.NOWHERE,
            password = "portal-shared-secret",
            nowhereUplink = "tcp",
            nowhereDownlink = "tcp",
            tls = TlsConfiguration(
                serverName = "portal.example.com",
                alpn = listOf("h3"),
                allowInsecure = true
            )
        )
        val identity = NowhereClient.Identity.of(config)
        val client = NowhereClient(config).also {
            it.tlsTransportFactory = { pair.clientSide }
        }

        val serverJob = async {
            val server = TlsServer(
                transport = pair.serverSide,
                leafCertificates = leafCertificates,
                supportedAlpns = listOf("h3")
            )
            val record = server.handshake(ByteArray(0))
            val exporter = record.exportKeyingMaterial(
                label = "EXPORTER-Nowhere-Auth".toByteArray(Charsets.US_ASCII),
                context = ByteArray(0),
                length = 32
            )!!
            val bootstrap = record.receive()!!
            // Answer READY with 4 trailing bytes ("pong"), then a second record ("later").
            record.send(byteArrayOf(0x00, 'p'.code.toByte(), 'o'.code.toByte(), 'n'.code.toByte(), 'g'.code.toByte()))
            record.send(ascii("later"))
            val appWrite = record.receive()!!
            Triple(exporter, bootstrap, appWrite)
        }

        val connection = client.connect("example.com", 443, ascii("ping"))
        assertArrayEquals(ascii("pong"), connection.receiveRaw())
        assertArrayEquals(ascii("later"), connection.receiveRaw())
        connection.sendRaw(ascii("after-ready"))

        val (serverExporter, bootstrap, appWrite) = serverJob.await()
        assertArrayEquals(ascii("after-ready"), appWrite)

        // Independently derive the 32-byte auth frame + 24-byte DUPLEX TCP flow request:
        // Auth frame (32B): sessionId(16B) || tag(16B)
        // FlowHeader (5B): flags=0x00 (role=DUPLEX(0), kind=TCP(0), up=TCP(0), down=TCP(0), hop=0), flowId=1 (0x00000001)
        // Target (15B): type=DOMAIN(0x03), len=11, "example.com", port=443 (0x01BB)
        // InitialData (4B): "ping"
        val expectedAuthFrame = independentAuthFrame(
            secretKey = "portal-shared-secret",
            transportByte = 0x01, // TLS_TCP
            exporter = serverExporter,
            sessionId = identity.sessionId
        )
        val expectedFlowRequest = byteArrayOf(
            0x00, 0x00, 0x00, 0x00, 0x01, // flags=0x00, flowId=1
            0x03, 11,
            'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
            'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(), '.'.code.toByte(),
            'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x01, 0xBB.toByte(), // port 443
            'p'.code.toByte(), 'i'.code.toByte(), 'n'.code.toByte(), 'g'.code.toByte()
        )
        assertArrayEquals(expectedAuthFrame + expectedFlowRequest, bootstrap)

        connection.cancel()
        assertEquals(0, identity.leased)
    }

    @Test
    fun `TLS carrier connectUDP frames DUPLEX UDP flow request and length-prefixed datagrams`() = runBlocking {
        val pair = InMemoryTransportPair()
        val config = ProxyConfiguration(
            id = UUID.fromString("00000000-0000-4000-8000-000000000102"),
            name = "nowhere-tls-udp",
            serverAddress = "198.51.100.11",
            serverPort = 443u,
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.NOWHERE,
            password = "udp-tls-secret",
            nowhereUplink = "tcp",
            nowhereDownlink = "tcp",
            tls = TlsConfiguration(
                serverName = "portal.example.com",
                alpn = listOf("h3"),
                allowInsecure = true
            )
        )
        val identity = NowhereClient.Identity.of(config)
        val client = NowhereClient(config).also {
            it.tlsTransportFactory = { pair.clientSide }
        }

        val serverJob = async {
            val server = TlsServer(
                transport = pair.serverSide,
                leafCertificates = leafCertificates,
                supportedAlpns = listOf("h3")
            )
            val record = server.handshake(ByteArray(0))
            val exporter = record.exportKeyingMaterial(
                label = "EXPORTER-Nowhere-Auth".toByteArray(Charsets.US_ASCII),
                context = ByteArray(0),
                length = 32
            )!!
            val bootstrap = record.receive()!!
            // Answer READY with an inline UDP packet of 3 bytes ("dns") in the same record.
            record.send(byteArrayOf(0x00, 0x00, 0x03, 'd'.code.toByte(), 'n'.code.toByte(), 's'.code.toByte()))
            val clientPacket = record.receive()!!
            Triple(exporter, bootstrap, clientPacket)
        }

        val udp = client.connectUDP("198.51.100.7", 5353)
        assertArrayEquals(ascii("dns"), udp.receiveRaw())
        udp.sendRaw(byteArrayOf(0xAA.toByte(), 0xBB.toByte()))

        val (serverExporter, bootstrap, clientPacket) = serverJob.await()
        assertArrayEquals(byteArrayOf(0x00, 0x02, 0xAA.toByte(), 0xBB.toByte()), clientPacket)

        // flags = role=DUPLEX(0) | (kind=UDP(1) << 2) | (up=TCP(0) << 3) | (down=TCP(0) << 4) | (hop=0 << 5) = 0x04
        // Target = IPv4(0x01) + 198.51.100.7 + port 5353 (0x14E9)
        val expectedAuthFrame = independentAuthFrame("udp-tls-secret", 0x01, serverExporter, identity.sessionId)
        val expectedFlowRequest = byteArrayOf(
            0x04, 0x00, 0x00, 0x00, 0x01,
            0x01, 198.toByte(), 51, 100, 7, 0x14, 0xE9.toByte()
        )
        assertArrayEquals(expectedAuthFrame + expectedFlowRequest, bootstrap)

        udp.cancel()
        assertEquals(0, identity.leased)
    }

    // MARK: - QUIC datagram UDP & asymmetric flows

    private class ScriptedQuicStream(
        private val incoming: Channel<ByteArray> = Channel(Channel.UNLIMITED)
    ) : ProxyConnection() {
        val sent = CopyOnWriteArrayList<ByteArray>()
        var cancelledCount = AtomicInteger(0)

        override val isConnected: Boolean get() = cancelledCount.get() == 0

        override suspend fun sendRaw(data: ByteArray) {
            sent.add(data.copyOf())
        }

        override fun sendRawAsync(data: ByteArray) {
            sent.add(data.copyOf())
        }

        override suspend fun receiveRaw(): ByteArray? = incoming.receiveCatching().getOrNull()

        override fun cancel() {
            cancelledCount.incrementAndGet()
            incoming.close()
        }

        fun closeIncoming() {
            incoming.close()
        }

        fun pushIncoming(data: ByteArray) {
            incoming.trySend(data)
        }
    }

    @Test
    fun `QUIC UDP flow sends unfragmented DATA, fragments oversized payloads, reassembles, and emits CLOSE on cancel`() = runBlocking {
        val config = ProxyConfiguration(
            id = UUID.fromString("00000000-0000-4000-8000-000000000103"),
            name = "nowhere-quic-udp",
            serverAddress = "203.0.113.9",
            serverPort = 443u,
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.NOWHERE,
            password = "quic-udp-secret",
            nowhereUplink = "udp",
            nowhereDownlink = "udp",
            tls = TlsConfiguration(serverName = "portal.example.com")
        )
        val identity = NowhereClient.Identity.of(config)
        val settings = NowhereClient.settings(config, identity.sessionId)
        val session = NowhereSession.shared(settings)

        val controlStream = ScriptedQuicStream()
        val openedRequests = CopyOnWriteArrayList<ByteArray>()
        val sentDatagrams = CopyOnWriteArrayList<ByteArray>()
        session.streamOpener = { req ->
            openedRequests.add(req)
            NowhereSession.OpenedFlow(controlStream, ByteArray(0))
        }
        session.datagramSender = { frame -> sentDatagrams.add(frame) }
        // Max datagram size = 23 bytes -> unfragmented DATA fits up to 23 - 5 = 18 bytes;
        // FRAGMENT header is 13 bytes -> max fragment payload = 23 - 13 = 10 bytes.
        session.maxDatagramPayloadProvider = { 23 }

        val client = NowhereClient(config)
        val udp = client.connectUDP("203.0.113.53", 53)
        assertEquals(1, session.flowCount)
        assertEquals(1, identity.leased)

        // 1. Verify the DUPLEX UDP flow request sent on the QUIC control stream:
        // flags = role=DUPLEX(0) | (kind=UDP(1)<<2=0x04) | (up=UDP(1)<<3=0x08) | (down=UDP(1)<<4=0x10) = 0x1C
        // flowId = 1 (0x00000001)
        // target = IPv4(0x01), 203.0.113.53, port=53 (0x0035)
        assertEquals(1, openedRequests.size)
        assertArrayEquals(
            byteArrayOf(
                0x1C, 0x00, 0x00, 0x00, 0x01,
                0x01, 203.toByte(), 0, 113, 53, 0x00, 0x35
            ),
            openedRequests[0]
        )

        // 2. Small packet (4 bytes <= 18 bytes budget) goes out as a single DATA (0x00) datagram:
        udp.sendRaw(byteArrayOf(1, 2, 3, 4))
        assertEquals(1, sentDatagrams.size)
        assertArrayEquals(
            byteArrayOf(
                0x00, // DATA
                0x00, 0x00, 0x00, 0x01, // flowId = 1
                1, 2, 3, 4
            ),
            sentDatagrams[0]
        )

        // 3. 19-byte packet (> 18 bytes budget) splits into two FRAGMENT (0x01) datagrams (10B + 9B) with packetId = 1:
        sentDatagrams.clear()
        val nineteenBytes = ByteArray(19) { (it + 1).toByte() }
        udp.sendRaw(nineteenBytes)
        assertEquals(2, sentDatagrams.size)
        assertArrayEquals(
            byteArrayOf(
                0x01, // FRAGMENT
                0x00, 0x00, 0x00, 0x01, // flowId = 1
                0x00, 0x00, 0x00, 0x01, // packetId = 1
                0x00, // fragmentIndex = 0
                0x02, // fragmentCount = 2
                0x00, 19, // totalLength = 19
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10
            ),
            sentDatagrams[0]
        )
        assertArrayEquals(
            byteArrayOf(
                0x01, // FRAGMENT
                0x00, 0x00, 0x00, 0x01, // flowId = 1
                0x00, 0x00, 0x00, 0x01, // packetId = 1
                0x01, // fragmentIndex = 1
                0x02, // fragmentCount = 2
                0x00, 19, // totalLength = 19
                11, 12, 13, 14, 15, 16, 17, 18, 19
            ),
            sentDatagrams[1]
        )

        // 4. Feed out-of-order incoming FRAGMENT (0x01) datagrams for flowId = 1, packetId = 99, totalLength = 5:
        session.handleDatagram(
            byteArrayOf(
                0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 99, 0x01, 0x02, 0x00, 0x05,
                'l'.code.toByte(), 'd'.code.toByte()
            )
        )
        session.handleDatagram(
            byteArrayOf(
                0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 99, 0x00, 0x02, 0x00, 0x05,
                'w'.code.toByte(), 'o'.code.toByte(), 'r'.code.toByte()
            )
        )
        assertArrayEquals(ascii("world"), udp.receiveRaw())

        // 5. Cancelling the UDP connection emits a 5-byte CLOSE (0x02) control datagram and releases the flow:
        sentDatagrams.clear()
        udp.cancel()
        assertEquals(1, sentDatagrams.size)
        assertArrayEquals(
            byteArrayOf(
                0x02, // CLOSE
                0x00, 0x00, 0x00, 0x01 // flowId = 1
            ),
            sentDatagrams[0]
        )
        assertEquals(1, controlStream.cancelledCount.get())
        assertEquals(0, session.flowCount)
        assertEquals(0, identity.leased)
    }

    @Test
    fun `asymmetric TCP flow opens OPEN on TLS uplink and ATTACH on QUIC downlink sharing flowId`() = runBlocking {
        val pair = InMemoryTransportPair()
        val config = ProxyConfiguration(
            id = UUID.fromString("00000000-0000-4000-8000-000000000104"),
            name = "nowhere-asym-tcp",
            serverAddress = "198.51.100.12",
            serverPort = 443u,
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.NOWHERE,
            password = "asym-secret",
            nowhereUplink = "tcp",
            nowhereDownlink = "udp",
            tls = TlsConfiguration(
                serverName = "portal.example.com",
                alpn = listOf("h3"),
                allowInsecure = true
            )
        )
        val identity = NowhereClient.Identity.of(config)
        val settings = NowhereClient.settings(config, identity.sessionId)
        val session = NowhereSession.shared(settings)

        val quicDownStream = ScriptedQuicStream()
        quicDownStream.pushIncoming(ascii("from-quic-downlink"))
        val attachRequestDeferred = CompletableDeferred<ByteArray>()
        session.streamOpener = { req ->
            attachRequestDeferred.complete(req)
            NowhereSession.OpenedFlow(quicDownStream, ascii("early-down"))
        }

        val tlsServerJob = async {
            val server = TlsServer(
                transport = pair.serverSide,
                leafCertificates = leafCertificates,
                supportedAlpns = listOf("h3")
            )
            val record = server.handshake(ByteArray(0))
            val openBootstrap = record.receive()!!
            // Uplink READY carries no downlink payload.
            record.send(byteArrayOf(0x00))
            val uplinkData = record.receive()!!
            Pair(openBootstrap, uplinkData)
        }

        val client = NowhereClient(config).also {
            it.tlsTransportFactory = { pair.clientSide }
        }
        val conn = client.connect("example.com", 8080, ascii("init"))

        // Downlink reads pending from QUIC ATTACH stream first, then stream chunks:
        assertArrayEquals(ascii("early-down"), conn.receiveRaw())
        assertArrayEquals(ascii("from-quic-downlink"), conn.receiveRaw())

        // Uplink writes go to the TLS OPEN stream:
        conn.sendRaw(ascii("to-tls-uplink"))

        val (openBootstrap, uplinkData) = tlsServerJob.await()
        val attachRequest = attachRequestDeferred.await()

        assertArrayEquals(ascii("to-tls-uplink"), uplinkData)

        // Verify OPEN request (after 32-byte auth frame):
        // flags = role=OPEN(1) | (kind=TCP(0)<<2) | (up=TCP(0)<<3) | (down=UDP(1)<<4=0x10) = 0x11
        val openFlowBytes = openBootstrap.copyOfRange(32, openBootstrap.size)
        assertArrayEquals(
            byteArrayOf(
                0x11, 0x00, 0x00, 0x00, 0x01,
                0x03, 11,
                'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
                'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(), '.'.code.toByte(),
                'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
                0x1F, 0x90.toByte(), // port 8080
                'i'.code.toByte(), 'n'.code.toByte(), 'i'.code.toByte(), 't'.code.toByte()
            ),
            openFlowBytes
        )

        // Verify ATTACH request on QUIC:
        // flags = role=ATTACH(2) | (kind=TCP(0)<<2) | (up=TCP(0)<<3) | (down=UDP(1)<<4=0x10) = 0x12, flowId=1
        assertArrayEquals(
            byteArrayOf(0x12, 0x00, 0x00, 0x00, 0x01),
            attachRequest
        )

        conn.cancel()
        assertEquals(0, session.flowCount)
        assertEquals(0, identity.leased)
    }
}

