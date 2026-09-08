package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

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
}
