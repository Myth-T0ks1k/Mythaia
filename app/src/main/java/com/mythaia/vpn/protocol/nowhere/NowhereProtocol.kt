package com.mythaia.vpn.protocol.nowhere

import java.io.IOException
import java.net.IDN
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The Nowhere wire format.
 *
 * Nowhere reaches a portal over either TLS-on-TCP or QUIC and then speaks one
 * small binary language over both. A flow — a single proxied connection — is
 * described by a five-byte header naming a role, a 32-bit flow id, whether the
 * payload is TCP or UDP, and which carrier each direction rides on. That last
 * part is what makes the protocol unusual: the uplink and the downlink may use
 * different transports, so a flow can be opened on one carrier and attached to
 * on the other, with the flow id being the only thing tying the two halves
 * together.
 *
 * Two mechanisms in here deserve their own attention.
 *
 * The first is the portal hop counter, packed into the top three bits of the
 * flags byte. A portal that forwards a flow to another portal increments it,
 * and a flow arriving with more than [MAX_PORTAL_HOPS] hops is refused. That
 * is what bounds a chain of portals and stops a mis-configured cycle from
 * carrying traffic around forever; the counter has to live in the header
 * rather than in either endpoint because no single portal can see the chain.
 *
 * The second is UDP fragmentation. Proxied UDP rides in QUIC datagrams, which
 * the transport will not split, so a packet larger than the path allows is cut
 * up by this layer: each piece carries the packet id, its index, how many
 * pieces there are and the length of the whole packet, and the far side puts
 * them back together (see [NowhereFragmentReassembler]).
 *
 * Everything here is a pure function of bytes. Opening the carrier, leasing
 * flow ids, multiplexing and session lifetime live elsewhere; keeping the
 * framing separate is what lets it be checked against the protocol itself
 * rather than against this encoder.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object NowhereProtocol {

    // Constants of the format. Every one of these is part of the contract with
    // the portal and none of them may drift.

    /** The QUIC application error code for a clean close. */
    const val CLOSE_ERR_CODE_OK = 0x100L

    /** The ALPN a portal offers, on both TLS and QUIC. */
    const val DEFAULT_ALPN = "now/1"

    /** sessionId(16) then the leading 16 bytes of the authentication tag. */
    const val AUTH_FRAME_SIZE = 32

    /** flags(1) then flowId(4). */
    const val FLOW_HEADER_SIZE = 5

    /** A flow result is a single status byte. */
    const val FLOW_RESULT_SIZE = 1

    /** type(1) then flowId(4), on a DATA or CLOSE datagram. */
    const val UDP_HEADER_SIZE = 5

    /** type(1) flowId(4) packetId(4) index(1) count(1) totalLength(2). */
    const val UDP_FRAGMENT_HEADER_SIZE = 13

    /** A UDP packet's length is announced in 16 bits, so this is the ceiling. */
    const val MAX_UDP_PACKET_SIZE = 65535

    /** A DNS name in wire form, per RFC 1035 §2.3.4. */
    const val MAX_DOMAIN_LENGTH = 253

    /** Three bits of hop counter, so a flow may cross at most seven portals. */
    const val MAX_PORTAL_HOPS = 7

    /** A session id is 128 bits of randomness chosen once per transport. */
    const val SESSION_ID_SIZE = 16

    /** Both the derived authentication key and the TLS exporter are 256 bits. */
    const val AUTH_KEY_SIZE = 32

    // Key derivation. The shape is an HKDF whose salt is the hash of a
    // version-qualified label, so a key configured for one protocol version
    // cannot authenticate against another.

    /** Hashed to make the extraction salt. */
    const val AUTH_ROOT_LABEL = "nowhere/now/1/auth-root"

    /** The expansion info, followed on the wire by a single counter byte. */
    const val AUTH_INFO_LABEL = "authentication"

    /** The RFC 8446 §7.5 exporter label both carriers bind the session to. */
    const val EXPORTER_LABEL = "EXPORTER-Nowhere-Auth"

    /** How many bytes of exported keying material the auth frame covers. */
    const val EXPORTER_LENGTH = 32

    // Address type bytes, which follow SOCKS5's numbering (RFC 1928 §5).
    private const val ATYP_IPV4 = 0x01
    private const val ATYP_DOMAIN = 0x03
    private const val ATYP_IPV6 = 0x04

    /**
     * Which carrier a direction of a flow rides on.
     *
     * This is deliberately not the same idea as [FlowKind]: a TCP flow can be
     * carried over a QUIC uplink, and a UDP flow can be carried over a TLS
     * stream.
     */
    enum class NowhereNetwork { TCP, UDP }

    /** Which carrier the auth frame is binding, mixed into the tag. */
    enum class AuthTransport(val value: Int) {
        TLS_TCP(0x01),
        QUIC(0x02)
    }

    /**
     * What this end of the flow is doing.
     *
     * A [DUPLEX] flow carries both directions, and is the ordinary case when
     * uplink and downlink share a carrier. When they do not, the client sends
     * an [OPEN] on the uplink and an [ATTACH] on the downlink, and the portal
     * joins them by flow id.
     */
    enum class FlowRole(val value: Int) {
        DUPLEX(0),
        OPEN(1),
        ATTACH(2);

        internal companion object {
            fun from(value: Int): FlowRole? = entries.firstOrNull { it.value == value }
        }
    }

    /** What the flow proxies, as opposed to what carries it. */
    enum class FlowKind(val value: Int) {
        TCP(0),
        UDP(1)
    }

    /** Why a portal refused a flow. Zero is not a code; it means accepted. */
    enum class FlowRejectCode(val value: Int, val description: String) {
        INVALID_REQUEST(1, "invalid request"),
        METADATA_CONFLICT(2, "metadata conflict"),
        PAIR_TIMEOUT(3, "pair timeout"),
        FLOW_LIMIT(4, "flow limit"),
        DIAL_FAILED(5, "dial failed"),
        SESSION_REPLACED(6, "session replaced"),
        INTERNAL_ERROR(7, "internal error");

        internal companion object {
            fun from(value: Int): FlowRejectCode? = entries.firstOrNull { it.value == value }
        }
    }

    /** The single byte a portal answers a flow request with. */
    sealed class FlowResult {
        /** The flow is up and the next byte on the carrier is payload. */
        data object Ready : FlowResult()

        data class Reject(val code: FlowRejectCode) : FlowResult()
    }

    /**
     * The five-byte preamble of every flow.
     *
     * [hops] is the portal hop counter. A client always emits zero; the field
     * is here because a portal forwarding this flow onward rewrites the header
     * with the count raised by one, and every hop revalidates the budget.
     *
     * [flowId] is unsigned on the wire and is carried as a [Long] so that an id
     * past 2^31 does not arrive as a negative number that then sorts and
     * compares wrongly.
     */
    data class FlowHeader(
        val role: FlowRole,
        val flowId: Long,
        val kind: FlowKind,
        val uplink: NowhereNetwork,
        val downlink: NowhereNetwork,
        val hops: Int = 0
    ) {
        /**
         * Whether a destination follows this header.
         *
         * An attach names no destination: it is joining a flow whose target
         * the portal already learned from the matching open.
         */
        val carriesTarget: Boolean get() = role != FlowRole.ATTACH

        /**
         * Rejects a header no portal would honour.
         *
         * [carrier] is the transport this header actually arrived on or is
         * about to be written to. Checking it catches the case where the two
         * halves of an asymmetric flow were sent down the wrong carriers,
         * which otherwise shows up much later as a flow that never pairs.
         */
        fun validate(carrier: NowhereNetwork? = null) {
            if (hops > MAX_PORTAL_HOPS) {
                throw NowhereError.InvalidFlow("Hop budget exceeds $MAX_PORTAL_HOPS")
            }
            if (hops < 0) throw NowhereError.InvalidFlow("Negative hop count")
            if (flowId !in 0..0xFFFFFFFFL) {
                throw NowhereError.InvalidFlow("Flow ID out of range")
            }
            if (flowId == 0L) throw NowhereError.InvalidFlow("Invalid zero flow ID")
            // A duplex flow rides one carrier in both directions, so a header
            // claiming otherwise is describing something it cannot be.
            if (role == FlowRole.DUPLEX && uplink != downlink) {
                throw NowhereError.InvalidFlow("Duplex carrier mismatch")
            }
            if (carrier != null) {
                val expected = if (role == FlowRole.ATTACH) downlink else uplink
                if (carrier != expected) throw NowhereError.InvalidFlow("Flow carrier mismatch")
            }
        }

        /**
         * The header a portal writes when it passes this flow to the next one.
         *
         * Throws once the budget is spent, which is the whole point of the
         * counter: the refusal happens at the portal that would have made the
         * eighth hop rather than somewhere downstream.
         */
        fun forwarded(): FlowHeader = copy(hops = hops + 1).also { it.validate() }
    }

    /**
     * Where a flow is going, in the address form Nowhere borrows from SOCKS5.
     *
     * A literal address is sent as bytes rather than as text so that the
     * portal does no parsing and no resolution; a name is sent lowercased and
     * in its ASCII (punycode) form so that two spellings of the same host
     * cannot produce two different cache or metadata entries at the portal.
     */
    sealed class Target {
        abstract val port: Int

        /** How many bytes [encode] will produce. */
        abstract val encodedLength: Int

        abstract fun encode(): ByteArray

        class Ipv4(val address: ByteArray, override val port: Int) : Target() {
            init {
                require(address.size == 4) { "IPv4 address must be 4 bytes" }
                require(port in 1..65535) { "port out of range: $port" }
            }

            override val encodedLength: Int get() = 1 + 4 + 2

            override fun encode(): ByteArray {
                val out = ByteArray(encodedLength)
                out[0] = ATYP_IPV4.toByte()
                address.copyInto(out, 1)
                out.putUInt16(5, port)
                return out
            }

            override fun equals(other: Any?): Boolean =
                this === other ||
                    (other is Ipv4 && port == other.port && address.contentEquals(other.address))

            override fun hashCode(): Int = 31 * address.contentHashCode() + port

            override fun toString(): String =
                "Ipv4(${address.joinToString(".") { (it.toInt() and 0xFF).toString() }}:$port)"
        }

        class Ipv6(val address: ByteArray, override val port: Int) : Target() {
            init {
                require(address.size == 16) { "IPv6 address must be 16 bytes" }
                require(port in 1..65535) { "port out of range: $port" }
            }

            override val encodedLength: Int get() = 1 + 16 + 2

            override fun encode(): ByteArray {
                val out = ByteArray(encodedLength)
                out[0] = ATYP_IPV6.toByte()
                address.copyInto(out, 1)
                out.putUInt16(17, port)
                return out
            }

            override fun equals(other: Any?): Boolean =
                this === other ||
                    (other is Ipv6 && port == other.port && address.contentEquals(other.address))

            override fun hashCode(): Int = 31 * address.contentHashCode() + port

            override fun toString(): String =
                "Ipv6(${address.joinToString("") { "%02x".format(it) }}:$port)"
        }

        /** [host] is already ASCII, lowercased and validated. */
        data class Domain(val host: String, override val port: Int) : Target() {
            init {
                require(port in 1..65535) { "port out of range: $port" }
            }

            override val encodedLength: Int get() = 1 + 1 + host.length + 2

            override fun encode(): ByteArray {
                val name = host.toByteArray(Charsets.UTF_8)
                val out = ByteArray(1 + 1 + name.size + 2)
                out[0] = ATYP_DOMAIN.toByte()
                out[1] = name.size.toByte()
                name.copyInto(out, 2)
                out.putUInt16(2 + name.size, port)
                return out
            }
        }

        companion object {
            /**
             * Classifies a host the way the protocol requires.
             *
             * The order matters: an IPv4 literal is recognised first, then
             * IPv6, and only a host that is neither becomes a name. A bracketed
             * IPv6 literal is unwrapped first because that is how a host
             * arrives out of a URL (RFC 3986 §3.2.2).
             */
            fun of(host: String, port: Int): Target {
                if (port == 0) throw NowhereError.InvalidFlow("Invalid zero target port")
                if (port !in 1..65535) throw NowhereError.InvalidFlow("Target port out of range")

                val unwrapped =
                    if (host.length >= 2 && host.startsWith("[") && host.endsWith("]")) {
                        host.substring(1, host.length - 1)
                    } else {
                        host
                    }

                parseIpv4Literal(unwrapped)?.let { return Ipv4(it, port) }
                parseIpv6Literal(unwrapped)?.let { return Ipv6(it, port) }

                val wireHost = asciiWireHost(unwrapped)
                validateDomain(wireHost)
                return Domain(wireHost, port)
            }
        }
    }

    /** A decoded destination and how many bytes of the buffer it occupied. */
    data class DecodedTarget(val target: Target, val consumed: Int)

    /** Which of the three datagram shapes this is. */
    enum class UdpType(val value: Int) {
        DATA(0),
        FRAGMENT(1),
        CLOSE(2);

        internal companion object {
            fun from(value: Int): UdpType? = entries.firstOrNull { it.value == value }
        }
    }

    /** The type and flow id every datagram starts with. */
    data class UdpEnvelope(val type: UdpType, val flowId: Long)

    /**
     * One decoded datagram.
     *
     * The fragment fields are zero on a [UdpType.DATA] or [UdpType.CLOSE]
     * message, which carry no fragmentation header at all; on a DATA message
     * [totalLength] is filled in with the payload's own length so that a
     * caller can treat complete and reassembled packets alike.
     */
    class UdpMessage(
        val type: UdpType,
        val flowId: Long,
        val packetId: Long,
        val fragmentId: Int,
        val fragmentCount: Int,
        val totalLength: Int,
        val payload: ByteArray
    ) {
        override fun equals(other: Any?): Boolean =
            this === other || (
                other is UdpMessage &&
                    type == other.type &&
                    flowId == other.flowId &&
                    packetId == other.packetId &&
                    fragmentId == other.fragmentId &&
                    fragmentCount == other.fragmentCount &&
                    totalLength == other.totalLength &&
                    payload.contentEquals(other.payload)
                )

        override fun hashCode(): Int {
            var result = type.hashCode()
            result = 31 * result + flowId.hashCode()
            result = 31 * result + packetId.hashCode()
            result = 31 * result + fragmentId
            result = 31 * result + fragmentCount
            result = 31 * result + totalLength
            result = 31 * result + payload.contentHashCode()
            return result
        }

        override fun toString(): String =
            "UdpMessage($type flow=$flowId packet=$packetId " +
                "frag=$fragmentId/$fragmentCount total=$totalLength payload=${payload.size})"
    }

    // Authentication.

    /**
     * Turns the configured shared secret into the 32-byte key that signs auth
     * frames.
     *
     * Extraction is salted with the hash of a label that names the protocol
     * version, so the same passphrase configured against a future version
     * yields an unrelated key rather than a cross-version forgery. The 0x01
     * appended to the info string is HKDF's block counter for the single
     * output block.
     */
    fun deriveAuthKey(sharedKey: String): ByteArray {
        val keyBytes = sharedKey.toByteArray(Charsets.UTF_8)
        if (keyBytes.isEmpty()) {
            throw NowhereError.ProtocolViolation("Missing Nowhere shared key")
        }
        if (keyBytes.size > 255) {
            throw NowhereError.ProtocolViolation("Nowhere shared key exceeds 255 bytes")
        }
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(AUTH_ROOT_LABEL.toByteArray(Charsets.UTF_8))
        val authRoot = hmacSha256(salt, keyBytes)
        val info = AUTH_INFO_LABEL.toByteArray(Charsets.UTF_8) + byteArrayOf(0x01)
        return hmacSha256(authRoot, info)
    }

    /**
     * The first 32 bytes a client writes on a fresh carrier.
     *
     * The tag covers the carrier kind, the TLS or QUIC exporter and the
     * session id, so a frame captured from a TLS connection cannot be replayed
     * onto a QUIC one or onto a different handshake — the exporter is unique
     * per handshake and is never itself transmitted. Only half the tag goes on
     * the wire; 128 bits is ample against forgery and it keeps the frame at a
     * round [AUTH_FRAME_SIZE].
     */
    fun makeAuthFrame(
        authKey: ByteArray,
        transport: AuthTransport,
        exporter: ByteArray,
        sessionId: ByteArray
    ): ByteArray {
        if (authKey.size != AUTH_KEY_SIZE ||
            exporter.size != EXPORTER_LENGTH ||
            sessionId.size != SESSION_ID_SIZE
        ) {
            throw NowhereError.AuthenticationRejected("Invalid authentication material")
        }
        val message = ByteArray(1 + EXPORTER_LENGTH + SESSION_ID_SIZE)
        message[0] = transport.value.toByte()
        exporter.copyInto(message, 1)
        sessionId.copyInto(message, 1 + EXPORTER_LENGTH)

        val tag = hmacSha256(authKey, message)
        val frame = ByteArray(AUTH_FRAME_SIZE)
        sessionId.copyInto(frame, 0)
        tag.copyInto(frame, SESSION_ID_SIZE, 0, AUTH_FRAME_SIZE - SESSION_ID_SIZE)
        return frame
    }

    private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    // Flow framing.

    /**
     * The flags byte then the flow id, big-endian.
     *
     * The flags byte is packed as role in bits 0-1, kind in bit 2, uplink
     * carrier in bit 3, downlink carrier in bit 4, and the portal hop count in
     * bits 5-7.
     */
    fun encodeFlowHeader(header: FlowHeader): ByteArray {
        header.validate()
        var flags = header.role.value or (header.kind.value shl 2)
        if (header.uplink == NowhereNetwork.UDP) flags = flags or (1 shl 3)
        if (header.downlink == NowhereNetwork.UDP) flags = flags or (1 shl 4)
        flags = flags or (header.hops shl 5)

        val out = ByteArray(FLOW_HEADER_SIZE)
        out[0] = flags.toByte()
        out.putUInt32(1, header.flowId)
        return out
    }

    /**
     * Reads a flow header, or null when [data] is not exactly one.
     *
     * The size is required to match rather than merely to suffice: a caller
     * always knows the header is five bytes, and accepting a longer buffer
     * would let a framing mistake elsewhere pass unnoticed.
     */
    fun decodeFlowHeader(data: ByteArray): FlowHeader? {
        if (data.size != FLOW_HEADER_SIZE) return null
        val flags = data[0].toInt() and 0xFF
        val role = FlowRole.from(flags and 0x03) ?: return null
        val header = FlowHeader(
            role = role,
            flowId = data.uint32(1),
            kind = if (flags and 0x04 == 0) FlowKind.TCP else FlowKind.UDP,
            uplink = if (flags and 0x08 == 0) NowhereNetwork.TCP else NowhereNetwork.UDP,
            downlink = if (flags and 0x10 == 0) NowhereNetwork.TCP else NowhereNetwork.UDP,
            hops = flags ushr 5
        )
        return try {
            header.validate()
            header
        } catch (_: NowhereError) {
            null
        }
    }

    /**
     * A whole flow request: header, destination if the role carries one, and
     * any payload the caller already has.
     *
     * Sending the first bytes of the connection in the same write as the
     * request is what keeps a proxied TCP connection to one round trip; the
     * portal is expected to hold them until the dial succeeds.
     */
    fun encodeFlowRequest(
        header: FlowHeader,
        target: Target?,
        initialData: ByteArray? = null
    ): ByteArray {
        header.validate()
        if (header.carriesTarget != (target != null)) {
            throw NowhereError.InvalidFlow("Flow target does not match role")
        }
        val initial = initialData ?: ByteArray(0)
        val out = ByteArray(FLOW_HEADER_SIZE + (target?.encodedLength ?: 0) + initial.size)
        encodeFlowHeader(header).copyInto(out)
        var at = FLOW_HEADER_SIZE
        if (target != null) {
            target.encode().copyInto(out, at)
            at += target.encodedLength
        }
        initial.copyInto(out, at)
        return out
    }

    /**
     * Reads back a destination in the form [Target.encode] writes.
     *
     * The reference client only ever encodes, since a portal is what reads
     * these; this is the exact inverse, and it applies the same name rules to
     * incoming bytes as [Target.of] applies to outgoing ones so that a peer
     * cannot smuggle a name the encoder would have refused.
     *
     * Returns null on a truncated or malformed buffer rather than throwing,
     * because a caller reading a stream cannot tell the two apart until it has
     * the whole address.
     */
    fun decodeTarget(bytes: ByteArray, offset: Int = 0): DecodedTarget? {
        if (offset < 0 || offset >= bytes.size) return null
        return when (bytes[offset].toInt() and 0xFF) {
            ATYP_IPV4 -> {
                if (offset + 7 > bytes.size) return null
                val port = bytes.uint16(offset + 5)
                if (port == 0) return null
                DecodedTarget(Target.Ipv4(bytes.copyOfRange(offset + 1, offset + 5), port), 7)
            }

            ATYP_IPV6 -> {
                if (offset + 19 > bytes.size) return null
                val port = bytes.uint16(offset + 17)
                if (port == 0) return null
                DecodedTarget(Target.Ipv6(bytes.copyOfRange(offset + 1, offset + 17), port), 19)
            }

            ATYP_DOMAIN -> {
                if (offset + 2 > bytes.size) return null
                val length = bytes[offset + 1].toInt() and 0xFF
                if (length == 0 || offset + 4 + length > bytes.size) return null
                val host = String(bytes, offset + 2, length, Charsets.US_ASCII)
                if (host.toByteArray(Charsets.US_ASCII).size != length) return null
                try {
                    validateDomain(host)
                } catch (_: NowhereError) {
                    return null
                }
                val port = bytes.uint16(offset + 2 + length)
                if (port == 0) return null
                DecodedTarget(Target.Domain(host, port), 4 + length)
            }

            else -> null
        }
    }

    /** The single byte a portal answers with. */
    fun encodeFlowResult(result: FlowResult): ByteArray = when (result) {
        is FlowResult.Ready -> byteArrayOf(0)
        is FlowResult.Reject -> byteArrayOf(result.code.value.toByte())
    }

    /** Reads that byte, or null when it is absent or names no known code. */
    fun decodeFlowResult(data: ByteArray, offset: Int = 0): FlowResult? {
        if (offset < 0 || offset >= data.size) return null
        val value = data[offset].toInt() and 0xFF
        if (value == 0) return FlowResult.Ready
        val code = FlowRejectCode.from(value) ?: return null
        return FlowResult.Reject(code)
    }

    // Datagram framing.

    /**
     * A CLOSE datagram, which tells the far side a UDP flow is finished.
     *
     * The type is a parameter only so the caller reads at the call site as the
     * frame it is building; nothing else may be sent through here, because
     * DATA and FRAGMENT both need a payload.
     */
    fun encodeUdpControl(type: UdpType, flowId: Long): ByteArray {
        if (type != UdpType.CLOSE || flowId == 0L || flowId !in 0..0xFFFFFFFFL) {
            throw NowhereError.InvalidFlow("Invalid UDP CLOSE frame")
        }
        val out = ByteArray(UDP_HEADER_SIZE)
        out[0] = type.value.toByte()
        out.putUInt32(1, flowId)
        return out
    }

    /**
     * Cuts one UDP packet into datagrams that each fit [maxDatagramSize].
     *
     * A packet that fits goes as a single DATA frame with no fragmentation
     * header at all, which is both smaller and cheaper for the far side; only
     * when it does not fit does the eight-byte-larger FRAGMENT header appear.
     * Because that header is larger, a payload just past the DATA limit is
     * always cut into at least two pieces, never one.
     *
     * A fragmented packet needs a non-zero packet id: it is the only thing
     * distinguishing this packet's pieces from the next packet's on the same
     * flow, and the reassembler keys on it.
     */
    fun encodeUdpDataFragments(
        flowId: Long,
        packetId: Long,
        payload: ByteArray,
        maxDatagramSize: Int
    ): List<ByteArray> {
        if (flowId == 0L || flowId !in 0..0xFFFFFFFFL) {
            throw NowhereError.InvalidFlow("Invalid flow ID")
        }
        if (payload.size > MAX_UDP_PACKET_SIZE) throw NowhereError.PacketTooLarge(payload.size)
        if (maxDatagramSize < UDP_HEADER_SIZE) {
            throw NowhereError.DatagramTooLarge(maxDatagramSize, UDP_HEADER_SIZE)
        }

        if (payload.size <= maxDatagramSize - UDP_HEADER_SIZE) {
            val frame = ByteArray(UDP_HEADER_SIZE + payload.size)
            frame[0] = UdpType.DATA.value.toByte()
            frame.putUInt32(1, flowId)
            payload.copyInto(frame, UDP_HEADER_SIZE)
            return listOf(frame)
        }

        if (packetId == 0L || packetId !in 0..0xFFFFFFFFL ||
            maxDatagramSize <= UDP_FRAGMENT_HEADER_SIZE
        ) {
            throw NowhereError.DatagramTooLarge(maxDatagramSize, UDP_FRAGMENT_HEADER_SIZE)
        }

        val capacity = maxDatagramSize - UDP_FRAGMENT_HEADER_SIZE
        val count = (payload.size + capacity - 1) / capacity
        // The index and the count are one byte each, and a single fragment is
        // never correct here because the unfragmented form would have fitted.
        if (count !in 2..255) throw NowhereError.PacketTooLarge(payload.size)

        return (0 until count).map { index ->
            val start = index * capacity
            val end = minOf(payload.size, start + capacity)
            val frame = ByteArray(UDP_FRAGMENT_HEADER_SIZE + end - start)
            frame[0] = UdpType.FRAGMENT.value.toByte()
            frame.putUInt32(1, flowId)
            frame.putUInt32(5, packetId)
            frame[9] = index.toByte()
            frame[10] = count.toByte()
            frame.putUInt16(11, payload.size)
            payload.copyInto(frame, UDP_FRAGMENT_HEADER_SIZE, start, end)
            frame
        }
    }

    /**
     * The type and flow id at the head of any datagram, or null when the head
     * is not one.
     *
     * The reserved bits above the two type bits must be clear. Refusing a
     * datagram that sets them keeps the field available for a later version:
     * an old client drops such a frame rather than silently treating it as a
     * type it recognises.
     */
    fun decodeUdpEnvelope(data: ByteArray): UdpEnvelope? {
        if (data.size < UDP_HEADER_SIZE) return null
        val flags = data[0].toInt() and 0xFF
        if (flags and 0xFC != 0) return null
        val type = UdpType.from(flags and 0x03) ?: return null
        val flowId = data.uint32(1)
        if (flowId == 0L) return null
        return UdpEnvelope(type, flowId)
    }

    /**
     * Parses a whole datagram, or null when it is not a well-formed one.
     *
     * The fragment checks are the interesting part, and each one closes a way
     * of making the far side hold memory it will never be able to use: a
     * count below two is not a fragmented packet, an index at or past the
     * count names a piece that cannot exist, an empty payload is a free
     * reassembly slot, and a piece longer than the whole packet minus one byte
     * for each of its siblings can never be completed.
     */
    fun decodeUdpDatagram(data: ByteArray): UdpMessage? {
        val envelope = decodeUdpEnvelope(data) ?: return null
        return when (envelope.type) {
            UdpType.DATA -> {
                val payload = data.copyOfRange(UDP_HEADER_SIZE, data.size)
                if (payload.size > MAX_UDP_PACKET_SIZE) return null
                UdpMessage(
                    type = UdpType.DATA,
                    flowId = envelope.flowId,
                    packetId = 0,
                    fragmentId = 0,
                    fragmentCount = 0,
                    totalLength = payload.size,
                    payload = payload
                )
            }

            UdpType.FRAGMENT -> {
                if (data.size <= UDP_FRAGMENT_HEADER_SIZE) return null
                val packetId = data.uint32(5)
                val index = data[9].toInt() and 0xFF
                val count = data[10].toInt() and 0xFF
                val total = data.uint16(11)
                val payload = data.copyOfRange(UDP_FRAGMENT_HEADER_SIZE, data.size)
                if (packetId == 0L) return null
                if (count < 2 || index >= count) return null
                if (total == 0 || total < count) return null
                if (payload.isEmpty()) return null
                if (payload.size + count - 1 > total) return null
                UdpMessage(
                    type = UdpType.FRAGMENT,
                    flowId = envelope.flowId,
                    packetId = packetId,
                    fragmentId = index,
                    fragmentCount = count,
                    totalLength = total,
                    payload = payload
                )
            }

            UdpType.CLOSE -> {
                if (data.size != UDP_HEADER_SIZE) return null
                UdpMessage(
                    type = UdpType.CLOSE,
                    flowId = envelope.flowId,
                    packetId = 0,
                    fragmentId = 0,
                    fragmentCount = 0,
                    totalLength = 0,
                    payload = ByteArray(0)
                )
            }
        }
    }

    // UDP carried on a stream.

    /** A packet read out of a stream, and how much of the buffer it used. */
    data class UdpStreamPacket(val payload: ByteArray, val consumed: Int) {
        override fun equals(other: Any?): Boolean =
            this === other || (
                other is UdpStreamPacket &&
                    consumed == other.consumed &&
                    payload.contentEquals(other.payload)
                )

        override fun hashCode(): Int = 31 * payload.contentHashCode() + consumed
    }

    /**
     * A UDP packet framed for a stream carrier: a 16-bit length then the
     * bytes.
     *
     * A stream has no message boundaries of its own, so the length is what
     * restores them; the datagram form needs no such prefix because QUIC
     * delivers a datagram whole or not at all.
     */
    fun encodeUdpStreamPacket(payload: ByteArray): ByteArray {
        if (payload.size > MAX_UDP_PACKET_SIZE) throw NowhereError.PacketTooLarge(payload.size)
        val out = ByteArray(2 + payload.size)
        out.putUInt16(0, payload.size)
        payload.copyInto(out, 2)
        return out
    }

    /** Reads one such packet, or null while the buffer is still short of one. */
    fun decodeUdpStreamPacket(data: ByteArray, offset: Int = 0): UdpStreamPacket? {
        if (offset < 0 || offset + 2 > data.size) return null
        val length = data.uint16(offset)
        if (offset + 2 + length > data.size) return null
        return UdpStreamPacket(data.copyOfRange(offset + 2, offset + 2 + length), 2 + length)
    }

    // Host classification.

    /**
     * Puts a name into the form that goes on the wire: ASCII, lowercase.
     *
     * A non-ASCII name is converted with IDNA rather than sent as UTF-8; the
     * portal is entitled to assume a DNS name, and a UTF-8 one would fail the
     * label rules below in a confusing place.
     */
    private fun asciiWireHost(host: String): String {
        if (host.isEmpty()) throw NowhereError.InvalidFlow("Empty target host")
        if (host.all { it.code < 0x80 }) return host.lowercase()
        val converted = try {
            IDN.toASCII(host, IDN.ALLOW_UNASSIGNED)
        } catch (_: IllegalArgumentException) {
            throw NowhereError.InvalidFlow("Target is not valid IDNA")
        }
        if (converted.isEmpty() || !converted.all { it.code < 0x80 }) {
            throw NowhereError.InvalidFlow("Target is not valid IDNA")
        }
        return converted.lowercase()
    }

    /**
     * Applies the DNS name rules (RFC 1035 §2.3.1, RFC 1123 §2.1).
     *
     * Empty labels are rejected, which also rules out a trailing dot and a
     * doubled one; a portal that accepted both "a.b" and "a.b." would treat
     * one host as two.
     */
    private fun validateDomain(domain: String) {
        val length = domain.toByteArray(Charsets.UTF_8).size
        if (length == 0 || length > MAX_DOMAIN_LENGTH) {
            throw NowhereError.ProtocolViolation("invalid target length ($length)")
        }
        for (label in domain.split('.')) {
            val valid = label.isNotEmpty() &&
                label.length <= 63 &&
                label.first() != '-' &&
                label.last() != '-' &&
                label.all { it.isAsciiAlphaNumeric() || it == '-' }
            if (!valid) throw NowhereError.InvalidFlow("Invalid DNS target")
        }
    }

    private fun Char.isAsciiAlphaNumeric(): Boolean =
        this in '0'..'9' || this in 'A'..'Z' || this in 'a'..'z'

    /**
     * A dotted quad, or null.
     *
     * Strict in the same way `inet_pton` is: exactly four decimal octets, no
     * leading zeros. Leading zeros matter because some resolvers read them as
     * octal, so a host that two pieces of software disagree about is exactly
     * the kind of address that should not become a proxy destination.
     */
    private fun parseIpv4Literal(host: String): ByteArray? {
        val out = ByteArray(4)
        var index = 0
        var value = -1
        for (ch in host) {
            when {
                ch in '0'..'9' -> {
                    if (value == 0) return null
                    value = (if (value < 0) 0 else value) * 10 + (ch - '0')
                    if (value > 255) return null
                }

                ch == '.' -> {
                    if (value < 0 || index == 3) return null
                    out[index++] = value.toByte()
                    value = -1
                }

                else -> return null
            }
        }
        if (value < 0 || index != 3) return null
        out[3] = value.toByte()
        return out
    }

    /**
     * An IPv6 literal, or null.
     *
     * Hand-rolled rather than delegated to `InetAddress`, for two reasons:
     * that class resolves anything it fails to recognise as a literal, which
     * would turn a malformed host into a DNS lookup on whatever thread is
     * encoding; and it collapses `::ffff:1.2.3.4` to a four-byte address,
     * whereas the wire form here is sixteen bytes.
     */
    private fun parseIpv6Literal(host: String): ByteArray? {
        if (!host.contains(':')) return null

        val elision = host.indexOf("::")
        // Two elisions would be ambiguous about how many zero groups each one
        // stands for, so at most one is allowed.
        if (elision >= 0 && host.indexOf("::", elision + 1) >= 0) return null

        if (elision < 0) {
            val whole = parseIpv6Groups(host) ?: return null
            return if (whole.size == 16) whole else null
        }

        val head = parseIpv6Groups(host.substring(0, elision)) ?: return null
        val tail = parseIpv6Groups(host.substring(elision + 2)) ?: return null
        // The elision must stand for at least one group of zeros.
        if (head.size + tail.size > 14) return null

        val out = ByteArray(16)
        head.copyInto(out, 0)
        tail.copyInto(out, 16 - tail.size)
        return out
    }

    /**
     * The colon-separated half of an IPv6 literal, with the trailing dotted
     * quad of the IPv4-embedding forms allowed in last position.
     */
    private fun parseIpv6Groups(text: String): ByteArray? {
        if (text.isEmpty()) return ByteArray(0)
        val parts = text.split(':')
        val out = ByteArray(parts.size * 2 + 2)
        var at = 0
        for ((index, part) in parts.withIndex()) {
            if (index == parts.size - 1 && part.contains('.')) {
                val quad = parseIpv4Literal(part) ?: return null
                quad.copyInto(out, at)
                at += 4
                break
            }
            if (part.isEmpty() || part.length > 4) return null
            var value = 0
            for (ch in part) {
                val digit = when (ch) {
                    in '0'..'9' -> ch - '0'
                    in 'a'..'f' -> ch - 'a' + 10
                    in 'A'..'F' -> ch - 'A' + 10
                    else -> return null
                }
                value = value * 16 + digit
            }
            out[at++] = (value ushr 8).toByte()
            out[at++] = value.toByte()
        }
        return out.copyOf(at)
    }
}

// Big-endian accessors. Everything Nowhere writes is network byte order.

private fun ByteArray.putUInt16(at: Int, value: Int) {
    this[at] = (value ushr 8).toByte()
    this[at + 1] = value.toByte()
}

private fun ByteArray.putUInt32(at: Int, value: Long) {
    this[at] = (value ushr 24).toByte()
    this[at + 1] = (value ushr 16).toByte()
    this[at + 2] = (value ushr 8).toByte()
    this[at + 3] = value.toByte()
}

private fun ByteArray.uint16(at: Int): Int =
    ((this[at].toInt() and 0xFF) shl 8) or (this[at + 1].toInt() and 0xFF)

private fun ByteArray.uint32(at: Int): Long =
    ((this[at].toLong() and 0xFF) shl 24) or
        ((this[at + 1].toLong() and 0xFF) shl 16) or
        ((this[at + 2].toLong() and 0xFF) shl 8) or
        (this[at + 3].toLong() and 0xFF)

/**
 * Puts fragmented UDP packets back together.
 *
 * A slot is opened by the first fragment of a packet and is keyed by flow and
 * packet id together, because packet ids only have to be unique within a flow.
 * The rules that close a slot early all exist because the far side is not
 * trusted: a peer that could open slots faster than they complete, or leave
 * them half-filled, would otherwise pin memory here indefinitely. So a slot
 * dies when a later fragment contradicts the first about the shape of the
 * packet, when a repeated index arrives with different bytes, when the pieces
 * would overrun the announced length, or when [ttlNanos] passes without the
 * packet completing. There are at most [maxSlots] of them at once.
 *
 * Expiry is checked whenever a fragment arrives rather than on a timer, which
 * makes the whole class a pure function of its inputs and [clock] and so
 * testable without waiting for real time to pass.
 *
 * Not thread-safe: the session that owns one already serialises datagram
 * delivery, and a second lock here would only be a second thing to get wrong.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereFragmentReassembler(
    private val maxSlots: Int = DEFAULT_MAX_SLOTS,
    private val ttlNanos: Long = DEFAULT_TTL_NANOS,
    private val clock: () -> Long = System::nanoTime
) {
    companion object {
        /** How many packets may be part-assembled at once. */
        const val DEFAULT_MAX_SLOTS = 64

        /** How long an incomplete packet is held: ten seconds. */
        const val DEFAULT_TTL_NANOS = 10_000_000_000L
    }

    private data class Key(val flowId: Long, val packetId: Long)

    private class Slot(
        val createdAt: Long,
        val fragmentCount: Int,
        val totalLength: Int
    ) {
        val fragments = arrayOfNulls<ByteArray>(fragmentCount)
        var received = 0
        var receivedBytes = 0
    }

    private val slots = LinkedHashMap<Key, Slot>()

    /** How many packets are currently part-assembled. */
    val size: Int get() = slots.size

    /**
     * Takes one fragment and returns the complete packet if it was the last
     * one missing, or null while the packet is still incomplete — or was
     * abandoned.
     *
     * Anything that is not a [NowhereProtocol.UdpType.FRAGMENT] is refused
     * here rather than quietly passed through, since a caller that hands a
     * DATA message to the reassembler has confused the two paths.
     */
    fun accept(message: NowhereProtocol.UdpMessage): ByteArray? {
        if (message.type != NowhereProtocol.UdpType.FRAGMENT) return null
        expire(clock())

        val key = Key(message.flowId, message.packetId)
        val existing = slots[key]
        val slot: Slot
        if (existing != null) {
            // The first fragment fixed the shape of the packet; a later one
            // disagreeing means one of them is forged or stale, and there is
            // no way to tell which, so neither is kept.
            if (existing.fragmentCount != message.fragmentCount ||
                existing.totalLength != message.totalLength
            ) {
                slots.remove(key)
                return null
            }
            slot = existing
        } else {
            if (slots.size >= maxSlots) return null
            if (message.fragmentId >= message.fragmentCount) return null
            slot = Slot(clock(), message.fragmentCount, message.totalLength)
            slots[key] = slot
        }

        val index = message.fragmentId
        if (index >= slot.fragmentCount) {
            slots.remove(key)
            return null
        }

        val duplicate = slot.fragments[index]
        if (duplicate != null) {
            // A retransmission of the same bytes is harmless and ignored; a
            // different payload for the same index is an attempt to rewrite a
            // packet mid-assembly, and takes the slot with it.
            if (!duplicate.contentEquals(message.payload)) slots.remove(key)
            return null
        }
        if (slot.receivedBytes + message.payload.size > slot.totalLength) {
            slots.remove(key)
            return null
        }

        slot.fragments[index] = message.payload
        slot.received++
        slot.receivedBytes += message.payload.size
        if (slot.received != slot.fragmentCount) return null

        slots.remove(key)
        // Every index arrived, so the bytes must add up to what the sender
        // announced; if they do not, the pieces came from different packets.
        if (slot.receivedBytes != slot.totalLength) return null

        val out = ByteArray(slot.totalLength)
        var at = 0
        for (fragment in slot.fragments) {
            val piece = fragment ?: return null
            piece.copyInto(out, at)
            at += piece.size
        }
        return out
    }

    /**
     * Drops everything held for a flow.
     *
     * Called when a flow closes: its packet ids mean nothing afterwards, and
     * holding them would keep slots from anyone else until the TTL ran out.
     */
    fun forget(flowId: Long) {
        slots.keys.removeAll { it.flowId == flowId }
    }

    /** Drops every slot, for a session that is going away entirely. */
    fun clear() {
        slots.clear()
    }

    private fun expire(now: Long) {
        slots.entries.removeAll { now - it.value.createdAt > ttlNanos }
    }
}

/**
 * What went wrong in the Nowhere layer.
 *
 * These are throwing failures — a request that cannot be built, or material
 * that cannot be right. Failures of parsing come back as null instead, because
 * a decoder reading a stream cannot distinguish "malformed" from "not yet
 * complete" and the caller treats both the same way.
 */
sealed class NowhereError(message: String) : IOException(message) {

    /** A configured value is unusable, before any bytes are exchanged. */
    class ProtocolViolation(detail: String) : NowhereError(detail)

    /** A flow header, target or control frame that could not be built. */
    class InvalidFlow(detail: String) : NowhereError(detail)

    /** The authentication material is the wrong shape. */
    class AuthenticationRejected(detail: String) : NowhereError(detail)

    /** A UDP packet larger than the 16-bit length field can describe. */
    class PacketTooLarge(size: Int) :
        NowhereError("UDP packet of $size bytes exceeds ${NowhereProtocol.MAX_UDP_PACKET_SIZE}")

    /** The path allows a datagram too small to carry even a header. */
    class DatagramTooLarge(maxFrame: Int, headerSize: Int) :
        NowhereError("Datagram limit of $maxFrame bytes cannot hold a $headerSize byte header")
}
