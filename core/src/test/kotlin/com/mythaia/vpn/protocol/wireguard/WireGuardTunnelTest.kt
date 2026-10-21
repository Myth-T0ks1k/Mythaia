package com.mythaia.vpn.protocol.wireguard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The parts of the tunnel that can be exercised without a socket: how a
 * received datagram is sorted, and how a packet's own length is read.
 */
class WireGuardTunnelTest {

    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    private fun tunnel(extraInterface: String = ""): WireGuardTunnel =
        WireGuardTunnel(
            WireGuardConfig.parse(
                """
                [Interface]
                PrivateKey = $privateKey
                Address = 10.0.0.2/32
                $extraInterface

                [Peer]
                PublicKey = $peerKey
                Endpoint = 192.0.2.1:51820
                AllowedIPs = 0.0.0.0/0
                """.trimIndent()
            )
        )

    private fun message(size: Int, typeAt: Int, type: Int): ByteArray =
        ByteArray(size) { 0xAB.toByte() }.also { WireGuardHandshake.writeLe32(it, typeAt, type) }

    // MARK: - Classification

    @Test
    fun `plain WireGuard reads the type at offset zero`() {
        val wg = tunnel()
        assertEquals(
            WireGuardTunnel.Kind.RESPONSE,
            wg.classify(message(WireGuardHandshake.RESPONSE_SIZE, 0, 2))
        )
        assertEquals(WireGuardTunnel.Kind.COOKIE, wg.classify(message(64, 0, 3)))
        assertEquals(WireGuardTunnel.Kind.TRANSPORT, wg.classify(message(128, 0, 4)))
        assertEquals(WireGuardTunnel.Kind.UNKNOWN, wg.classify(message(128, 0, 9)))
    }

    @Test
    fun `an S2-junked response is recognised past its junk`() {
        // The response is the only message AmneziaWG pads, and the padding is
        // random — so a dispatcher reading offset 0 sees noise and throws the
        // handshake away, leaving the tunnel retrying forever.
        val junk = 30
        val wg = tunnel("S2 = $junk\nH2 = 2")

        val response = message(WireGuardHandshake.RESPONSE_SIZE + junk, junk, 2)
        assertEquals(WireGuardTunnel.Kind.RESPONSE, wg.classify(response))
    }

    @Test
    fun `a junked response is recognised under a renumbered H2`() {
        val junk = 15
        val h2 = 0x2A3B4C5D
        val wg = tunnel("S2 = $junk\nH1 = 1234567\nH2 = $h2\nH3 = 3333333\nH4 = 4433221")

        val response = message(WireGuardHandshake.RESPONSE_SIZE + junk, junk, h2)
        assertEquals(WireGuardTunnel.Kind.RESPONSE, wg.classify(response))
    }

    @Test
    fun `a datagram of the junked length that is not a response is left alone`() {
        // Length alone must not be enough: a transport packet that happens to
        // be 92 + S2 bytes long would otherwise be handed to the handshake.
        val junk = 30
        val wg = tunnel("S2 = $junk\nH2 = 2")

        val transport = message(WireGuardHandshake.RESPONSE_SIZE + junk, 0, 4)
        assertEquals(WireGuardTunnel.Kind.TRANSPORT, wg.classify(transport))
    }

    @Test
    fun `a runt datagram is not classified`() {
        assertEquals(WireGuardTunnel.Kind.UNKNOWN, tunnel().classify(ByteArray(3)))
    }

    // MARK: - Packet length

    @Test
    fun `an IPv4 packet reports its own total length`() {
        val packet = ByteArray(64)
        packet[0] = 0x45
        packet[2] = 0x00
        packet[3] = 40
        assertEquals(40, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `an IPv6 packet reports the header plus its payload`() {
        val packet = ByteArray(128)
        packet[0] = 0x60
        packet[4] = 0x00
        packet[5] = 24
        assertEquals(64, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `padding past the declared length is not written to the TUN`() {
        // The plaintext is padded to a multiple of 16, so what comes out of the
        // AEAD is longer than the packet inside it.
        val packet = ByteArray(48)
        packet[0] = 0x45
        packet[3] = 37
        assertEquals(37, WireGuardTunnel.ipPacketLength(packet))
    }

    @Test
    fun `a truncated or unknown header has no length`() {
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(0)))
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(10) { 0x45 }))
        assertNull(WireGuardTunnel.ipPacketLength(ByteArray(64) { 0x25 }))
    }

    // MARK: - HChaCha20

    @Test
    fun `HChaCha20 matches the RFC draft test vector`() {
        // draft-irtf-cfrg-xchacha, section 2.2.1. Checked against the published
        // answer rather than our own round trip: a wrong core would still
        // decrypt whatever it had encrypted.
        val key = ByteArray(32) { it.toByte() }
        val nonce = byteArrayOf(
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27
        )
        val expected = intArrayOf(
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
            0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
            0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
            0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc
        ).map { it.toByte() }.toByteArray()

        assertArrayEquals(expected, WireGuardCrypto.hchacha20(key, nonce))
    }

    @Test
    fun `XChaCha20 rejects a tampered cookie and a wrong associated mac1`() {
        val key = WireGuardCrypto.randomBytes(32)
        val nonce = WireGuardCrypto.randomBytes(24)
        val mac1 = WireGuardCrypto.randomBytes(16)

        // Sealing goes through the same subkey derivation as opening.
        val subkey = WireGuardCrypto.hchacha20(key, nonce.copyOf(16))
        val inner = ByteArray(12).also { nonce.copyInto(it, 4, 16, 24) }
        val cookie = WireGuardCrypto.randomBytes(16)
        val sealed = sealWithNonce(subkey, inner, cookie, mac1)

        assertArrayEquals(cookie, WireGuardCrypto.xopen(key, nonce, sealed, mac1))
        assertNull(WireGuardCrypto.xopen(key, nonce, sealed, WireGuardCrypto.randomBytes(16)))
        assertNull(
            WireGuardCrypto.xopen(
                key, nonce, sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }, mac1
            )
        )
    }

    private fun sealWithNonce(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = org.bouncycastle.crypto.modes.ChaCha20Poly1305()
        cipher.init(
            true,
            org.bouncycastle.crypto.params.AEADParameters(
                org.bouncycastle.crypto.params.KeyParameter(key), 128, nonce, aad
            )
        )
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var written = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        written += cipher.doFinal(out, written)
        return if (written == out.size) out else out.copyOf(written)
    }

    // MARK: - End-to-end PacketDevice tunnel

    @Test
    fun `PacketDevice tunnel completes handshake and carries IPv4 packets for WireGuard and AmneziaWG`() {
        assertRoundTripThroughPacketDevice(amneziaBlock = "")
        assertRoundTripThroughPacketDevice(
            amneziaBlock = """
                Jc = 2
                Jmin = 12
                Jmax = 24
                S1 = 15
                S2 = 25
                H1 = 100001
                H2 = 100002
                H3 = 100003
                H4 = 100004
            """.trimIndent(),
            s1 = 15,
            s2 = 25,
            h1 = 100001,
            h2 = 100002,
            h4 = 100004
        )
    }

    private fun assertRoundTripThroughPacketDevice(
        amneziaBlock: String,
        s1: Int = 0,
        s2: Int = 0,
        h1: Int = WireGuardHandshake.MESSAGE_INITIATION,
        h2: Int = WireGuardHandshake.MESSAGE_RESPONSE,
        h4: Int = WireGuardHandshake.MESSAGE_TRANSPORT
    ) {
        val (clientPriv, _) = WireGuardCrypto.generateKeyPair()
        val (serverPriv, serverPub) = WireGuardCrypto.generateKeyPair()
        val peerSocket = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
        peerSocket.soTimeout = 5000
        val peerThread = Thread({
            val buf = ByteArray(2048)
            var sendKey: ByteArray? = null
            var receiveKey: ByteArray? = null
            var clientIndex = 0
            val responderIndex = 0x33445566
            try {
                while (!peerSocket.isClosed) {
                    val p = java.net.DatagramPacket(buf, buf.size)
                    peerSocket.receive(p)
                    val data = p.data.copyOfRange(p.offset, p.offset + p.length)
                    if (data.size == s1 + WireGuardHandshake.INITIATION_SIZE &&
                        WireGuardHandshake.readLe32(data, s1) == h1
                    ) {
                        val init = data.copyOfRange(s1, data.size)
                        clientIndex = WireGuardHandshake.readLe32(init, 4)
                        val ephI = init.copyOfRange(8, 40)
                        val encStatic = init.copyOfRange(40, 88)
                        val encTs = init.copyOfRange(88, 116)
                        var c = WireGuardCrypto.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII))
                        var h = WireGuardCrypto.hash(
                            WireGuardCrypto.hash(c, "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray(Charsets.US_ASCII)),
                            serverPub
                        )
                        c = WireGuardCrypto.kdf(c, ephI, 1)[0]
                        h = WireGuardCrypto.hash(h, ephI)
                        var d = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(serverPriv, ephI), 2)
                        c = d[0]
                        val initStatic = WireGuardCrypto.open(d[1], 0, encStatic, h) ?: continue
                        h = WireGuardCrypto.hash(h, encStatic)
                        d = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(serverPriv, initStatic), 2)
                        c = d[0]
                        WireGuardCrypto.open(d[1], 0, encTs, h) ?: continue
                        h = WireGuardCrypto.hash(h, encTs)
                        val (ePriv, ePub) = WireGuardCrypto.generateKeyPair()
                        c = WireGuardCrypto.kdf(c, ePub, 1)[0]
                        h = WireGuardCrypto.hash(h, ePub)
                        c = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(ePriv, ephI), 1)[0]
                        c = WireGuardCrypto.kdf(c, WireGuardCrypto.sharedSecret(ePriv, initStatic), 1)[0]
                        val three = WireGuardCrypto.kdf(c, ByteArray(32), 3)
                        c = three[0]
                        h = WireGuardCrypto.hash(h, three[1])
                        val empty = WireGuardCrypto.seal(three[2], 0, ByteArray(0), h)
                        h = WireGuardCrypto.hash(h, empty)
                        val body = ByteArray(60)
                        WireGuardHandshake.writeLe32(body, 0, h2)
                        WireGuardHandshake.writeLe32(body, 4, responderIndex)
                        WireGuardHandshake.writeLe32(body, 8, clientIndex)
                        ePub.copyInto(body, 12)
                        empty.copyInto(body, 44)
                        val mac1 = WireGuardCrypto.mac(
                            WireGuardCrypto.hash("mac1----".toByteArray(Charsets.US_ASCII), initStatic),
                            body
                        )
                        val resp = (if (s2 > 0) WireGuardCrypto.randomBytes(s2) else ByteArray(0)) + body + mac1 + ByteArray(16)
                        val transport = WireGuardCrypto.kdf(c, ByteArray(0), 2)
                        receiveKey = transport[0]
                        sendKey = transport[1]
                        peerSocket.send(java.net.DatagramPacket(resp, resp.size, p.socketAddress))
                    } else if (data.size >= 32 && WireGuardHandshake.readLe32(data, 0) == h4) {
                        val rk = receiveKey ?: continue
                        val sk = sendKey ?: continue
                        val counter = WireGuardHandshake.readLe64(data, 8)
                        val opened = WireGuardCrypto.open(rk, counter, data.copyOfRange(16, data.size), ByteArray(0)) ?: continue
                        val ipLen = WireGuardTunnel.ipPacketLength(opened) ?: continue
                        val replyIp = opened.copyOf(ipLen)
                        // Swap source (12..15) and destination (16..19) IPv4 addresses.
                        for (i in 0 until 4) {
                            val tmp = replyIp[12 + i]
                            replyIp[12 + i] = replyIp[16 + i]
                            replyIp[16 + i] = tmp
                        }
                        val ciphertext = WireGuardCrypto.seal(sk, 0L, replyIp, ByteArray(0))
                        val out = ByteArray(16 + ciphertext.size)
                        WireGuardHandshake.writeLe32(out, 0, h4)
                        WireGuardHandshake.writeLe32(out, 4, clientIndex)
                        WireGuardHandshake.writeLe64(out, 8, 0L)
                        ciphertext.copyInto(out, 16)
                        peerSocket.send(java.net.DatagramPacket(out, out.size, p.socketAddress))
                        break
                    }
                }
            } catch (_: Exception) {
            }
        }, "test-wg-peer").apply { isDaemon = true; start() }

        val outbound = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val inbound = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val device = object : PacketDevice {
            @Volatile var closed = false
            override fun read(buffer: ByteArray): Int {
                while (!closed) {
                    val pkt = outbound.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                    pkt.copyInto(buffer, 0, 0, pkt.size)
                    return pkt.size
                }
                return -1
            }
            override fun write(packet: ByteArray, length: Int) {
                inbound.offer(packet.copyOf(length))
            }
            override fun close() {
                closed = true
            }
        }

        val cfg = WireGuardConfig.parse(
            """
            [Interface]
            PrivateKey = ${WireGuardCrypto.encodeKey(clientPriv)}
            Address = 10.77.0.2/32
            $amneziaBlock

            [Peer]
            PublicKey = ${WireGuardCrypto.encodeKey(serverPub)}
            Endpoint = 127.0.0.1:${peerSocket.localPort}
            AllowedIPs = 0.0.0.0/0
            """.trimIndent()
        )
        val wg = WireGuardTunnel(cfg)
        try {
            wg.start(device)
            val deadline = System.currentTimeMillis() + 5_000L
            while (!wg.hasHandshake && System.currentTimeMillis() < deadline) {
                Thread.sleep(20)
            }
            org.junit.Assert.assertTrue("Handshake did not complete in time", wg.hasHandshake)

            val ipv4 = ByteArray(40)
            ipv4[0] = 0x45
            ipv4[2] = 0x00
            ipv4[3] = 40
            // 10.77.0.2 -> 10.77.0.1
            byteArrayOf(10, 77, 0, 2).copyInto(ipv4, 12)
            byteArrayOf(10, 77, 0, 1).copyInto(ipv4, 16)
            "hello-wg".toByteArray().copyInto(ipv4, 20)
            outbound.offer(ipv4)

            val echoed = inbound.poll(5, java.util.concurrent.TimeUnit.SECONDS)
            org.junit.Assert.assertNotNull("Timed out waiting for echoed IPv4 packet", echoed)
            assertEquals(40, echoed!!.size)
            assertArrayEquals(byteArrayOf(10, 77, 0, 1), echoed.copyOfRange(12, 16))
            assertArrayEquals(byteArrayOf(10, 77, 0, 2), echoed.copyOfRange(16, 20))
            assertEquals("hello-wg", String(echoed.copyOfRange(20, 28)))
            org.junit.Assert.assertTrue(wg.bytesOut >= 40L && wg.bytesIn >= 40L)
        } finally {
            wg.stop()
            device.close()
            peerSocket.close()
            peerThread.join(1000)
        }
    }

    @Test
    fun `lab sing-box WireGuard endpoint carries a UDP echo packet through PacketDevice`() {
        val singBox = sequenceOf(
            System.getenv("MYTHAIA_SING_BOX"),
            System.getenv("SING_BOX")
        ).filterNotNull().map { java.io.File(it) }.firstOrNull { it.isFile }
        org.junit.Assume.assumeTrue("sing-box not installed", singBox != null)

        val wgPort = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val echoSocket = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
        val echoPort = echoSocket.localPort
        val echoThread = Thread({
            val buf = ByteArray(2048)
            try {
                while (!echoSocket.isClosed) {
                    val p = java.net.DatagramPacket(buf, buf.size)
                    echoSocket.receive(p)
                    val reply = ("echo:" + String(p.data, p.offset, p.length)).toByteArray()
                    echoSocket.send(java.net.DatagramPacket(reply, reply.size, p.socketAddress))
                }
            } catch (_: Exception) {
            }
        }, "test-udp-echo").apply { isDaemon = true; start() }

        val (serverPrivBytes, serverPubBytes) = WireGuardCrypto.generateKeyPair()
        val (clientPrivBytes, clientPubBytes) = WireGuardCrypto.generateKeyPair()
        val serverPriv = WireGuardCrypto.encodeKey(serverPrivBytes)
        val serverPub = WireGuardCrypto.encodeKey(serverPubBytes)
        val clientPriv = WireGuardCrypto.encodeKey(clientPrivBytes)
        val clientPub = WireGuardCrypto.encodeKey(clientPubBytes)

        val configFile = java.io.File.createTempFile("sb-wg-test-", ".json")
        configFile.writeText(
            """
            {
              "log": {"level": "error"},
              "endpoints": [{
                "type": "wireguard",
                "tag": "wg",
                "system": false,
                "listen_port": $wgPort,
                "address": ["10.77.0.1/24"],
                "private_key": "$serverPriv",
                "peers": [{"public_key": "$clientPub", "allowed_ips": ["10.77.0.2/32"]}]
              }],
              "outbounds": [{"type": "direct", "tag": "direct"}],
              "route": {"rules": [{"port": [$echoPort], "action": "route-options", "override_address": "127.0.0.1"}]}
            }
            """.trimIndent()
        )
        val process = ProcessBuilder(singBox!!.absolutePath, "run", "-c", configFile.absolutePath)
            .redirectErrorStream(true)
            .start()
        val outbound = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val inbound = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val device = object : PacketDevice {
            @Volatile var closed = false
            override fun read(buffer: ByteArray): Int {
                while (!closed) {
                    val pkt = outbound.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
                    pkt.copyInto(buffer, 0, 0, pkt.size)
                    return pkt.size
                }
                return -1
            }
            override fun write(packet: ByteArray, length: Int) {
                inbound.offer(packet.copyOf(length))
            }
            override fun close() {
                closed = true
            }
        }
        val wg = WireGuardTunnel(
            WireGuardConfig.parse(
                """
                [Interface]
                PrivateKey = $clientPriv
                Address = 10.77.0.2/32
                MTU = 1280

                [Peer]
                PublicKey = $serverPub
                AllowedIPs = 0.0.0.0/0
                Endpoint = 127.0.0.1:$wgPort
                """.trimIndent()
            )
        )
        try {
            Thread.sleep(300)
            wg.start(device)
            val deadline = System.currentTimeMillis() + 8_000L
            while (!wg.hasHandshake && System.currentTimeMillis() < deadline) {
                Thread.sleep(30)
            }
            org.junit.Assert.assertTrue("sing-box WireGuard handshake timed out", wg.hasHandshake)

            val payload = "lab-wg-ping".toByteArray(Charsets.UTF_8)
            val pkt = buildIpv4UdpPacket(
                srcIp = byteArrayOf(10, 77, 0, 2),
                dstIp = byteArrayOf(198.toByte(), 51, 100, 1),
                srcPort = 41234,
                dstPort = echoPort,
                payload = payload
            )
            outbound.offer(pkt)

            val replyPkt = inbound.poll(5, java.util.concurrent.TimeUnit.SECONDS)
            org.junit.Assert.assertNotNull("Timed out waiting for UDP echo reply through sing-box WireGuard", replyPkt)
            val replyBody = String(replyPkt!!, 28, replyPkt.size - 28, Charsets.UTF_8)
            assertEquals("echo:lab-wg-ping", replyBody)
        } finally {
            wg.stop()
            device.close()
            process.destroyForcibly()
            echoSocket.close()
            echoThread.join(1000)
            configFile.delete()
        }
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = (totalLen ushr 8).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[6] = 0x40
        pkt[8] = 64
        pkt[9] = 17
        srcIp.copyInto(pkt, 12)
        dstIp.copyInto(pkt, 16)
        var ipSum = 0
        for (i in 0 until 20 step 2) {
            ipSum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        while ((ipSum ushr 16) != 0) ipSum = (ipSum and 0xFFFF) + (ipSum ushr 16)
        val ipChecksum = ipSum.inv() and 0xFFFF
        pkt[10] = (ipChecksum ushr 8).toByte()
        pkt[11] = (ipChecksum and 0xFF).toByte()

        pkt[20] = (srcPort ushr 8).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = (dstPort ushr 8).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        pkt[24] = (udpLen ushr 8).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        payload.copyInto(pkt, 28)

        var udpSum = 0
        for (i in 12 until 20 step 2) {
            udpSum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
        }
        udpSum += 17 + udpLen
        var i = 20
        while (i + 1 < totalLen) {
            udpSum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < totalLen) udpSum += (pkt[i].toInt() and 0xFF) shl 8
        while ((udpSum ushr 16) != 0) udpSum = (udpSum and 0xFFFF) + (udpSum ushr 16)
        val udpChecksum = (udpSum.inv() and 0xFFFF).let { if (it == 0) 0xFFFF else it }
        pkt[26] = (udpChecksum ushr 8).toByte()
        pkt[27] = (udpChecksum and 0xFF).toByte()
        return pkt
    }

    @Test
    fun `ipPacketLength rejects malformed IPv4 header and total lengths`() {
        org.junit.Assert.assertNull(WireGuardTunnel.ipPacketLength(ByteArray(0)))
        org.junit.Assert.assertNull(WireGuardTunnel.ipPacketLength(ByteArray(19) { 0x45 }))
        // IHL < 5 (header length < 20 bytes) is invalid even if total length >= 20.
        val badIhl = ByteArray(20).apply {
            this[0] = 0x44
            this[2] = 0
            this[3] = 20
        }
        org.junit.Assert.assertNull(WireGuardTunnel.ipPacketLength(badIhl))
        // Total length < IHL (e.g. total = 10 or 0 with IHL = 20, or total = 20 with IHL = 24) is invalid.
        val runtTotal = ByteArray(24).apply {
            this[0] = 0x45
            this[2] = 0
            this[3] = 10
        }
        org.junit.Assert.assertNull(WireGuardTunnel.ipPacketLength(runtTotal))
        val smallerThanOptionsHeader = ByteArray(24).apply {
            this[0] = 0x46 // IHL = 24
            this[2] = 0
            this[3] = 20   // total = 20 < 24
        }
        org.junit.Assert.assertNull(WireGuardTunnel.ipPacketLength(smallerThanOptionsHeader))
        // Valid 24-byte IPv4 header with options.
        val validWithOptions = ByteArray(24).apply {
            this[0] = 0x46
            this[2] = 0
            this[3] = 24
        }
        assertEquals(24, WireGuardTunnel.ipPacketLength(validWithOptions))
    }
}
