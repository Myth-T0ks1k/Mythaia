package com.mythaia.desktop.tun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The crash-recovery snapshot is read back by a process running as SYSTEM,
 * so it holds route data and nothing that could become a command: the
 * argv is rebuilt from fixed templates, and a file that is not exactly
 * what this version writes is thrown away whole.
 */
class RouteSnapshotTest {

    private val config = TunNetConfig(
        interfaceIndex = 27,
        physicalInterfaceIndex = 5,
        physicalGateway = "192.168.1.1",
        excludedHosts = listOf("203.0.113.10"),
        excludedNetworks = listOf("10.0.0.0/8")
    )

    @Test
    fun `delete commands come from fixed templates`() {
        assertEquals(
            "route delete 203.0.113.10 mask 255.255.255.255 192.168.1.1 if 5",
            RouteEntry.v4("203.0.113.10", 32, "192.168.1.1", 5).deleteCommand().toString()
        )
        assertEquals(
            "netsh interface ipv6 delete route 8000::/1 interface=27 store=active",
            RouteEntry.v6("8000::", 1, 27).deleteCommand().toString()
        )
        assertTrue(RoutePlan.teardownEntries(config).map { it.deleteCommand() }.none { it.essential })
    }

    @Test
    fun `the snapshot covers the adapter's IPv6 halves too`() {
        val entries = RoutePlan.teardownEntries(config)
        assertTrue(entries.contains(RouteEntry.v6("::", 1, 27)))
        assertTrue(entries.contains(RouteEntry.v6("8000::", 1, 27)))
        assertTrue(entries.contains(RouteEntry.v4("0.0.0.0", 1, "10.8.0.1", 27)))
        assertTrue(entries.contains(RouteEntry.v4("10.0.0.0", 8, "192.168.1.1", 5)))
        assertTrue(RoutePlan.teardownEntries(config.copy(ipv6Address = null)).none { it.kind == RouteEntry.IPV6 })
        // The command form of the same plan still deletes the IPv6 routes.
        assertTrue(RoutePlan.teardown(config).any { it.toString() == "netsh interface ipv6 delete route ::/1 interface=27 store=active" })
    }

    @Test
    fun `what was written is read back unchanged`() {
        val entries = RoutePlan.teardownEntries(config) + RoutePlan.includeHostEntry(config, "8.8.8.8")!!
        assertEquals(entries, WindowsRoutes.parseSnapshot(WindowsRoutes.encodeSnapshot(entries)))
    }

    @Test
    fun `the old format and other versions are rejected`() {
        assertNull(WindowsRoutes.parseSnapshot(null))
        assertNull(WindowsRoutes.parseSnapshot(""))
        assertNull(WindowsRoutes.parseSnapshot("""{"teardown":[["cmd","/c","calc"]]}"""))
        assertNull(WindowsRoutes.parseSnapshot("""{"version":1,"routes":[]}"""))
        assertNull(WindowsRoutes.parseSnapshot("""{"routes":[{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}]}"""))
        assertNotNull(WindowsRoutes.parseSnapshot("""{"version":2,"routes":[]}"""))
    }

    @Test
    fun `one bad entry rejects the whole file`() {
        fun snapshot(vararg entries: String) = """{"version":2,"routes":[${entries.joinToString(",")}]}"""
        val good = """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}"""
        assertEquals(1, WindowsRoutes.parseSnapshot(snapshot(good))?.size)
        val bad = listOf(
            """{"kind":"shell","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"evil.example","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4 && calc","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"999.1.1.1","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":33,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"fe80::1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":0}""",
            """{"kind":"route6","destination":"8000::","prefix":129,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"8000:: /1","prefix":1,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"1.2.3.4","prefix":1,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"8000::","prefix":1,"gateway":"192.168.1.1","interfaceIndex":27}"""
        )
        for (entry in bad) assertNull(entry, WindowsRoutes.parseSnapshot(snapshot(good, entry)))
    }

    @Test
    fun `WindowsRoutes apply, excludeHost, repointPhysical and restore execute planned commands`() {
        val file = java.io.File.createTempFile("routes-test-", ".json")
        try {
            val ran = mutableListOf<List<String>>()
            val routes = WindowsRoutes(
                snapshot = file,
                runCommand = { argv ->
                    ran += argv
                    WindowsNet.Result(0, "")
                },
                retryDelayMs = 0L
            )
            routes.apply(config)
            assertEquals(config, routes.applied)
            assertEquals(RoutePlan.setup(config).map { it.argv }, ran)
            org.junit.Assert.assertTrue(file.isFile)
            assertEquals(RoutePlan.teardownEntries(config), WindowsRoutes.parseSnapshot(file.readText()))

            ran.clear()
            routes.excludeHost("8.8.8.8")
            // Adding the same host or an already-excluded host is a no-op.
            routes.excludeHost("8.8.8.8")
            routes.excludeHost("203.0.113.10")
            routes.excludeHost("2001:4860:4860::8888")
            assertEquals(listOf(RoutePlan.excludeHost(config, "8.8.8.8")!!.argv), ran)
            assertEquals(
                listOf(RoutePlan.includeHostEntry(config, "8.8.8.8")!!) + RoutePlan.teardownEntries(config),
                WindowsRoutes.parseSnapshot(file.readText())
            )

            ran.clear()
            org.junit.Assert.assertTrue(routes.repointPhysical(12, "10.0.0.1", listOf("198.51.100.7")))
            assertEquals(12, routes.applied?.physicalInterfaceIndex)
            assertEquals("10.0.0.1", routes.applied?.physicalGateway)
            // Old physical routes on interface 5 deleted first, then new physical routes on interface 12 added.
            org.junit.Assert.assertTrue(ran.first().containsAll(listOf("route", "delete", "8.8.8.8", "if", "5")))
            org.junit.Assert.assertTrue(ran.last().containsAll(listOf("route", "add", "if", "12")))

            ran.clear()
            routes.restore()
            assertNull(routes.applied)
            org.junit.Assert.assertFalse(file.exists())
            val teardownCount = ran.size
            org.junit.Assert.assertTrue(teardownCount > 0)

            // A second restore is a no-op.
            routes.restore()
            assertEquals(teardownCount, ran.size)
        } finally {
            file.delete()
        }
    }

    @Test
    fun `WindowsRoutes rolls back and deletes snapshot when an essential command fails after retries`() {
        val file = java.io.File.createTempFile("routes-rollback-", ".json")
        try {
            val ran = mutableListOf<List<String>>()
            val routes = WindowsRoutes(
                snapshot = file,
                runCommand = { argv ->
                    ran += argv
                    if (argv.take(3) == listOf("route", "add", "0.0.0.0")) {
                        WindowsNet.Result(1, "The object already exists.")
                    } else {
                        WindowsNet.Result(0, "")
                    }
                },
                retryDelayMs = 0L
            )
            try {
                routes.apply(config)
                org.junit.Assert.fail("Expected IOException when essential route command fails")
            } catch (e: java.io.IOException) {
                org.junit.Assert.assertTrue(e.message.orEmpty().contains("route add 0.0.0.0"))
            }
            assertNull(routes.applied)
            org.junit.Assert.assertFalse(file.exists())
            // 1 initial attempt + 5 retries = 6 attempts on the failing essential command.
            assertEquals(6, ran.count { it.take(3) == listOf("route", "add", "0.0.0.0") })
            // Rollback ran the teardown delete commands.
            org.junit.Assert.assertTrue(ran.any { it.take(2) == listOf("route", "delete") })
        } finally {
            file.delete()
        }
    }

    @Test
    fun `WindowsRoutes cleanupLeftovers trusts SYSTEM and Administrators and ignores untrusted owners`() {
        val file = java.io.File.createTempFile("routes-leftovers-", ".json")
        try {
            val entries = RoutePlan.teardownEntries(config)
            file.writeText(WindowsRoutes.encodeSnapshot(entries))
            val untrustedRan = mutableListOf<List<String>>()
            WindowsRoutes(
                snapshot = file,
                runCommand = { argv -> untrustedRan += argv; WindowsNet.Result(0, "") },
                ownerSid = { "S-1-5-21-1111-2222-3333-1001" }
            ).cleanupLeftovers()
            if (WindowsNet.isWindows && WindowsNet.currentUserSid != "S-1-5-21-1111-2222-3333-1001") {
                org.junit.Assert.assertTrue(untrustedRan.isEmpty())
            }
            org.junit.Assert.assertFalse(file.exists())

            file.writeText(WindowsRoutes.encodeSnapshot(entries))
            val trustedRan = mutableListOf<List<String>>()
            WindowsRoutes(
                snapshot = file,
                runCommand = { argv -> trustedRan += argv; WindowsNet.Result(0, "") },
                ownerSid = { "S-1-5-18" }
            ).cleanupLeftovers()
            assertEquals(entries.map { it.deleteCommand().argv }, trustedRan)
            org.junit.Assert.assertFalse(file.exists())
        } finally {
            file.delete()
        }
    }

    @Test
    fun `WintunPacketDevice guards bounds and exchanges packets through WireGuardTunnel`() {
        val stats = com.mythaia.desktop.engine.TrafficStats()
        val written = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val toRead = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        val device = WintunPacketDevice(
            receivePacket = { buf, keepRunning ->
                var pkt: ByteArray? = null
                while (keepRunning() && pkt == null) {
                    pkt = toRead.poll(20, java.util.concurrent.TimeUnit.MILLISECONDS)
                }
                if (pkt == null) 0 else {
                    pkt.copyInto(buf, 0, 0, pkt.size)
                    pkt.size
                }
            },
            sendPacket = { pkt, len ->
                written.offer(pkt.copyOf(len))
                true
            },
            stats = stats,
            dropIpv6 = true
        )
        // Bounds guards: empty read buffer returns -1, out-of-range write length is ignored.
        assertEquals(-1, device.read(ByteArray(0)))
        device.write(byteArrayOf(0x45, 0, 0, 20), 0)
        device.write(byteArrayOf(0x45, 0, 0, 20), 10)
        org.junit.Assert.assertTrue(written.isEmpty())
        assertEquals(0L, stats.down.get())

        // End-to-end handshake + encrypted IPv4 exchange over loopback between client WintunPacketDevice and peer responder.
        val (clientPriv, _) = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.generateKeyPair()
        val (peerPriv, peerPub) = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.generateKeyPair()
        val peerSocket = java.net.DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
        peerSocket.soTimeout = 1000
        val peerThread = Thread({
            try {
                val buf = ByteArray(2048)
                var sendKey: ByteArray? = null
                var receiveKey: ByteArray? = null
                var clientIndex = 0
                val responderIndex = 0x33445566
                while (!peerSocket.isClosed) {
                    val dgram = java.net.DatagramPacket(buf, buf.size)
                    try {
                        peerSocket.receive(dgram)
                    } catch (_: java.net.SocketTimeoutException) {
                        continue
                    }
                    val data = buf.copyOf(dgram.length)
                    if (data.size == com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.INITIATION_SIZE &&
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.readLe32(data, 0) == 1
                    ) {
                        clientIndex = com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.readLe32(data, 4)
                        val ephI = data.copyOfRange(8, 40)
                        val encStatic = data.copyOfRange(40, 88)
                        val encTs = data.copyOfRange(88, 116)
                        var c = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII))
                        var h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(
                            com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(c, "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray(Charsets.US_ASCII)),
                            peerPub
                        )
                        c = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, ephI, 1)[0]
                        h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(h, ephI)
                        var d = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.sharedSecret(peerPriv, ephI), 2)
                        c = d[0]
                        val initStatic = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.open(d[1], 0, encStatic, h) ?: continue
                        h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(h, encStatic)
                        d = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.sharedSecret(peerPriv, initStatic), 2)
                        c = d[0]
                        com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.open(d[1], 0, encTs, h) ?: continue
                        h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(h, encTs)
                        val (ePriv, ePub) = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.generateKeyPair()
                        c = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, ePub, 1)[0]
                        h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(h, ePub)
                        c = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.sharedSecret(ePriv, ephI), 1)[0]
                        c = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.sharedSecret(ePriv, initStatic), 1)[0]
                        val three = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, ByteArray(32), 3)
                        c = three[0]
                        h = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash(h, three[1])
                        val empty = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.seal(three[2], 0, ByteArray(0), h)
                        val body = ByteArray(60)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe32(body, 0, 2)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe32(body, 4, responderIndex)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe32(body, 8, clientIndex)
                        ePub.copyInto(body, 12)
                        empty.copyInto(body, 44)
                        val mac1 = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.mac(
                            com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.hash("mac1----".toByteArray(Charsets.US_ASCII), initStatic),
                            body
                        )
                        val resp = body + mac1 + ByteArray(16)
                        val transport = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.kdf(c, ByteArray(0), 2)
                        receiveKey = transport[0]
                        sendKey = transport[1]
                        peerSocket.send(java.net.DatagramPacket(resp, resp.size, dgram.socketAddress))
                    } else if (data.size >= 32 && com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.readLe32(data, 0) == 4) {
                        val rk = receiveKey ?: continue
                        val sk = sendKey ?: continue
                        val counter = com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.readLe64(data, 8)
                        val opened = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.open(rk, counter, data.copyOfRange(16, data.size), ByteArray(0)) ?: continue
                        val ipLen = com.mythaia.vpn.protocol.wireguard.WireGuardTunnel.ipPacketLength(opened) ?: continue
                        val replyIp = opened.copyOf(ipLen)
                        val ciphertext = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.seal(sk, 0L, replyIp, ByteArray(0))
                        val out = ByteArray(16 + ciphertext.size)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe32(out, 0, 4)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe32(out, 4, clientIndex)
                        com.mythaia.vpn.protocol.wireguard.WireGuardHandshake.writeLe64(out, 8, 0L)
                        ciphertext.copyInto(out, 16)
                        peerSocket.send(java.net.DatagramPacket(out, out.size, dgram.socketAddress))
                        break
                    }
                }
            } catch (_: Exception) {
            }
        }, "test-wg-peer").apply { isDaemon = true; start() }

        val tunnel = com.mythaia.vpn.protocol.wireguard.WireGuardTunnel(
            config = com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse(
                """
                [Interface]
                PrivateKey = ${com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.encodeKey(clientPriv)}
                Address = 10.9.0.2/32
                DNS = 1.1.1.1
                MTU = 1400

                [Peer]
                PublicKey = ${com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.encodeKey(peerPub)}
                Endpoint = 127.0.0.1:${peerSocket.localPort}
                AllowedIPs = 0.0.0.0/0
                """.trimIndent()
            ),
            openSocket = { physicalSocket { java.net.InetAddress.getByName("127.0.0.1") } }
        )

        try {
            tunnel.start(device)
            val deadline = System.currentTimeMillis() + 5_000L
            while (!tunnel.hasHandshake && System.currentTimeMillis() < deadline) {
                Thread.sleep(20)
            }
            org.junit.Assert.assertTrue("Expected WireGuard handshake to complete", tunnel.hasHandshake)
            val ipv6Pkt = ByteArray(40).apply { this[0] = 0x60 }
            val ipv4Pkt = ByteArray(28).apply {
                this[0] = 0x45
                this[2] = 0
                this[3] = 28
                this[20] = 0xCA.toByte()
                this[21] = 0xFE.toByte()
            }
            // IPv6 packet is dropped by WintunPacketDevice (dropIpv6 = true), IPv4 packet goes through and echoes back.
            toRead.offer(ipv6Pkt)
            toRead.offer(ipv4Pkt)
            val echoed = written.poll(5, java.util.concurrent.TimeUnit.SECONDS)
            assertNotNull("Expected echoed IPv4 packet from WireGuardTunnel", echoed)
            org.junit.Assert.assertArrayEquals(ipv4Pkt, echoed)
            assertEquals(28L, stats.up.get())
            assertEquals(28L, stats.down.get())
        } finally {
            tunnel.stop()
            device.close()
            peerSocket.close()
            peerThread.join(1000)
        }
    }
}
