package com.mythaia.vpn.protocol

import com.mythaia.data.model.HttpTransportConfiguration
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.network.ClashProxyParser
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.XrayJsonImporter
import com.mythaia.vpn.protocol.naive.http2.HpackDecoder
import com.mythaia.vpn.protocol.naive.http2.HpackEncoder
import com.mythaia.vpn.protocol.naive.http2.Http2Frame
import com.mythaia.vpn.protocol.naive.http2.Http2FrameFlags
import com.mythaia.vpn.protocol.naive.http2.Http2FrameType
import com.mythaia.vpn.protocol.naive.http2.Http2Framer
import com.mythaia.vpn.protocol.naive.http2.Http2Wire
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class V2RayHttpTransportTest {

    @Test
    fun `HTTP 1-1 first write prepends request header to payload and hijacks raw stream after 200`() = runBlocking {
        val written = mutableListOf<ByteArray>()
        val inbound = ArrayDeque<ByteArray>(
            listOf(
                "HTTP/1.1 200 OK\r\nServer: nginx\r\n".toByteArray(Charsets.ISO_8859_1),
                "\r\nfirst-reply".toByteArray(Charsets.ISO_8859_1),
                "second-reply".toByteArray(Charsets.ISO_8859_1)
            )
        )
        val inner = object : Transport {
            override suspend fun send(data: ByteArray) {
                written.add(data)
            }
            override fun sendAsync(data: ByteArray) {
                written.add(data)
            }
            override suspend fun receive(): ByteArray? =
                if (inbound.isEmpty()) null else inbound.removeFirst()
            override fun forceCancel() {}
        }

        val http = HttpTransportConfiguration(
            hosts = listOf("cdn.example.com"),
            path = "v2ray",
            method = "PUT",
            headers = mapOf("X-Custom" to "val")
        )
        val host = V2RayHttpTransport.pickAuthority(http, secure = false, serverAddress = "203.0.113.10")
        assertEquals("cdn.example.com", host)
        val prefix = V2RayHttpTransport.encodeHttp1RequestPrefix(http, host)
        val conn = Http1ConnTransport(inner, prefix)

        val payload1 = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val payload2 = byteArrayOf(0x05, 0x06)
        conn.send(payload1)
        conn.send(payload2)

        assertEquals(2, written.size)
        val expectedFirst = (
            "PUT /v2ray HTTP/1.1\r\n" +
                "Host: cdn.example.com\r\n" +
                "X-Custom: val\r\n" +
                "\r\n"
            ).toByteArray(Charsets.UTF_8) + payload1
        assertArrayEquals(expectedFirst, written[0])
        assertArrayEquals(payload2, written[1])

        assertArrayEquals("first-reply".toByteArray(Charsets.UTF_8), conn.receive())
        assertArrayEquals("second-reply".toByteArray(Charsets.UTF_8), conn.receive())
    }

    @Test
    fun `HTTP 1-1 non-200 status fails the first read`() = runBlocking {
        val inner = object : Transport {
            override suspend fun send(data: ByteArray) {}
            override fun sendAsync(data: ByteArray) {}
            override suspend fun receive(): ByteArray =
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
            override fun forceCancel() {}
        }
        val conn = Http1ConnTransport(inner, "PUT / HTTP/1.1\r\nHost: 203.0.113.1\r\n\r\n".toByteArray())
        try {
            conn.receive()
            fail("expected ProtocolError on 403")
        } catch (e: ProxyError.ProtocolError) {
            assertTrue(e.message!!, e.message!!.contains("403"))
        }
    }

    @Test
    fun `default authority is www_example_com on HTTP 2 and serverAddress on HTTP 1-1`() {
        val empty = HttpTransportConfiguration()
        assertEquals("www.example.com", V2RayHttpTransport.pickAuthority(empty, secure = true, serverAddress = "203.0.113.5"))
        assertEquals("203.0.113.5", V2RayHttpTransport.pickAuthority(empty, secure = false, serverAddress = "203.0.113.5"))

        val headerBlocks = V2RayHttpTransport.encodeHttp2Headers(
            HttpTransportConfiguration(
                hosts = listOf("h2.example.com"),
                path = "/stream",
                method = "POST",
                headers = mapOf("Host" to "ignored.example.com", "User-Agent" to "custom-ua")
            ),
            authority = "h2.example.com"
        )
        val decoded = HpackDecoder().decode(headerBlocks)
        assertEquals(
            listOf(
                ":authority" to "h2.example.com",
                ":method" to "POST",
                ":path" to "/stream",
                ":scheme" to "https",
                "user-agent" to "custom-ua"
            ),
            decoded
        )
    }

    @Test
    fun `HTTP 2 stream sends HEADERS without END_STREAM then DATA frames`() = runBlocking {
        val clientToServer = Channel<ByteArray>(Channel.UNLIMITED)
        val serverToClient = Channel<ByteArray>(Channel.UNLIMITED)

        // Pre-seed the server's initial SETTINGS for the handshake.
        serverToClient.trySend(Http2Framer.serialize(Http2Frame(Http2FrameType.SETTINGS, 0, 0, ByteArray(0))))

        val wire = object : Http2Wire {
            override suspend fun receive(): ByteArray? = serverToClient.receiveCatching().getOrNull()
            override suspend fun send(data: ByteArray) {
                clientToServer.trySend(data)
            }
            override fun cancel() {
                clientToServer.close()
                serverToClient.close()
            }
        }

        val http = HttpTransportConfiguration(path = "/tun")
        val headers = V2RayHttpTransport.encodeHttp2Headers(http, "www.example.com")
        val transport = V2RayHttpTransport.openUnpooledHttp2(headers, "/tun") { wire }
        val serverPayload = byteArrayOf(0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())
        try {
            val respHeaders = HpackEncoder.encodeHeaderBlock(listOf(":status" to "200"))
            serverToClient.trySend(
                Http2Framer.serialize(
                    Http2Frame(Http2FrameType.HEADERS, Http2FrameFlags.END_HEADERS, 1, respHeaders)
                )
            )
            serverToClient.trySend(
                Http2Framer.serialize(
                    Http2Frame(Http2FrameType.DATA, 0, 1, serverPayload)
                )
            )
            val clientPayload = byteArrayOf(1, 2, 3, 4, 5)
            transport.send(clientPayload)
            assertArrayEquals(serverPayload, transport.receive())

            // Collect everything the client put on the wire and verify the HTTP/2 frames.
            val allSent = java.io.ByteArrayOutputStream()
            while (true) {
                val chunk = clientToServer.tryReceive().getOrNull() ?: break
                allSent.write(chunk)
            }
            val bytes = allSent.toByteArray()
            val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
            assertArrayEquals(preface, bytes.copyOfRange(0, 24))

            // Walk the 9-byte HTTP/2 frame headers after the 24-byte preface.
            var pos = 24
            val frames = mutableListOf<Triple<Int, Int, Pair<Int, ByteArray>>>()
            while (pos + 9 <= bytes.size) {
                val len = ((bytes[pos].toInt() and 0xFF) shl 16) or
                    ((bytes[pos + 1].toInt() and 0xFF) shl 8) or
                    (bytes[pos + 2].toInt() and 0xFF)
                val type = bytes[pos + 3].toInt() and 0xFF
                val flags = bytes[pos + 4].toInt() and 0xFF
                val streamId = ((bytes[pos + 5].toInt() and 0x7F) shl 24) or
                    ((bytes[pos + 6].toInt() and 0xFF) shl 16) or
                    ((bytes[pos + 7].toInt() and 0xFF) shl 8) or
                    (bytes[pos + 8].toInt() and 0xFF)
                val body = bytes.copyOfRange(pos + 9, pos + 9 + len)
                frames.add(Triple(type, flags, streamId to body))
                pos += 9 + len
            }

            // Stream 1 must have a HEADERS frame (type 0x01) with END_HEADERS (0x04) and NOT END_STREAM (0x01),
            // followed by a DATA frame (type 0x00) carrying clientPayload.
            val stream1Headers = frames.first { it.first == 0x01 && it.third.first == 1 }
            assertEquals(0x04, stream1Headers.second and 0x05)
            val stream1Data = frames.first { it.first == 0x00 && it.third.first == 1 }
            assertEquals(0x00, stream1Data.second and 0x01)
            assertArrayEquals(clientPayload, stream1Data.third.second)
        } finally {
            transport.forceCancel()
        }
    }

    @Test
    fun `share links, Xray JSON and Clash h2 round-trip http and quic transports`() {
        val uuid = "b1a2c3d4-0000-4000-8000-000000000001"

        // VLESS over http (spelled h2 or http) and quic
        val vlessH2 = ProxyConfiguration.fromUrl(
            "vless://$uuid@example.com:443?type=h2&security=tls&host=a.example.com,b.example.com&path=%2Fh2&method=POST#V"
        )
        assertEquals("http", vlessH2.transport)
        assertEquals(listOf("a.example.com", "b.example.com"), vlessH2.httpTransport?.hosts)
        assertEquals("/h2", vlessH2.httpTransport?.path)
        assertEquals("POST", vlessH2.httpTransport?.method)
        assertEquals("a.example.com", vlessH2.tls?.serverName)
        val vlessH2Reparsed = ProxyConfiguration.fromUrl(vlessH2.toUrl())
        assertEquals(vlessH2.httpTransport, vlessH2Reparsed.httpTransport)
        assertFalse(LatencyTester.listensOnUdp(vlessH2))

        val vlessQuic = ProxyConfiguration.fromUrl("vless://$uuid@example.com:443?type=quic&security=tls#VQ")
        assertEquals("quic", vlessQuic.transport)
        assertTrue(LatencyTester.listensOnUdp(vlessQuic))
        assertEquals("quic", ProxyConfiguration.fromUrl(vlessQuic.toUrl()).transport)

        // Trojan over http and quic
        val trojanQuic = ProxyConfiguration.fromUrl("trojan://secret@example.com:443?type=quic#TQ")
        assertEquals("quic", trojanQuic.transport)
        assertTrue(LatencyTester.listensOnUdp(trojanQuic))
        assertEquals("quic", ProxyConfiguration.fromUrl(trojanQuic.toUrl()).transport)

        // VMess over h2 and quic
        val vmessH2 = vlessH2.copy(outboundProtocol = OutboundProtocol.VMESS)
        val vmessH2Reparsed = ProxyConfiguration.fromUrl(vmessH2.toUrl())
        assertEquals("http", vmessH2Reparsed.transport)
        assertEquals(vlessH2.httpTransport, vmessH2Reparsed.httpTransport)

        val vmessQuic = vlessQuic.copy(outboundProtocol = OutboundProtocol.VMESS)
        assertEquals("quic", ProxyConfiguration.fromUrl(vmessQuic.toUrl()).transport)

        // Xray JSON httpSettings and quicSettings
        val xrayJson = """
        {"outbounds":[
          {"tag":"xh2","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"$uuid"}]}]},
           "streamSettings":{"network":"h2","security":"tls","httpSettings":{"host":["h1.example.com"],"path":"/xp","method":"GET"}}},
          {"tag":"xquic","protocol":"vmess","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"$uuid"}]}]},
           "streamSettings":{"network":"quic","security":"tls","quicSettings":{"security":"none","header":{"type":"none"}}}}
        ]}"""
        val (xh2, xquic) = XrayJsonImporter.parse(xrayJson)
        assertEquals("http", xh2.transport)
        assertEquals(listOf("h1.example.com"), xh2.httpTransport?.hosts)
        assertEquals("/xp", xh2.httpTransport?.path)
        assertEquals("GET", xh2.httpTransport?.method)
        assertEquals("quic", xquic.transport)

        // Clash network: h2 with h2-opts across vless, vmess, trojan
        val clashDoc = JSONObject(
            """
            {"proxies":[
              {"name":"c-vless","type":"vless","server":"example.com","port":443,"uuid":"$uuid","tls":true,"network":"h2",
               "h2-opts":{"host":["c1.example.com","c2.example.com"],"path":"/clash"}},
              {"name":"c-vmess","type":"vmess","server":"example.com","port":443,"uuid":"$uuid","alterId":0,"cipher":"auto","tls":true,"network":"h2",
               "h2-opts":{"host":["vm.example.com"],"path":"/vm"}},
              {"name":"c-trojan","type":"trojan","server":"example.com","port":443,"password":"pw","network":"h2",
               "h2-opts":{"host":["tr.example.com"],"path":"/tr"}}
            ]}
            """.trimIndent()
        )
        val clashConfigs = ClashProxyParser.parseDocument(clashDoc).configurations
        assertEquals(3, clashConfigs.size)
        assertEquals(listOf("c1.example.com", "c2.example.com"), clashConfigs[0].httpTransport?.hosts)
        assertEquals("/clash", clashConfigs[0].httpTransport?.path)
        assertEquals("c1.example.com", clashConfigs[0].tls?.serverName)
        assertEquals("/vm", clashConfigs[1].httpTransport?.path)
        assertEquals("vm.example.com", clashConfigs[1].tls?.serverName)
        assertEquals("/tr", clashConfigs[2].httpTransport?.path)
        assertEquals("tr.example.com", clashConfigs[2].trojanTls?.serverName)
    }
}
