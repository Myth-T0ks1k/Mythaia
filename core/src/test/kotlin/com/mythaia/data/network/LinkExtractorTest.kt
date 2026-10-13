package com.mythaia.data.network

import org.junit.Assert.assertEquals
import org.junit.Test

class LinkExtractorTest {

    @Test
    fun `links come out of a chat message`() {
        val text = """
            Привет! Твой ключ: vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main.
            Запасной (на всякий): hysteria2://pass@1.2.3.4:443?sni=x.com#Backup, и подписка
            «https://sub.example.com/abc?token=1» — обновляй раз в день!
        """.trimIndent()
        assertEquals(
            listOf(
                "vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main",
                "hysteria2://pass@1.2.3.4:443?sni=x.com#Backup",
                "https://sub.example.com/abc?token=1"
            ),
            LinkExtractor.extract(text)
        )
    }

    @Test
    fun `other clients' import links are unwrapped`() {
        assertEquals(listOf("https://sub.example.com/x"), LinkExtractor.extract("happ://add/https://sub.example.com/x"))
        assertEquals(
            listOf("https://sub.example.com/a?b=c"),
            LinkExtractor.extract("v2rayng://install-config?url=https%3A%2F%2Fsub.example.com%2Fa%3Fb%3Dc")
        )
        assertEquals(
            listOf("https://s.example.com/p"),
            LinkExtractor.extract("sing-box://import-remote-profile?url=https%3A%2F%2Fs.example.com%2Fp#name=My")
        )
    }

    @Test
    fun `a letter that grows when lowercased does not shift the link`() {
        // "İ".lowercase() is two chars, so an offset found in a lowercased
        // copy of the text landed one char into every link after it.
        val link = "vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main"
        assertEquals(listOf(link), LinkExtractor.extract("İşte: $link"))
        assertEquals(listOf(link), LinkExtractor.extract("İİİ $link İİİ"))
    }

    @Test
    fun `a vmess link is not mistaken for shadowsocks and duplicates collapse`() {
        val vmess = "vmess://eyJhZGQiOiIxLjIuMy40In0="
        assertEquals(listOf(vmess), LinkExtractor.extract("$vmess\n$vmess"))
        assertEquals(listOf("ss://YWVzOnBhc3M@1.2.3.4:8388#a"), LinkExtractor.extract("(ss://YWVzOnBhc3M@1.2.3.4:8388#a)"))
    }
}
