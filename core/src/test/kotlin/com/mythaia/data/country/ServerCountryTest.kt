package com.mythaia.data.country

import com.mythaia.data.model.ProxyConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Locale
import java.util.UUID

class ServerCountryTest {

    @Test
    fun `a flag wins, wherever it is`() {
        assertEquals("DE", ServerCountry.fromName("🇩🇪 Frankfurt 01"))
        assertEquals("NL", ServerCountry.fromName("VLESS | Amsterdam 🇳🇱"))
        assertEquals("JP", ServerCountry.fromName("Fast 🇯🇵 node, not 🇺🇸"))
        // A pair that is no region is no flag.
        assertEquals("FI", ServerCountry.fromName("🇿🇿 Helsinki"))
    }

    @Test
    fun `a code at the start reads as the country`() {
        assertEquals("NL", ServerCountry.fromName("[NL] 2"))
        assertEquals("US", ServerCountry.fromName("US-West 3"))
        assertEquals("DE", ServerCountry.fromName("DE1 Premium"))
        assertEquals("GB", ServerCountry.fromName("UK London"))
        assertEquals("IT", ServerCountry.fromName("(IT) Milano"))
    }

    @Test
    fun `country names in several languages, and cities`() {
        assertEquals("DE", ServerCountry.fromName("Германия 3"))
        assertEquals("US", ServerCountry.fromName("United States - Reality"))
        assertEquals("KR", ServerCountry.fromName("south korea xhttp"))
        assertEquals("FI", ServerCountry.fromName("Server in Finland"))
        assertEquals("ES", ServerCountry.fromName("Servidor España 2"))
        assertEquals("NL", ServerCountry.fromName("Нидерланды | grpc"))
        assertEquals("NL", ServerCountry.fromName("Amsterdam 4"))
        assertEquals("DE", ServerCountry.fromName("Frankfurt-am-Main"))
        assertEquals("HK", ServerCountry.fromName("Hong Kong 02"))
        assertEquals("DE", ServerCountry.fromName("德国 01"))
        assertEquals("HK", ServerCountry.fromName("香港节点-03"))
        assertEquals("DE", ServerCountry.fromName("آلمان ۱"))
    }

    @Test
    fun `words that only look like a country are left alone`() {
        // Romania holds "oman"; WS is WebSocket, not Samoa; "IT" mid-name is a word.
        assertEquals("RO", ServerCountry.fromName("Romania"))
        assertNull(ServerCountry.fromName("Server WS 443"))
        assertNull(ServerCountry.fromName("Fast IT node"))
        assertNull(ServerCountry.fromName("My server 1"))
        assertNull(ServerCountry.fromName("vless-reality-01"))
        assertNull(ServerCountry.fromName(""))
    }

    @Test
    fun `flags come out of codes`() {
        assertEquals("🇯🇵", ServerCountry.flag("JP"))
        assertEquals("", ServerCountry.flag("j"))
        assertEquals("", ServerCountry.flag("12"))
    }

    private fun config(name: String) = ProxyConfiguration(
        name = name, serverAddress = "example.com", serverPort = 443u, uuid = UUID.randomUUID(), encryption = "none"
    )

    @Test
    fun `sections by country name, unplaced last, list order kept`() {
        val list = listOf("🇩🇪 1", "🇳🇱 1", "x", "🇩🇪 2", "Austria", "🇳🇱 2").map { config(it) }
        val sections = CountryGrouping.sections(list, { ServerCountry.of(it) }, Locale.ENGLISH)
        assertEquals(listOf("AT", "DE", "NL", null), sections.map { it.code })
        assertEquals(listOf("🇩🇪 1", "🇩🇪 2"), sections[1].items.map { it.name })
        assertEquals(listOf("x"), sections[3].items.map { it.name })
        // In Russian the order follows the Russian names: Австрия, Германия, Нидерланды.
        assertEquals(listOf("AT", "DE", "NL", null), CountryGrouping.sections(list, { ServerCountry.of(it) }, Locale.forLanguageTag("ru")).map { it.code })
        assertEquals("Germany", CountryGrouping.displayName("DE", Locale.ENGLISH))
    }
}
