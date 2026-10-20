package com.mythaia.data.country

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.GeoIpDatabase
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * Which country a server is in, for grouping the server list.
 *
 * The name says it first — providers lead with a flag, an ISO code or the
 * country written out ("🇩🇪 Frankfurt", "[NL] 2", "Германия 3", "德国 01") —
 * and the name is what the user sees, so it wins. Only a name that says
 * nothing falls back to the GeoIP database (the user's own, when one is
 * imported), and only for an address already known: a literal, the
 * resolved IP a link carried, or one the DNS cache holds. Grouping a list
 * never sends a DNS query.
 */
object ServerCountry {

    /** ISO 3166-1 alpha-2, uppercase; null when nothing says where the server is. */
    fun of(config: ProxyConfiguration): String? = fromName(config.name) ?: fromAddress(config)

    /**
     * Auto's [candidates] kept to [country] when the user asked for Auto
     * within one country — all of them again once that country has none
     * left, so Auto never ends up with nothing to choose from.
     */
    fun keepTo(candidates: List<ProxyConfiguration>, country: String?): List<ProxyConfiguration> {
        if (country == null) return candidates
        return candidates.filter { of(it) == country }.ifEmpty { candidates }
    }

    fun fromAddress(config: ProxyConfiguration): String? {
        if (!GeoIpDatabase.isLoaded) return null
        val ip = config.resolvedIP?.takeIf { DnsCache.isIpAddress(it) }
            ?: config.serverAddress.trim('[', ']').takeIf { DnsCache.isIpAddress(it) }
            ?: DnsCache.cachedIPs(config.serverAddress)?.firstOrNull()
            ?: return null
        return GeoIpDatabase.countryCode(ip)?.uppercase()?.takeIf { it in codes }
    }

    /** Names repeat across refreshes and recompositions; the answer for one never changes. */
    private val nameCache = ConcurrentHashMap<String, String>()
    private const val NONE = ""
    private const val MAX_CACHE = 20_000

    fun fromName(name: String): String? {
        nameCache[name]?.let { return it.ifEmpty { null } }
        val code = detect(name)
        if (nameCache.size >= MAX_CACHE) nameCache.clear()
        nameCache[name] = code ?: NONE
        return code
    }

    /** "🇯🇵" for "JP". */
    fun flag(code: String): String {
        if (code.length != 2 || !code.all { it in 'A'..'Z' }) return ""
        return String(Character.toChars(FLAG_A + (code[0] - 'A'))) + String(Character.toChars(FLAG_A + (code[1] - 'A')))
    }

    private fun detect(name: String): String? {
        flagCode(name)?.let { return it }
        LEADING_CODE.find(name)?.let { match ->
            normalizeCode(match.groupValues[1])?.let { return it }
        }
        val words = words(name)
        byWords(words)?.let { return it }
        if (name.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }) {
            for ((text, code) in hanNames) if (name.contains(text)) return code
        }
        for (match in ANY_CODE.findAll(name)) {
            val token = match.groupValues[1]
            if (token in AMBIGUOUS_CODES) continue
            normalizeCode(token)?.let { return it }
        }
        return null
    }

    private const val FLAG_A = 0x1F1E6
    private const val FLAG_Z = 0x1F1FF

    /** A pair of regional-indicator letters, if the name holds one that is a real region. */
    private fun flagCode(text: String): String? {
        var i = 0
        while (i < text.length) {
            val cp = text.codePointAt(i)
            val width = Character.charCount(cp)
            if (cp in FLAG_A..FLAG_Z && i + width < text.length) {
                val next = text.codePointAt(i + width)
                if (next in FLAG_A..FLAG_Z) {
                    val code = "${'A' + (cp - FLAG_A)}${'A' + (next - FLAG_A)}"
                    normalizeCode(code)?.let { return it }
                    i += width + Character.charCount(next)
                    continue
                }
            }
            i += width
        }
        return null
    }

    /** "[DE] …", "DE-1", "(US) …", "NL2 …": a code at the very start is the strongest plain-text sign. */
    private val LEADING_CODE = Regex("^[^\\p{L}\\p{N}]*([A-Z]{2})(?!\\p{L})")

    /** A standalone uppercase code anywhere: weaker, so the ones that double as words are skipped. */
    private val ANY_CODE = Regex("(?<!\\p{L})([A-Z]{2})(?!\\p{L})")

    /** Codes that mean something else in a server name: WebSocket, a TV box, AI, AM/PM, a CC. */
    private val AMBIGUOUS_CODES = setOf("WS", "TV", "AI", "AM", "PM", "CC", "IP", "ID", "IN", "IS", "IT", "ME", "MY", "NO", "SO", "TO", "BE", "DO", "GO", "OR", "AS", "AT", "BY", "ON", "UP")

    private val codes: Set<String> = Locale.getISOCountries().toHashSet() + "XK"

    private fun normalizeCode(code: String): String? {
        val upper = code.uppercase(Locale.ROOT)
        return when (upper) {
            "UK" -> "GB"
            in codes -> upper
            else -> null
        }
    }

    /** Lowercase words, split on anything that is not a letter (digits, emoji and punctuation alike). */
    private fun words(text: String): List<String> {
        val out = ArrayList<String>()
        val current = StringBuilder()
        for (ch in text) {
            if (Character.isLetter(ch) || ch == '\'' && current.isNotEmpty()) {
                current.append(ch.lowercaseChar())
            } else if (current.isNotEmpty()) {
                out += current.toString()
                current.setLength(0)
            }
        }
        if (current.isNotEmpty()) out += current.toString()
        return out
    }

    private const val MAX_NAME_WORDS = 4

    /** The longest country or city name the words spell, scanning left to right. */
    private fun byWords(words: List<String>): String? {
        for (start in words.indices) {
            for (length in minOf(MAX_NAME_WORDS, words.size - start) downTo 1) {
                val phrase = if (length == 1) words[start] else words.subList(start, start + length).joinToString(" ")
                names[phrase]?.let { return it }
            }
        }
        return null
    }

    /**
     * Every country's name in the languages server lists are written in,
     * from the platform's own locale data, plus the short and old names
     * people use and the cities servers are usually named after.
     */
    private val names: Map<String, String> by lazy {
        val map = HashMap<String, String>()
        val languages = listOf(Locale.ENGLISH, Locale.forLanguageTag("ru"), Locale.forLanguageTag("es"), Locale.forLanguageTag("fa"))
        for (code in codes) {
            val region = Locale.Builder().setRegion(code).build()
            for (language in languages) {
                val display = region.getDisplayCountry(language).lowercase(language)
                if (display.isEmpty() || display.equals(code, ignoreCase = true)) continue
                val phrase = words(display).joinToString(" ")
                // Short names are too often ordinary words ("Ý", "Anh", "Чад").
                if (phrase.length >= 4 && phrase.split(' ').size <= MAX_NAME_WORDS) map.putIfAbsent(phrase, code)
            }
        }
        for ((alias, code) in ALIASES) map[alias] = code
        for ((city, code) in CITIES) map.putIfAbsent(city, code)
        map
    }

    /** Chinese names, matched inside the text: Chinese has no spaces to split words on. */
    private val hanNames: List<Pair<String, String>> by lazy {
        val zh = Locale.forLanguageTag("zh-CN")
        val list = codes.mapNotNull { code ->
            val display = Locale.Builder().setRegion(code).build().getDisplayCountry(zh)
            if (display.length >= 2 && display.any { Character.UnicodeScript.of(it.code) == Character.UnicodeScript.HAN }) display to code
            else null
        } + HAN_ALIASES
        // Longer first, so 香港 is not read as something shorter inside it.
        list.sortedByDescending { it.first.length }
    }

    private val ALIASES = mapOf(
        "usa" to "US", "america" to "US", "united states of america" to "US",
        "uk" to "GB", "britain" to "GB", "great britain" to "GB", "england" to "GB", "scotland" to "GB",
        "wales" to "GB", "london" to "GB",
        "holland" to "NL", "dutch" to "NL",
        "deutschland" to "DE", "german" to "DE",
        "korea" to "KR", "south korea" to "KR",
        "uae" to "AE", "emirates" to "AE", "dubai" to "AE",
        "czech" to "CZ", "czech republic" to "CZ",
        "turkey" to "TR", "türkiye" to "TR", "turkiye" to "TR",
        "hong kong" to "HK", "hongkong" to "HK",
        "macau" to "MO", "macao" to "MO",
        "taiwan" to "TW",
        "russia" to "RU", "russian federation" to "RU",
        "vietnam" to "VN", "viet nam" to "VN",
        "сша" to "US", "америка" to "US", "штаты" to "US",
        "англия" to "GB", "британия" to "GB",
        "голландия" to "NL",
        "корея" to "KR", "южная корея" to "KR",
        "оаэ" to "AE", "эмираты" to "AE",
        "чехия" to "CZ", "турция" to "TR", "гонконг" to "HK", "тайвань" to "TW",
        "молдавия" to "MD", "киргизия" to "KG", "белоруссия" to "BY",
        "آمریکا" to "US", "امریکا" to "US", "انگلیس" to "GB", "هلند" to "NL", "آلمان" to "DE", "ترکیه" to "TR",
        "امارات" to "AE", "فرانسه" to "FR", "فنلاند" to "FI", "روسیه" to "RU", "کانادا" to "CA", "ژاپن" to "JP"
    )

    private val HAN_ALIASES = listOf(
        "美国" to "US", "美國" to "US", "英国" to "GB", "英國" to "GB", "德国" to "DE", "德國" to "DE",
        "日本" to "JP", "香港" to "HK", "台湾" to "TW", "台灣" to "TW", "新加坡" to "SG", "狮城" to "SG",
        "韩国" to "KR", "韓國" to "KR", "俄罗斯" to "RU", "荷兰" to "NL", "法国" to "FR", "澳门" to "MO"
    )

    private val CITIES = mapOf(
        "amsterdam" to "NL", "rotterdam" to "NL", "frankfurt" to "DE", "berlin" to "DE", "munich" to "DE",
        "münchen" to "DE", "nuremberg" to "DE", "falkenstein" to "DE", "düsseldorf" to "DE", "dusseldorf" to "DE",
        "hamburg" to "DE", "manchester" to "GB", "paris" to "FR", "marseille" to "FR", "helsinki" to "FI",
        "stockholm" to "SE", "oslo" to "NO", "copenhagen" to "DK", "warsaw" to "PL", "prague" to "CZ",
        "vienna" to "AT", "zurich" to "CH", "zürich" to "CH", "geneva" to "CH", "milan" to "IT", "rome" to "IT",
        "madrid" to "ES", "barcelona" to "ES", "lisbon" to "PT", "bucharest" to "RO", "sofia" to "BG",
        "budapest" to "HU", "kyiv" to "UA", "kiev" to "UA", "moscow" to "RU", "petersburg" to "RU",
        "istanbul" to "TR", "almaty" to "KZ", "astana" to "KZ", "tokyo" to "JP", "osaka" to "JP",
        "seoul" to "KR", "taipei" to "TW", "mumbai" to "IN", "bangalore" to "IN", "delhi" to "IN",
        "sydney" to "AU", "melbourne" to "AU", "toronto" to "CA", "montreal" to "CA", "vancouver" to "CA",
        "sao paulo" to "BR", "são paulo" to "BR", "tel aviv" to "IL", "dublin" to "IE", "tallinn" to "EE",
        "riga" to "LV", "vilnius" to "LT", "tbilisi" to "GE", "yerevan" to "AM", "tashkent" to "UZ",
        "bishkek" to "KG", "new york" to "US", "los angeles" to "US", "chicago" to "US", "dallas" to "US",
        "miami" to "US", "seattle" to "US", "san jose" to "US", "ashburn" to "US", "atlanta" to "US",
        "silicon valley" to "US", "johannesburg" to "ZA",
        "амстердам" to "NL", "франкфурт" to "DE", "берлин" to "DE", "мюнхен" to "DE", "лондон" to "GB",
        "париж" to "FR", "хельсинки" to "FI", "стокгольм" to "SE", "варшава" to "PL", "прага" to "CZ",
        "вена" to "AT", "москва" to "RU", "петербург" to "RU", "стамбул" to "TR", "алматы" to "KZ",
        "астана" to "KZ", "токио" to "JP", "сеул" to "KR", "нью йорк" to "US", "рига" to "LV", "таллин" to "EE"
    )
}
