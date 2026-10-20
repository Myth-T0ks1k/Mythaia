package com.mythaia.data.country

import java.text.Collator
import java.util.Locale

/** One country's servers in a list grouped by country. [code] is null for the ones nothing could place. */
data class CountrySection<T>(val code: String?, val items: List<T>)

/**
 * The server list cut into countries, shared by the phone and the desktop.
 */
object CountryGrouping {

    /**
     * Splits [items] by [countryOf], each country keeping its servers in
     * list order. Countries sort by their name in [locale]; the servers
     * nothing could place come last. A list that is all one country (or
     * none) comes back as a single section, which callers show as the
     * plain list it is.
     */
    fun <T> sections(
        items: List<T>,
        countryOf: (T) -> String?,
        locale: Locale = Locale.getDefault()
    ): List<CountrySection<T>> {
        val byCode = LinkedHashMap<String?, MutableList<T>>()
        for (item in items) byCode.getOrPut(countryOf(item)) { ArrayList() }.add(item)
        val collator = Collator.getInstance(locale)
        val names = byCode.keys.filterNotNull().associateWith { displayName(it, locale) }
        return byCode.entries
            .sortedWith(compareBy<Map.Entry<String?, MutableList<T>>> { it.key == null }
                .thenComparator { a, b -> collator.compare(names[a.key].orEmpty(), names[b.key].orEmpty()) })
            .map { CountrySection(it.key, it.value) }
    }

    /** "Germany", "Германия": the country's name in [locale], or the code if the platform has none. */
    fun displayName(code: String, locale: Locale = Locale.getDefault()): String =
        Locale.Builder().setRegion(code).build().getDisplayCountry(locale).ifEmpty { code }
}
