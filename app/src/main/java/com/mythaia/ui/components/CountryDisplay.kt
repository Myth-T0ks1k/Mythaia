package com.mythaia.ui.components

import java.util.Locale

/**
 * Turning an ISO 3166-1 alpha-2 code into something a person reads.
 *
 * Shared by onboarding and settings, which show the same country list.
 */

/** The flag emoji for [code], built from the two regional-indicator letters. */
fun flagForCountryCode(code: String): String {
    if (code.length < 2) return ""
    val first = Character.toChars(0x1F1E6 - 'A'.code + code[0].uppercaseChar().code)
    val second = Character.toChars(0x1F1E6 - 'A'.code + code[1].uppercaseChar().code)
    return String(first) + String(second)
}

/**
 * A locale carrying only [code] as its region, for [Locale.getDisplayCountry].
 *
 * Built rather than constructed: `Locale("", code)` is deprecated, and the
 * builder is the replacement that does not guess at a language.
 */
fun localeForRegion(code: String): Locale =
    Locale.Builder().setRegion(code).build()

/** "🇯🇵 Japan" — the flag and the country name in the reader's own language. */
fun countryDisplayName(code: String): String =
    "${flagForCountryCode(code)} ${localeForRegion(code).displayCountry}"
