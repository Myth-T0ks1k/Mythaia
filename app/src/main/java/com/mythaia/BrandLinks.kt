package com.mythaia

/**
 * External links surfaced in the UI.
 *
 * Centralised so the brand can be re-pointed in one place.
 */
object BrandLinks {

    /**
     * Community chat opened from Settings, or null while there is none.
     *
     * Null is the deliberate default: the row it drives hides itself rather
     * than sending a Mythaia user to somebody else's group. Set this to the
     * Mythaia invite and the row comes back on its own.
     */
    val TELEGRAM_COMMUNITY: String? = null

    /** Whether the Settings row for [TELEGRAM_COMMUNITY] should be shown at all. */
    val hasCommunityLink: Boolean
        get() = !TELEGRAM_COMMUNITY.isNullOrBlank()
}
