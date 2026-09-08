package com.mythaia.vpn.mitm

/**
 * A parsed `.amrs` rule set: a display [name], the `hostname` [domainSuffixes]
 * that gate which hosts are intercepted, and the ordered [rules].
 *
 * This is the unit of configuration a `.amrs` file describes. Which set applies
 * to a given connection (suffix matching, most-specific-wins) is a decision for
 * the session layer, not for this model or [MitmRewriter]: the rewriter is a
 * pure transform over a set that has already been selected for the host, so
 * [domainSuffixes] is carried for that upstream selector and is not consulted
 * when rules are applied.
 *
 * `parameters`, `icon-*`, and the JavaScript operations of the format are not
 * modelled — they exist only to feed the script engine, which this port does
 * not include (see [AmrsParser]). The [MAX_RULE_COUNT] cap is exposed for the
 * storage/subscription layer to enforce; the parser itself never truncates,
 * mirroring the reference parser, which returns everything it could read and
 * leaves the cap to the store.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
data class MitmRuleSet(
    val name: String,
    val domainSuffixes: List<String>,
    val rules: List<MitmRule>
) {
    companion object {
        /** Hard cap the reference enforces per set; import/subscription past it is rejected in full. */
        const val MAX_RULE_COUNT = 10_000
    }
}
