package com.mythaia.data.model

import android.content.SharedPreferences

/** Which apps the tunnel carries. */
enum class SplitTunnelMode(val raw: String) {
    /** Every app goes through the tunnel. */
    OFF("off"),

    /** Only the selected apps go through the tunnel; everything else is direct. */
    ALLOW("allow"),

    /** The selected apps go direct; everything else goes through the tunnel. */
    DISALLOW("disallow");

    companion object {
        fun fromRaw(raw: String?): SplitTunnelMode =
            entries.firstOrNull { it.raw == raw } ?: OFF
    }
}

/**
 * Per-app split tunnelling, applied through `VpnService.Builder`'s
 * `addAllowedApplication` / `addDisallowedApplication`.
 *
 * Android-only: iOS gives a network extension no equivalent control.
 */
data class SplitTunnelSettings(
    val mode: SplitTunnelMode = SplitTunnelMode.OFF,
    val packages: Set<String> = emptySet()
) {

    /**
     * Whether the builder should be told anything at all.
     *
     * An ALLOW list with nothing in it would establish a tunnel that carries no
     * app's traffic, which reads as a broken VPN rather than as a setting; a
     * DISALLOW list with nothing in it is just the default. Both collapse to
     * "carry everything".
     */
    val isActive: Boolean
        get() = mode != SplitTunnelMode.OFF && packages.isNotEmpty()

    companion object {
        const val KEY_MODE = "splitTunnelMode"
        const val KEY_PACKAGES = "splitTunnelPackages"

        fun read(prefs: SharedPreferences): SplitTunnelSettings = SplitTunnelSettings(
            mode = SplitTunnelMode.fromRaw(prefs.getString(KEY_MODE, SplitTunnelMode.OFF.raw)),
            // getStringSet hands back an instance that must not be mutated and
            // whose contents are undefined after a later edit, so copy it.
            packages = prefs.getStringSet(KEY_PACKAGES, emptySet())?.toSet() ?: emptySet()
        )

        fun write(prefs: SharedPreferences, settings: SplitTunnelSettings) {
            prefs.edit()
                .putString(KEY_MODE, settings.mode.raw)
                .putStringSet(KEY_PACKAGES, settings.packages.toSet())
                .apply()
        }
    }
}
