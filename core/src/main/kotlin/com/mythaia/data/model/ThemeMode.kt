package com.mythaia.data.model

/** Which palette the app draws in. */
enum class ThemeMode(val raw: String) {
    /** Follow the device. */
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark");

    companion object {
        fun fromRaw(raw: String?): ThemeMode =
            entries.firstOrNull { it.raw == raw } ?: SYSTEM

        const val KEY = "themeMode"
    }
}
