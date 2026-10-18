package com.mythaia.desktop.model

import com.mythaia.data.model.DomainRuleType
import kotlinx.serialization.Serializable

/** Everything the desktop app remembers besides servers and subscriptions. */
@Serializable
data class DesktopSettings(
    val socksPort: Int = 10808,
    val httpPort: Int = 10809,
    val allowLan: Boolean = false,
    val socksUdp: Boolean = true,

    val setSystemProxy: Boolean = true,
    val proxyBypass: String = DEFAULT_BYPASS,
    val launchAtLogin: Boolean = false,
    val startMinimized: Boolean = false,
    val closeToTray: Boolean = true,
    val autoConnect: Boolean = false,

    /** `rule` or `global`. */
    val routeMode: String = "rule",
    val bypassTurkmenistan: Boolean = true,

    /** The group whose selection is live: `default` or a subscription id. */
    val activeGroupId: String = "default",
    /** Group id -> pinned configuration id. No entry means Auto. */
    val groupPins: Map<String, String> = emptyMap(),
    /** Group id -> the server Auto last settled on, to connect to at once. */
    val autoChoices: Map<String, String> = emptyMap(),
    /** A chain chosen as the outbound instead of a group's server; null for none. */
    val selectedChainId: String? = null,
    /** `proxy` (local SOCKS/HTTP + system proxy) or `tun` (Wintun, all traffic). */
    val tunnelMode: String = "proxy",

    val fragmentEnabled: Boolean = true,
    val fragmentMinLength: Int = 100,
    val fragmentMaxLength: Int = 200,
    val fragmentMinInterval: Int = 10,
    val fragmentMaxInterval: Int = 20,
    val allowInsecure: Boolean = false,

    val dohEnabled: Boolean = false,
    val dohUrl: String = "https://1.1.1.1/dns-query",

    /** `auto`, `ru` or `en`. */
    val language: String = "auto",
    /** `system`, `light` or `dark`. */
    val theme: String = "system",

    /** Hours between automatic subscription refreshes; 0 turns them off. */
    val subscriptionUpdateHours: Int = 12,

    /** Asks GitHub for a new release once a day. Off until the user turns it on. */
    val updateAutoCheck: Boolean = false,
    val updateLastCheck: Long = 0,
    /** The release the daily check already announced, so it is announced once. */
    val updateDismissedTag: String? = null,

    val windowWidth: Int = 1120,
    val windowHeight: Int = 740
) {
    val isGlobal: Boolean get() = routeMode == "global"

    companion object {
        const val DEFAULT_BYPASS =
            "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*;<local>"
    }
}

/** Where a connection goes. */
@Serializable
enum class RouteTarget { PROXY, DIRECT, BLOCK }

/** One user routing rule: a match and what to do with it. */
@Serializable
data class RouteRule(
    val type: DomainRuleType,
    val value: String,
    val action: RouteTarget
)
