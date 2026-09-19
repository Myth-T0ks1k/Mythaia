package com.mythaia.data.model

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class Subscription(
    @Serializable(with = UuidSerializer::class) val id: UUID = UUID.randomUUID(),
    val name: String,
    val url: String,
    val lastUpdate: Long? = null,
    val upload: Long? = null,
    val download: Long? = null,
    val total: Long? = null,
    val expire: Long? = null,
    val collapsed: Boolean = false,
    /** Whether the user manually renamed this subscription — prevents auto-overwrite on update. */
    val isNameCustomized: Boolean = false,
    /**
     * Domain fronting for the fetch itself.
     *
     * When [frontTargets] is not empty the subscription is downloaded by
     * connecting to each target in turn (a host or IP, optionally `:port`),
     * presenting [frontSni] in the TLS handshake (the URL's own host when
     * null) and the URL's host in the HTTP `Host` header. This gets a panel
     * through a filter that blocks its domain but not the CDN in front of it.
     */
    val frontSni: String? = null,
    val frontTargets: List<String> = emptyList()
) {
    /** Whether the fetch goes through a front rather than straight to the URL. */
    val isFronted: Boolean get() = frontTargets.isNotEmpty()
}
