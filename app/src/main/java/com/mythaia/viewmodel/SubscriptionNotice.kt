package com.mythaia.viewmodel

import java.util.UUID

/**
 * What the bar at the bottom of the screen says about a subscription refresh.
 * Each one goes away on its own after a while.
 */
sealed class SubscriptionNotice {
    abstract val subscriptionId: UUID
    abstract val name: String

    /** The refresh failed; [canRetry] offers the download through a server that works. */
    data class Failed(
        override val subscriptionId: UUID,
        override val name: String,
        val message: String,
        val canRetry: Boolean
    ) : SubscriptionNotice()

    /** Looking for a working server and fetching through it. */
    data class Retrying(override val subscriptionId: UUID, override val name: String) : SubscriptionNotice()

    /** Updated through [server]. */
    data class UpdatedThrough(
        override val subscriptionId: UUID,
        override val name: String,
        val server: String
    ) : SubscriptionNotice()

    /**
     * A Happ routing link was opened or pasted: profile [profile] added (and
     * turned on with [active]), or routing profiles turned off when it is null.
     */
    data class Routing(val profile: String?, val active: Boolean) : SubscriptionNotice() {
        override val subscriptionId: UUID get() = UUID(0, 0)
        override val name: String get() = profile ?: ""
    }
}
