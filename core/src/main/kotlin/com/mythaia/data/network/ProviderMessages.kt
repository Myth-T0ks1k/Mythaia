package com.mythaia.data.network

import com.mythaia.data.model.Subscription
import java.security.MessageDigest

/**
 * Which of a subscription's messages deserve a system notification: an
 * `announce` or `sub-info-text` the user has not been notified of yet, and
 * the `sub-expire` warning once it is due. Each text is raised once — its
 * hash is kept with the subscription — so a refresh every hour does not
 * repeat what was already said.
 *
 * Shared by the phone (notification channel "Provider messages") and the
 * desktop (tray balloon); neither needs Google's push service, since the
 * refresh that brings the text is already running.
 */
object ProviderMessages {

    enum class Kind { ANNOUNCE, INFO, EXPIRY }

    data class Message(
        val kind: Kind,
        /** The provider's text; null for [Kind.EXPIRY], which the app words itself. */
        val text: String?,
        /** Where the message's button leads, when it has one. */
        val link: String? = null,
        val linkLabel: String? = null,
        val expiry: Subscription.ExpiryWarning? = null
    )

    /**
     * What [subscription] says at [now] that it has not said before, and the
     * subscription with those messages marked as said.
     */
    fun due(subscription: Subscription, now: Long = System.currentTimeMillis()): Pair<List<Message>, Subscription> {
        val out = ArrayList<Message>()
        var next = subscription

        subscription.announce?.let { text ->
            val hash = hash(text)
            if (hash != subscription.announceShown) {
                out += Message(Kind.ANNOUNCE, text)
                next = next.copy(announceShown = hash)
            }
        }
        subscription.subInfo?.let { info ->
            val hash = hash(info.text)
            if (hash != subscription.infoShown) {
                out += Message(Kind.INFO, info.text, info.buttonLink, info.buttonText)
                next = next.copy(infoShown = hash)
            }
        }
        subscription.expiryWarning(now)?.let { warning ->
            val key = expiryKey(subscription, warning)
            if (key != subscription.expiryShown) {
                out += Message(Kind.EXPIRY, null, subscription.expireButtonLink, expiry = warning)
                next = next.copy(expiryShown = key)
            }
        }
        return out to next
    }

    /**
     * [subscription] with everything it says now marked as said, without a
     * notification: for one the user has just imported and is looking at.
     */
    fun markSeen(subscription: Subscription, now: Long = System.currentTimeMillis()): Subscription = due(subscription, now).second

    private fun expiryKey(subscription: Subscription, warning: Subscription.ExpiryWarning): String =
        "${subscription.expire}:" + if (warning is Subscription.ExpiryWarning.Expired) "expired" else "soon"

    private fun hash(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.trim().toByteArray(Charsets.UTF_8))
            .take(12).joinToString("") { "%02x".format(it) }
}
