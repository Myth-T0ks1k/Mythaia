package com.mythaia.data.routing

import kotlinx.serialization.Serializable

/**
 * The routing profiles the user has, and which one is in force.
 *
 * Kept as plain data with pure transitions so the phone and the desktop
 * store it the same way and the rules — Happ's — are tested once:
 *
 *  - a profile is identified by its name; adding one with a name already
 *    there updates it (that is how a provider ships a new version);
 *  - turning a profile on waits for its rule files: until they are on disk
 *    it is [pending] and the previous routing stays in force;
 *  - the files are fetched again once a week, or sooner when the profile's
 *    `LastUpdated` is newer than the files.
 */
@Serializable
data class RoutingProfiles(
    val entries: List<Entry> = emptyList(),
    /** The profile in force, by name; null when none is. */
    val active: String? = null,
    /** Turned on and waiting for its rule files. */
    val pending: String? = null
) {
    @Serializable
    data class Entry(
        val profile: RoutingProfile,
        /** The subscription that sent it; null when the user added it. */
        val subscriptionId: String? = null,
        val subscriptionName: String? = null,
        val addedAt: Long = 0,
        /** When the rule files were last fetched, and for which `LastUpdated`. */
        val filesAt: Long? = null,
        val filesFor: Long? = null,
        /** The last failed fetch, and why; cleared by one that works. */
        val filesTriedAt: Long? = null,
        val filesError: String? = null
    ) {
        val name: String get() = profile.name
    }

    val activeEntry: Entry? get() = active?.let { find(it) }
    val pendingEntry: Entry? get() = pending?.let { find(it) }

    fun find(name: String): Entry? = entries.firstOrNull { it.name.equals(name, ignoreCase = true) }

    /**
     * After [command]. [ready] says whether a profile's files are on disk;
     * [source] is the subscription that sent the command, if any.
     */
    fun apply(
        command: HappRouting.Command,
        now: Long,
        ready: (RoutingProfile) -> Boolean,
        source: Source? = null
    ): RoutingProfiles = when (command) {
        HappRouting.Command.Off -> copy(active = null, pending = null)
        is HappRouting.Command.Add -> {
            val added = upsert(command.profile, now, source)
            if (command.activate) added.activate(command.profile.name, ready) else added
        }
    }

    /** The subscription a command came from. */
    data class Source(val subscriptionId: String, val subscriptionName: String)

    private fun upsert(profile: RoutingProfile, now: Long, source: Source?): RoutingProfiles {
        val old = find(profile.name)
        val entry = if (old == null) {
            Entry(profile, source?.subscriptionId, source?.subscriptionName, addedAt = now)
        } else {
            // The files belong to their URLs: new URLs start over.
            val sameFiles = old.profile.geositeUrl == profile.geositeUrl && old.profile.geoipUrl == profile.geoipUrl
            old.copy(
                profile = profile,
                subscriptionId = source?.subscriptionId ?: old.subscriptionId,
                subscriptionName = source?.subscriptionName ?: old.subscriptionName,
                filesAt = if (sameFiles) old.filesAt else null,
                filesFor = if (sameFiles) old.filesFor else null,
                filesTriedAt = if (sameFiles) old.filesTriedAt else null,
                filesError = if (sameFiles) old.filesError else null
            )
        }
        val rest = entries.filterNot { it.name.equals(profile.name, ignoreCase = true) }
        val list = if (old == null) (rest + entry).takeLast(MAX_PROFILES) else entries.map { if (it === old) entry else it }
        // A rename of the active profile's case keeps it active.
        return copy(
            entries = list,
            active = active?.let { if (it.equals(profile.name, ignoreCase = true)) profile.name else it },
            pending = pending?.let { if (it.equals(profile.name, ignoreCase = true)) profile.name else it }
        ).dropDangling()
    }

    /** Puts [name] in force, or makes it [pending] while its files are missing. */
    fun activate(name: String, ready: (RoutingProfile) -> Boolean): RoutingProfiles {
        val entry = find(name) ?: return this
        return if (ready(entry.profile)) copy(active = entry.name, pending = null)
        else copy(pending = entry.name)
    }

    /** No profile in force, none waiting. */
    fun off(): RoutingProfiles = copy(active = null, pending = null)

    fun remove(name: String): RoutingProfiles =
        copy(entries = entries.filterNot { it.name.equals(name, ignoreCase = true) }).dropDangling()

    /** Drops every profile [subscriptionId] sent, for a deleted subscription. */
    fun removeFrom(subscriptionId: String): RoutingProfiles =
        copy(entries = entries.filterNot { it.subscriptionId == subscriptionId }).dropDangling()

    /**
     * After a fetch of [name]'s files: [error] null when every file arrived.
     * A pending profile goes into force then.
     */
    fun filesFetched(name: String, now: Long, error: String?): RoutingProfiles {
        val entry = find(name) ?: return this
        val updated = if (error == null) {
            entry.copy(filesAt = now, filesFor = entry.profile.lastUpdated, filesTriedAt = now, filesError = null)
        } else {
            entry.copy(filesTriedAt = now, filesError = error.take(300))
        }
        val next = copy(entries = entries.map { if (it === entry) updated else it })
        return if (error == null && pending.equals(entry.name, ignoreCase = true)) next.copy(active = entry.name, pending = null) else next
    }

    /**
     * Whether [entry]'s files should be fetched at [now]: never fetched,
     * a week old, or older than the profile's `LastUpdated`. A fetch that
     * failed is not retried within the hour, unless [force].
     */
    fun filesDue(entry: Entry, now: Long, force: Boolean = false): Boolean {
        if (entry.profile.geoFileUrls.isEmpty()) return false
        if (!force && entry.filesError != null && entry.filesTriedAt != null && now - entry.filesTriedAt < RETRY_MS) return false
        val at = entry.filesAt ?: return true
        if (now - at >= REFRESH_MS || now < at) return true
        val wanted = entry.profile.lastUpdated ?: return false
        return wanted > (entry.filesFor ?: 0L)
    }

    /** Every file URL some profile needs: whatever else is on disk can go. */
    val fileUrls: Set<String> get() = entries.flatMap { it.profile.geoFileUrls }.toSet()

    private fun dropDangling(): RoutingProfiles = copy(
        active = active?.takeIf { name -> entries.any { it.name.equals(name, ignoreCase = true) } },
        pending = pending?.takeIf { name -> entries.any { it.name.equals(name, ignoreCase = true) } }
    )

    companion object {
        const val MAX_PROFILES = 20
        const val REFRESH_MS = 7 * 24 * 60 * 60 * 1000L
        const val RETRY_MS = 60 * 60 * 1000L
    }
}
