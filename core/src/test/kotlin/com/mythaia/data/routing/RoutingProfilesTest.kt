package com.mythaia.data.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingProfilesTest {

    private val withFiles = RoutingProfile(
        name = "Russia",
        directSites = listOf("geosite:category-ru"),
        geositeUrl = "https://example.com/geosite.dat"
    )
    private val plain = RoutingProfile(name = "Plain", directIp = listOf("10.0.0.0/8"))
    private val now = 1_000_000_000_000L
    private val day = 24 * 60 * 60 * 1000L

    private fun add(state: RoutingProfiles, profile: RoutingProfile, activate: Boolean, ready: Boolean = false) =
        state.apply(HappRouting.Command.Add(profile, activate), now, { ready || it.geoFileUrls.isEmpty() })

    @Test
    fun `a profile without files goes into force at once`() {
        val state = add(RoutingProfiles(), plain, activate = true)
        assertEquals("Plain", state.active)
        assertNull(state.pending)
        assertFalse(state.filesDue(state.activeEntry!!, now))
    }

    @Test
    fun `turning one on waits for its files, keeping the previous one`() {
        var state = add(RoutingProfiles(), plain, activate = true)
        state = add(state, withFiles, activate = true)
        assertEquals("Plain", state.active)
        assertEquals("Russia", state.pending)
        assertTrue(state.filesDue(state.pendingEntry!!, now))

        val failed = state.filesFetched("Russia", now, "HTTP 404")
        assertEquals("Plain", failed.active)
        assertEquals("HTTP 404", failed.find("russia")!!.filesError)
        // No retry within the hour unless asked.
        assertFalse(failed.filesDue(failed.pendingEntry!!, now + 60_000))
        assertTrue(failed.filesDue(failed.pendingEntry!!, now + 60_000, force = true))

        val fetched = failed.filesFetched("Russia", now, null)
        assertEquals("Russia", fetched.active)
        assertNull(fetched.pending)
        assertNull(fetched.activeEntry!!.filesError)
    }

    @Test
    fun `adding without turning on leaves routing as it was`() {
        val state = add(RoutingProfiles(), withFiles, activate = false)
        assertNull(state.active)
        assertNull(state.pending)
        assertEquals(1, state.entries.size)
    }

    @Test
    fun `the same name updates the profile and keeps its files while the URLs stay`() {
        var state = add(RoutingProfiles(), withFiles, activate = true, ready = true)
        state = state.filesFetched("Russia", now, null)
        val updated = withFiles.copy(name = "RUSSIA", directSites = listOf("geosite:category-ru", "domain:extra.ru"))
        state = add(state, updated, activate = false)
        assertEquals(1, state.entries.size)
        assertEquals("RUSSIA", state.active)
        assertEquals(2, state.activeEntry!!.profile.directSites.size)
        assertEquals(now, state.activeEntry!!.filesAt)

        val moved = add(state, updated.copy(geositeUrl = "https://elsewhere.example/geosite.dat"), activate = false)
        assertNull(moved.activeEntry!!.filesAt)
    }

    @Test
    fun `files are fetched again weekly or when LastUpdated is newer`() {
        var state = add(RoutingProfiles(), withFiles.copy(lastUpdated = 100), activate = true, ready = true)
        state = state.filesFetched("Russia", now, null)
        val entry = state.activeEntry!!
        assertFalse(state.filesDue(entry, now + day))
        assertTrue(state.filesDue(entry, now + 8 * day))
        state = add(state, withFiles.copy(lastUpdated = 200), activate = false)
        assertTrue(state.filesDue(state.activeEntry!!, now + day))
    }

    @Test
    fun `off, remove, and a deleted subscription's profiles`() {
        var state = RoutingProfiles().apply(
            HappRouting.Command.Add(plain, true), now, { true },
            RoutingProfiles.Source("sub-1", "Provider")
        )
        assertEquals("sub-1", state.activeEntry!!.subscriptionId)
        assertNull(state.apply(HappRouting.Command.Off, now, { true }).active)
        state = state.removeFrom("sub-1")
        assertTrue(state.entries.isEmpty())
        assertNull(state.active)
        assertEquals(0, add(add(RoutingProfiles(), plain, true), withFiles, false).remove("plain").entries.count { it.name == "Plain" })
    }
}
