package com.mythaia.desktop.service

import com.sun.jna.platform.win32.Winsvc
import org.junit.Assert.assertEquals
import org.junit.Test

/** What the service reports to SCM while it starts slowly, runs and stops. */
class ServiceStatusTrackerTest {

    @Test
    fun `a slow start reads as progress, then running takes stop requests`() {
        val tracker = ServiceStatusTracker()
        // Reported before the slow steps, then after each of them.
        val pending = (1..4).map { tracker.next(Winsvc.SERVICE_START_PENDING) }
        assertEquals(listOf(1, 2, 3, 4), pending.map { it.checkPoint })
        pending.forEach {
            assertEquals(ServiceStatusTracker.PENDING_WAIT_HINT_MS, it.waitHintMs)
            assertEquals("no stop while starting", 0, it.controlsAccepted)
        }

        val running = tracker.next(Winsvc.SERVICE_RUNNING)
        assertEquals(0, running.checkPoint)
        assertEquals(0, running.waitHintMs)
        assertEquals(Winsvc.SERVICE_ACCEPT_STOP or Winsvc.SERVICE_ACCEPT_SHUTDOWN, running.controlsAccepted)

        val stopping = tracker.next(Winsvc.SERVICE_STOP_PENDING)
        assertEquals("a new pending state counts from one", 1, stopping.checkPoint)
        assertEquals(0, stopping.controlsAccepted)

        val stopped = tracker.next(Winsvc.SERVICE_STOPPED, exitCode = 1)
        assertEquals(0, stopped.checkPoint)
        assertEquals(0, stopped.waitHintMs)
        assertEquals(1, stopped.exitCode)
    }
}
