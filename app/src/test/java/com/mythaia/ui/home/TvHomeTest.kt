package com.mythaia.ui.home

import android.content.res.Configuration
import com.mythaia.R
import com.mythaia.viewmodel.VpnStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TvHomeTest {

    @Test
    fun `detects television by UiModeManager mode type or leanback feature`() {
        assertTrue(isTelevision(Configuration.UI_MODE_TYPE_TELEVISION, hasLeanbackFeature = false))
        assertTrue(isTelevision(Configuration.UI_MODE_TYPE_NORMAL, hasLeanbackFeature = true))
        assertFalse(isTelevision(Configuration.UI_MODE_TYPE_NORMAL, hasLeanbackFeature = false))
        assertFalse(isTelevision(Configuration.UI_MODE_TYPE_DESK, hasLeanbackFeature = false))
        assertFalse(isTelevision(Configuration.UI_MODE_TYPE_WATCH, hasLeanbackFeature = false))
        assertFalse(isTelevision(Configuration.UI_MODE_TYPE_CAR, hasLeanbackFeature = false))
    }

    @Test
    fun `status label reflects measuring, no internet, and each VPN state`() {
        assertEquals(
            R.string.measuring,
            tvStatusTextRes(VpnStatus.DISCONNECTED, autoSelecting = true, noInternet = false)
        )
        assertEquals(
            R.string.no_connectivity,
            tvStatusTextRes(VpnStatus.CONNECTED, autoSelecting = false, noInternet = true)
        )
        assertEquals(
            R.string.connected,
            tvStatusTextRes(VpnStatus.CONNECTED, autoSelecting = true, noInternet = false)
        )
        assertEquals(
            R.string.connecting,
            tvStatusTextRes(VpnStatus.CONNECTING, autoSelecting = false, noInternet = false)
        )
        assertEquals(
            R.string.disconnecting,
            tvStatusTextRes(VpnStatus.DISCONNECTING, autoSelecting = false, noInternet = false)
        )
        assertEquals(
            R.string.reconnecting,
            tvStatusTextRes(VpnStatus.REASSERTING, autoSelecting = false, noInternet = false)
        )
        assertEquals(
            R.string.disconnected,
            tvStatusTextRes(VpnStatus.DISCONNECTED, autoSelecting = false, noInternet = false)
        )
    }

    @Test
    fun `primary action offers add when empty, disconnect while active or connecting, and connect when idle`() {
        assertEquals(
            R.string.add_a_configuration,
            tvConnectActionRes(hasNoConfigurations = true, VpnStatus.DISCONNECTED, autoSelecting = false)
        )
        assertEquals(
            R.string.connect,
            tvConnectActionRes(hasNoConfigurations = false, VpnStatus.DISCONNECTED, autoSelecting = false)
        )
        assertEquals(
            R.string.disconnect,
            tvConnectActionRes(hasNoConfigurations = false, VpnStatus.CONNECTING, autoSelecting = false)
        )
        assertEquals(
            R.string.disconnect,
            tvConnectActionRes(hasNoConfigurations = false, VpnStatus.CONNECTED, autoSelecting = false)
        )
        assertEquals(
            R.string.disconnect,
            tvConnectActionRes(hasNoConfigurations = false, VpnStatus.REASSERTING, autoSelecting = false)
        )
        assertEquals(
            R.string.disconnect,
            tvConnectActionRes(hasNoConfigurations = false, VpnStatus.DISCONNECTED, autoSelecting = true)
        )
    }
}
