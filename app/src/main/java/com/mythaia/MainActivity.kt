package com.mythaia

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.mythaia.ui.navigation.AppNavigation
import com.mythaia.ui.onboarding.OnboardingScreen
import com.mythaia.ui.theme.MythaiaTheme
import com.mythaia.viewmodel.VpnStatus
import com.mythaia.viewmodel.VpnViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: VpnViewModel by viewModels()

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        } else {
            viewModel.onVpnPermissionDenied()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        viewModel.onRequestVpnPermission = { intent ->
            vpnPermissionLauncher.launch(intent)
        }

        handleDeepLinkIntent(intent)
        handleConnectIntent(intent)

        setContent {
            MythaiaTheme {
                var onboardingCompleted by remember { mutableStateOf(viewModel.hasCompletedOnboarding) }

                if (!onboardingCompleted) {
                    OnboardingScreen(
                        onComplete = { bypassCountryCode, adBlockEnabled ->
                            viewModel.completeOnboarding(bypassCountryCode, adBlockEnabled)
                            onboardingCompleted = true
                        }
                    )
                } else {
                    AppNavigation(viewModel = viewModel)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLinkIntent(intent)
        handleConnectIntent(intent)
    }

    private fun handleDeepLinkIntent(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        viewModel.onDeepLink(uri)
    }

    /**
     * Connects on behalf of the Quick Settings tile or the widget, which can
     * neither show the VPN consent dialog nor run the routing sync a connect
     * needs.
     *
     * The action is cleared once handled so a configuration change — a rotation,
     * a theme switch — does not replay it.
     */
    private fun handleConnectIntent(intent: Intent?) {
        if (intent?.action != ACTION_CONNECT) return
        intent.action = null
        if (viewModel.vpnStatus.value == VpnStatus.DISCONNECTED) {
            viewModel.connect()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.onRequestVpnPermission = null
    }

    companion object {
        /** Asks the app to bring the tunnel up, from outside the app. */
        const val ACTION_CONNECT = "com.mythaia.CONNECT"
    }
}
