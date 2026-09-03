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
        handleDeepLinkIntent(intent)
    }

    private fun handleDeepLinkIntent(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        viewModel.onDeepLink(uri)
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.onRequestVpnPermission = null
    }
}
