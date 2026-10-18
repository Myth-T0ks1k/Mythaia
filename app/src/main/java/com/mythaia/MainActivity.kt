package com.mythaia

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.core.content.ContextCompat
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import com.mythaia.data.model.ThemeMode
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

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* The connect proceeds either way; a refusal only hides the notification. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        viewModel.onRequestVpnPermission = { intent ->
            vpnPermissionLauncher.launch(intent)
        }
        viewModel.onRequestNotificationPermission = {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                PackageManager.PERMISSION_GRANTED
            ) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        // Only on a fresh launch. After process death Android hands onCreate
        // the original intent again, mutation and all, and replaying it
        // would connect unasked or reopen the Add sheet.
        if (savedInstanceState == null) {
            handleDeepLinkIntent(intent)
            handleConnectIntent(intent)
        }

        setContent {
            val themeMode by viewModel.themeMode.collectAsState()
            val darkTheme = when (themeMode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            // The status and navigation bar icons have to match the palette
            // the app draws, not the device's: pinned to dark on a light
            // device, the default detection would paint dark icons on the
            // dark ground and lose them.
            LaunchedEffect(darkTheme) {
                val transparent = android.graphics.Color.TRANSPARENT
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.auto(transparent, transparent) { darkTheme },
                    navigationBarStyle = SystemBarStyle.auto(transparent, transparent) { darkTheme }
                )
                // With three-button navigation Android lays a white scrim over
                // the app for contrast, which showed as a white band under the
                // navigation bar. The bar is solid and runs under the buttons
                // itself, so the contrast is already there.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    window.isNavigationBarContrastEnforced = false
                }
            }
            MythaiaTheme(darkTheme = darkTheme) {
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
        // Consumed: the view model outlives a recreation, and replaying the
        // link on every rotation would reopen the Add sheet each time.
        intent.action = null
        intent.data = null
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

    override fun onStart() {
        super.onStart()
        viewModel.setUiVisible(true)
        // Only when the user turned the daily check on; at most once a day.
        com.mythaia.data.update.AppUpdater.get(this).checkIfDue()
    }

    override fun onStop() {
        viewModel.setUiVisible(false)
        super.onStop()
    }

    override fun onDestroy() {
        super.onDestroy()
        viewModel.onRequestVpnPermission = null
        viewModel.onRequestNotificationPermission = null
    }

    companion object {
        /** Asks the app to bring the tunnel up, from outside the app. */
        const val ACTION_CONNECT = "com.mythaia.CONNECT"
    }
}
