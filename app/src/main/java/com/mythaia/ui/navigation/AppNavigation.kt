package com.mythaia.ui.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.mythaia.R
import com.mythaia.ui.components.SubscriptionNoticeBar
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.home.HomeScreen
import com.mythaia.ui.proxy.ProxyListScreen
import com.mythaia.ui.settings.SettingsScreen
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.serialization.Serializable

@Serializable object HomeRoute
@Serializable object ProxiesRoute
@Serializable object SettingsRoute

data class TopLevelRoute(
    val titleResId: Int,
    val route: Any,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

/**
 * Three destinations, Home, Proxies and Settings, in Material 3's navigation
 * bar (a rail on wide windows). Chains live inside Proxies as a tab.
 *
 * Settings used to be a sheet pulled up from a drawn hill on the home screen,
 * under its own caption and above a separate rounded bar: three unrelated
 * shapes stacked at the bottom of every screen. As a destination it gets the
 * same bar, a full screen and the system back gesture like the other two.
 */
@Composable
fun AppNavigation(viewModel: VpnViewModel) {
    val navController = rememberNavController()

    // Switch to the Proxies tab when a deep link arrives so ProxyListScreen can consume it.
    val pendingDeepLink by viewModel.pendingDeepLinkUrl.collectAsState()
    LaunchedEffect(pendingDeepLink) {
        if (pendingDeepLink != null) {
            navController.navigate(ProxiesRoute) {
                popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                launchSingleTop = true
                restoreState = true
            }
        }
    }

    val topLevelRoutes = listOf(
        TopLevelRoute(
            titleResId = R.string.home,
            route = HomeRoute,
            selectedIcon = Icons.Filled.Home,
            unselectedIcon = Icons.Outlined.Home
        ),
        TopLevelRoute(
            titleResId = R.string.proxies,
            route = ProxiesRoute,
            selectedIcon = ImageVector.vectorResource(R.drawable.ic_network_filled),
            unselectedIcon = ImageVector.vectorResource(R.drawable.ic_network_outlined)
        ),
        TopLevelRoute(
            titleResId = R.string.settings,
            route = SettingsRoute,
            selectedIcon = Icons.Filled.Settings,
            unselectedIcon = Icons.Outlined.Settings
        )
    )

    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentDestination = navBackStackEntry?.destination

    fun isSelected(route: TopLevelRoute): Boolean =
        currentDestination?.hierarchy?.any { it.hasRoute(route.route::class) } == true

    fun go(route: TopLevelRoute) {
        navController.navigate(route.route) {
            popUpTo(navController.graph.findStartDestination().id) { saveState = true }
            launchSingleTop = true
            restoreState = true
        }
    }

    // A rail once the window is wide enough for one; 600dp is Material's own
    // compact/medium boundary. Always use the rail on Android TV.
    val isTv = com.mythaia.ui.home.isTelevision(androidx.compose.ui.platform.LocalContext.current)
    val density = LocalDensity.current
    val containerWidth = LocalWindowInfo.current.containerSize.width
    val wideLayout = isTv || with(density) { containerWidth.toDp() } >= WIDE_LAYOUT_BREAKPOINT_DP.dp
    val openSettings = { go(topLevelRoutes.first { it.route == SettingsRoute }) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        // A subscription that did not update, on whichever screen is open.
        snackbarHost = { SubscriptionNoticeBar(viewModel) },
        bottomBar = {
            if (wideLayout) return@Scaffold
            NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainer) {
                topLevelRoutes.forEach { route ->
                    val selected = isSelected(route)
                    NavigationBarItem(
                        selected = selected,
                        onClick = { go(route) },
                        icon = {
                            Icon(
                                imageVector = if (selected) route.selectedIcon else route.unselectedIcon,
                                contentDescription = null
                            )
                        },
                        label = { Text(stringResource(route.titleResId), maxLines = 1) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                            unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        if (wideLayout) {
            Row(modifier = Modifier.fillMaxSize()) {
                NavigationRail(
                    containerColor = MaterialTheme.colorScheme.surface,
                    header = {
                        WingMark(
                            modifier = Modifier
                                .padding(top = 12.dp, bottom = 4.dp)
                                .size(28.dp),
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                ) {
                    Spacer(modifier = Modifier.weight(1f))
                    topLevelRoutes.forEach { topLevelRoute ->
                        val selected = isSelected(topLevelRoute)
                        NavigationRailItem(
                            icon = {
                                Icon(
                                    imageVector = if (selected) topLevelRoute.selectedIcon else topLevelRoute.unselectedIcon,
                                    contentDescription = null
                                )
                            },
                            label = {
                                Text(
                                    stringResource(topLevelRoute.titleResId),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            },
                            colors = NavigationRailItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                                unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant
                            ),
                            selected = selected,
                            onClick = { go(topLevelRoute) }
                        )
                    }
                    Spacer(modifier = Modifier.weight(1f))
                }
                VerticalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
                Box(modifier = Modifier.weight(1f)) {
                    AppNavHost(
                        navController = navController,
                        viewModel = viewModel,
                        contentPadding = innerPadding,
                        isTv = isTv,
                        onOpenSettings = openSettings
                    )
                }
            }
        } else {
            AppNavHost(
                navController = navController,
                viewModel = viewModel,
                contentPadding = innerPadding,
                isTv = isTv,
                onOpenSettings = openSettings
            )
        }
    }
}

/** The destinations, shared by the bar and the rail layouts. */
@Composable
private fun AppNavHost(
    navController: NavHostController,
    viewModel: VpnViewModel,
    contentPadding: PaddingValues,
    isTv: Boolean,
    onOpenSettings: () -> Unit
) {
    NavHost(
        navController = navController,
        startDestination = HomeRoute
    ) {
        composable<HomeRoute> {
            if (isTv) {
                com.mythaia.ui.home.TvHomeScreen(
                    viewModel = viewModel,
                    onOpenSettings = onOpenSettings,
                    contentPadding = contentPadding
                )
            } else {
                HomeScreen(
                    viewModel = viewModel,
                    contentPadding = contentPadding
                )
            }
        }
        composable<ProxiesRoute> {
            // Only the bottom inset: the screen draws its own header under the
            // status bar, and the outer padding would leave a blank band there.
            Box(modifier = Modifier.bottomBarPadding(contentPadding)) {
                ProxyListScreen(viewModel = viewModel)
            }
        }
        composable<SettingsRoute> {
            // The same: its top bar takes the status bar itself.
            Box(modifier = Modifier.bottomBarPadding(contentPadding)) {
                SettingsScreen(viewModel = viewModel)
            }
        }
    }

    // A release the daily check found, if the user turned that check on.
    com.mythaia.ui.settings.UpdatePrompt()

    // Routing Rules Updated alert — surfaces orphaned rule-set assignments that
    // were silently re-pointed to Default after a referenced proxy was deleted.
    val orphanedNames by viewModel.orphanedRuleSetNames.collectAsState()
    if (orphanedNames.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = { viewModel.clearOrphanedRuleSetNames() },
            title = { Text(stringResource(R.string.routing_rules_updated_title)) },
            text = {
                Text(stringResource(R.string.routing_rules_updated_message,
                    orphanedNames.joinToString(", ")))
            },
            confirmButton = {
                TextButton(onClick = { viewModel.clearOrphanedRuleSetNames() }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

/**
 * Room for the navigation bar under a destination, marked as used: the
 * destinations' own Scaffolds would otherwise add the system bar inset a
 * second time and leave an empty band above the bar that cut lists off.
 */
private fun Modifier.bottomBarPadding(contentPadding: PaddingValues): Modifier {
    val bottom = PaddingValues(bottom = contentPadding.calculateBottomPadding())
    return padding(bottom).consumeWindowInsets(bottom)
}

private const val WIDE_LAYOUT_BREAKPOINT_DP = 600
