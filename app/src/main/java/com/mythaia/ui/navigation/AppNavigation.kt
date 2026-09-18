package com.mythaia.ui.navigation

import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.vectorResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.mythaia.R
import com.mythaia.ui.home.HomeScreen
import com.mythaia.ui.proxy.ChainListScreen
import com.mythaia.ui.proxy.ProxyListScreen
import com.mythaia.ui.settings.SettingsScreen
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.VerticalDivider
import androidx.navigation.NavHostController
import com.mythaia.ui.components.WingMark
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.serialization.Serializable

@Serializable object HomeRoute
@Serializable object ProxiesRoute
@Serializable object ChainsRoute
@Serializable object SettingsRoute

data class TopLevelRoute(
    val titleResId: Int,
    val route: Any,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

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
            titleResId = R.string.chains,
            route = ChainsRoute,
            selectedIcon = Icons.Filled.Link,
            unselectedIcon = Icons.Outlined.Link
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

    // A rail once the window is wide enough for one: on a tablet or an unfolded
    // foldable a bottom bar wastes the height and puts the targets far from
    // where the hands are. 600dp is Material's own compact/medium boundary.
    // The window's own size rather than Configuration.screenWidthDp, which
    // excludes system decorations and is not updated in every multi-window
    // state — both of which matter exactly at a breakpoint.
    val density = LocalDensity.current
    val containerWidth = LocalWindowInfo.current.containerSize.width
    val wideLayout = with(density) { containerWidth.toDp() } >= WIDE_LAYOUT_BREAKPOINT_DP.dp

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            if (wideLayout) return@Scaffold

            // Paper bar with a 1dp hairline on top instead of elevation;
            // azure selection, slate unselected — the Wing chrome treatment.
            Column {
                HorizontalDivider(
                    thickness = 1.dp,
                    color = MaterialTheme.colorScheme.outline
                )
                NavigationBar(
                    containerColor = MaterialTheme.colorScheme.surface,
                    tonalElevation = 0.dp
                ) {
                    topLevelRoutes.forEach { topLevelRoute ->
                        val selected = isSelected(topLevelRoute)

                        NavigationBarItem(
                            icon = {
                                Icon(
                                    imageVector = if (selected) topLevelRoute.selectedIcon else topLevelRoute.unselectedIcon,
                                    contentDescription = stringResource(topLevelRoute.titleResId)
                                )
                            },
                            label = {
                                Text(
                                    stringResource(topLevelRoute.titleResId),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                            ),
                            selected = selected,
                            onClick = { go(topLevelRoute) }
                        )
                    }
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
                                    contentDescription = stringResource(topLevelRoute.titleResId)
                                )
                            },
                            label = {
                                Text(
                                    stringResource(topLevelRoute.titleResId),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            },
                            colors = NavigationRailItemDefaults.colors(
                                selectedIconColor = MaterialTheme.colorScheme.primary,
                                selectedTextColor = MaterialTheme.colorScheme.primary,
                                unselectedIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                unselectedTextColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                indicatorColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                            ),
                            selected = selected,
                            onClick = { go(topLevelRoute) }
                        )
                    }
                    Spacer(modifier = Modifier.weight(1f))
                }
                VerticalDivider(
                    thickness = 1.dp,
                    color = MaterialTheme.colorScheme.outline
                )
                Box(modifier = Modifier.weight(1f)) {
                    AppNavHost(
                        navController = navController,
                        viewModel = viewModel,
                        // The rail owns the start edge, so the content keeps
                        // only the insets the Scaffold reports for the rest.
                        contentPadding = innerPadding
                    )
                }
            }
        } else {
            AppNavHost(
                navController = navController,
                viewModel = viewModel,
                contentPadding = innerPadding
            )
        }
    }
}

/** The destinations, shared by the bar and the rail layouts. */
@Composable
private fun AppNavHost(
    navController: NavHostController,
    viewModel: VpnViewModel,
    contentPadding: PaddingValues
) {
    val innerPadding = contentPadding
    NavHost(
        navController = navController,
        startDestination = HomeRoute
    ) {
        composable<HomeRoute> {
            HomeScreen(viewModel = viewModel, contentPadding = innerPadding)
        }
        composable<ProxiesRoute> {
            Box(modifier = Modifier.padding(innerPadding)) {
                ProxyListScreen(viewModel = viewModel)
            }
        }
        composable<ChainsRoute> {
            Box(modifier = Modifier.padding(innerPadding)) {
                ChainListScreen(viewModel = viewModel)
            }
        }
        composable<SettingsRoute> {
            Box(modifier = Modifier.padding(innerPadding)) {
                SettingsScreen(viewModel = viewModel)
            }
        }
    }

    // Routing Rules Updated alert — surfaces orphaned rule-set assignments that
    // were silently re-pointed to Default after a referenced proxy was deleted.
    // Mirrors iOS ContentView's "Routing Rules Updated" alert.
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
 * Where the bottom bar gives way to a rail.
 *
 * Material's compact/medium boundary: below it a phone in portrait, at or
 * above it a tablet, a large phone in landscape, or an unfolded foldable.
 */
private const val WIDE_LAYOUT_BREAKPOINT_DP = 600
