package com.mythaia.ui.navigation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
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
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
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
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.home.HomeScreen
import com.mythaia.ui.proxy.ProxyListScreen
import com.mythaia.ui.settings.SettingsScreen
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.serialization.Serializable

@Serializable object HomeRoute
@Serializable object ProxiesRoute

data class TopLevelRoute(
    val titleResId: Int,
    val route: Any,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

/**
 * Two destinations, Home and Proxies. Chains live inside Proxies as a tab;
 * Settings is a sheet pulled up from the home screen, not a destination.
 */
@OptIn(ExperimentalMaterial3Api::class)
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

    var showSettings by rememberSaveable { mutableStateOf(false) }

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
    // compact/medium boundary.
    val density = LocalDensity.current
    val containerWidth = LocalWindowInfo.current.containerSize.width
    val wideLayout = with(density) { containerWidth.toDp() } >= WIDE_LAYOUT_BREAKPOINT_DP.dp

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            if (wideLayout) return@Scaffold
            Column {
                HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
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
                VerticalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
                Box(modifier = Modifier.weight(1f)) {
                    AppNavHost(
                        navController = navController,
                        viewModel = viewModel,
                        contentPadding = innerPadding,
                        onOpenSettings = { showSettings = true }
                    )
                }
            }
        } else {
            AppNavHost(
                navController = navController,
                viewModel = viewModel,
                contentPadding = innerPadding,
                onOpenSettings = { showSettings = true }
            )
        }
    }

    // Settings ride up from the bottom of the home screen. The whole screen,
    // with its own drill-down, lives inside the sheet; the sub-screens' own
    // back handling takes precedence until they are back at the root.
    if (showSettings) {
        ModalBottomSheet(
            onDismissRequest = { showSettings = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.background
        ) {
            Box(modifier = Modifier.fillMaxHeight(0.94f)) {
                SettingsScreen(viewModel = viewModel)
            }
        }
    }
}

/** The destinations, shared by the bar and the rail layouts. */
@Composable
private fun AppNavHost(
    navController: NavHostController,
    viewModel: VpnViewModel,
    contentPadding: PaddingValues,
    onOpenSettings: () -> Unit
) {
    NavHost(
        navController = navController,
        startDestination = HomeRoute
    ) {
        composable<HomeRoute> {
            HomeScreen(
                viewModel = viewModel,
                contentPadding = contentPadding,
                onOpenSettings = onOpenSettings
            )
        }
        composable<ProxiesRoute> {
            Box(modifier = Modifier.padding(contentPadding)) {
                ProxyListScreen(viewModel = viewModel)
            }
        }
    }

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

private const val WIDE_LAYOUT_BREAKPOINT_DP = 600
