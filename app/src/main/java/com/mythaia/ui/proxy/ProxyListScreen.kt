package com.mythaia.ui.proxy

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.Subscription
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.SubscriptionDomainHelper
import com.mythaia.ui.components.ProxyCardContent
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.ui.components.SubscriptionUsageCard
import androidx.compose.foundation.background
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.FilledIconToggleButton
import androidx.compose.material3.IconButtonDefaults
import com.mythaia.data.network.LatencyResult
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.coroutines.launch
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ProxyListScreen(viewModel: VpnViewModel) {
    val context = LocalContext.current
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()

    var showingAddSheet by remember { mutableStateOf(false) }
    var showingManualAddSheet by remember { mutableStateOf(false) }
    var deepLinkPrefill by remember { mutableStateOf<String?>(null) }

    // Auto-open the Add sheet when a deep link arrives (vless://, ss://, socks5://, or mythaia://add-proxy?link=…).
    val pendingDeepLink by viewModel.pendingDeepLinkUrl.collectAsState()
    androidx.compose.runtime.LaunchedEffect(pendingDeepLink) {
        val url = pendingDeepLink ?: return@LaunchedEffect
        deepLinkPrefill = url
        showingAddSheet = true
        viewModel.consumePendingDeepLink()
    }
    var configurationToEdit by remember { mutableStateOf<ProxyConfiguration?>(null) }
    var subscriptionToRename by remember { mutableStateOf<Subscription?>(null) }
    var updatingSubscriptionId by remember { mutableStateOf<java.util.UUID?>(null) }
    var showSubscriptionError by remember { mutableStateOf(false) }
    var subscriptionErrorMessage by remember { mutableStateOf("") }
    var collapsedSubscriptions by remember(subscriptions) {
        mutableStateOf(subscriptions.filter { it.collapsed }.map { it.id }.toSet())
    }

    val scope = rememberCoroutineScope()

    var searchQuery by remember { mutableStateOf("") }
    var sortByLatency by remember { mutableStateOf(false) }

    /**
     * Name or address, case-insensitively. A subscription can carry hundreds of
     * servers whose names differ by one word, so matching the address too is
     * what makes the search usable on them.
     */
    fun matchesQuery(config: ProxyConfiguration): Boolean {
        if (searchQuery.isBlank()) return true
        return config.name.contains(searchQuery, ignoreCase = true) ||
            config.serverAddress.contains(searchQuery, ignoreCase = true)
    }

    /**
     * Fastest first when sorting by latency; anything unmeasured or failed
     * sinks below everything that answered, keeping its original order.
     */
    fun ordered(configs: List<ProxyConfiguration>): List<ProxyConfiguration> {
        if (!sortByLatency) return configs
        return configs.sortedBy { config ->
            (latencyResults[config.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE
        }
    }

    val standaloneConfigs = remember(configurations, searchQuery, sortByLatency, latencyResults) {
        ordered(configurations.filter { it.subscriptionId == null && matchesQuery(it) })
    }

    val subscribedGroups = remember(configurations, subscriptions, searchQuery, sortByLatency, latencyResults) {
        subscriptions.mapNotNull { subscription ->
            val configs = ordered(
                configurations.filter { it.subscriptionId == subscription.id && matchesQuery(it) }
            )
            // A group with nothing left after filtering disappears rather than
            // showing an empty header.
            if (configs.isEmpty()) null else subscription to configs
        }
    }

    val hasResults = standaloneConfigs.isNotEmpty() || subscribedGroups.isNotEmpty()

    val autoSelecting by viewModel.autoSelecting.collectAsState()

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            Column {
                TopAppBar(
                    title = { Text(stringResource(R.string.proxies)) },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        titleContentColor = MaterialTheme.colorScheme.onSurface,
                        actionIconContentColor = MaterialTheme.colorScheme.primary
                    ),
                    actions = {
                        // Measures every server and switches to the fastest.
                        // Disabled while running so a second tap cannot start a
                        // competing round.
                        IconButton(
                            onClick = { scope.launch { viewModel.autoSelectFastest() } },
                            enabled = !autoSelecting && configurations.isNotEmpty()
                        ) {
                            if (autoSelecting) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    strokeWidth = 2.dp,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            } else {
                                Icon(
                                    imageVector = Icons.Default.Bolt,
                                    contentDescription = stringResource(R.string.auto_select_now)
                                )
                            }
                        }
                        IconButton(onClick = {
                            // Only test what's currently visible — standalone proxies
                            // plus configurations from expanded subscriptions.
                            val visible = standaloneConfigs + subscribedGroups
                                .filter { it.first.id !in collapsedSubscriptions }
                                .flatMap { it.second }
                            viewModel.testLatencies(forConfigs = visible)
                        }) {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = stringResource(R.string.test_all)
                            )
                        }
                    }
                )
                if (configurations.isNotEmpty()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surface)
                            .padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text(stringResource(R.string.search_proxies)) },
                            leadingIcon = {
                                Icon(
                                    imageVector = Icons.Default.Search,
                                    contentDescription = null,
                                    modifier = Modifier.size(18.dp)
                                )
                            },
                            trailingIcon = if (searchQuery.isNotEmpty()) {
                                {
                                    IconButton(onClick = { searchQuery = "" }) {
                                        Icon(
                                            imageVector = Icons.Default.Close,
                                            contentDescription = stringResource(R.string.clear),
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            } else {
                                null
                            },
                            singleLine = true,
                            colors = wingTextFieldColors(),
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier.weight(1f)
                        )
                        // Sorting is a view of the same list, so it is a toggle
                        // rather than a menu: one tap on, one tap off.
                        FilledIconToggleButton(
                            checked = sortByLatency,
                            onCheckedChange = { sortByLatency = it },
                            shape = RoundedCornerShape(14.dp),
                            colors = IconButtonDefaults.filledIconToggleButtonColors(
                                containerColor = MaterialTheme.colorScheme.surface,
                                contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                checkedContainerColor = MaterialTheme.colorScheme.primary,
                                checkedContentColor = MaterialTheme.colorScheme.onPrimary
                            )
                        ) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.Sort,
                                contentDescription = stringResource(R.string.sort_by_latency),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
                HorizontalDivider(
                    thickness = 1.dp,
                    color = MaterialTheme.colorScheme.outline
                )
            }
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showingAddSheet = true },
                shape = RoundedCornerShape(20.dp),
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = MaterialTheme.colorScheme.onPrimary,
                elevation = FloatingActionButtonDefaults.elevation(
                    defaultElevation = 0.dp,
                    pressedElevation = 0.dp,
                    focusedElevation = 0.dp,
                    hoveredElevation = 0.dp
                )
            ) {
                Icon(
                    imageVector = Icons.Default.Add,
                    contentDescription = stringResource(R.string.add)
                )
            }
        }
    ) { innerPadding ->
        if (configurations.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    WingMark(
                        modifier = Modifier.size(64.dp),
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.height(20.dp))
                    Text(
                        text = stringResource(R.string.no_proxies),
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.tap_to_add_proxy),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else if (!hasResults) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.no_matching_proxies),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(
                    start = 16.dp,
                    end = 16.dp,
                    top = 12.dp,
                    bottom = 96.dp
                ),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (standaloneConfigs.isNotEmpty()) {
                    items(standaloneConfigs, key = { it.id }) { config ->
                        ConfigurationRow(
                            configuration = config,
                            isSelected = config.id == selectedConfigId,
                            latency = latencyResults[config.id],
                            onSelect = { viewModel.setSelectedConfiguration(config) },
                            onEdit = { configurationToEdit = config },
                            onDelete = { viewModel.deleteConfiguration(config) },
                            onTestLatency = { viewModel.testLatency(forConfig = config) }
                        )
                    }
                }

                subscribedGroups.forEach { (subscription, configs) ->
                    val isCollapsed = collapsedSubscriptions.contains(subscription.id)
                    // Locked subscriptions (managed panels) hide the edit/delete
                    // menu entries — users should re-subscribe rather than edit
                    // individual proxies.
                    val editingDisabled = SubscriptionDomainHelper.shouldDisableProxyEditing(subscription.url)
                    item(key = "header_${subscription.id}") {
                        SubscriptionHeader(
                            subscription = subscription,
                            isCollapsed = isCollapsed,
                            isUpdating = updatingSubscriptionId == subscription.id,
                            onToggleCollapse = {
                                collapsedSubscriptions = if (isCollapsed) {
                                    collapsedSubscriptions - subscription.id
                                } else {
                                    collapsedSubscriptions + subscription.id
                                }
                                viewModel.toggleSubscriptionCollapsed(subscription)
                            },
                            onUpdate = {
                                if (updatingSubscriptionId == null) {
                                    updatingSubscriptionId = subscription.id
                                    scope.launch {
                                        try {
                                            viewModel.updateSubscription(subscription)
                                        } catch (e: Exception) {
                                            subscriptionErrorMessage = e.message ?: context.getString(R.string.unknown_error)
                                            showSubscriptionError = true
                                        }
                                        updatingSubscriptionId = null
                                    }
                                }
                            },
                            onDelete = { viewModel.deleteSubscription(subscription) },
                            onRename = { subscriptionToRename = subscription },
                            onTestLatency = { viewModel.testLatencies(forConfigs = configs) }
                        )
                    }
                    if (!isCollapsed) {
                        items(configs, key = { it.id }) { config ->
                            ConfigurationRow(
                                configuration = config,
                                isSelected = config.id == selectedConfigId,
                                latency = latencyResults[config.id],
                                editingDisabled = editingDisabled,
                                onSelect = { viewModel.setSelectedConfiguration(config) },
                                onEdit = { configurationToEdit = config },
                                onDelete = { viewModel.deleteConfiguration(config) },
                                onTestLatency = { viewModel.testLatency(forConfig = config) }
                            )
                        }
                    }
                }
            }
        }
    }

    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = {
                showingAddSheet = false
                deepLinkPrefill = null
            },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            AddProxyScreen(
                viewModel = viewModel,
                initialLink = deepLinkPrefill,
                onDismiss = {
                    showingAddSheet = false
                    deepLinkPrefill = null
                },
                onShowManualAdd = {
                    showingAddSheet = false
                    deepLinkPrefill = null
                    showingManualAddSheet = true
                },
                onImport = { config ->
                    viewModel.addConfiguration(config)
                    showingAddSheet = false
                    deepLinkPrefill = null
                },
                onSubscriptionImport = { configs, subscription ->
                    viewModel.addSubscription(configs, subscription)
                    showingAddSheet = false
                    deepLinkPrefill = null
                }
            )
        }
    }

    if (showingManualAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingManualAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            ProxyEditorScreen(
                configuration = null,
                onSave = { config ->
                    viewModel.addConfiguration(config)
                    showingManualAddSheet = false
                },
                onDismiss = { showingManualAddSheet = false }
            )
        }
    }

    configurationToEdit?.let { config ->
        ModalBottomSheet(
            onDismissRequest = { configurationToEdit = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            ProxyEditorScreen(
                configuration = config,
                onSave = { updated ->
                    viewModel.updateConfiguration(updated)
                    configurationToEdit = null
                },
                onDismiss = { configurationToEdit = null }
            )
        }
    }

    subscriptionToRename?.let { sub ->
        var newName by remember(sub.id) { mutableStateOf(sub.name) }
        AlertDialog(
            onDismissRequest = { subscriptionToRename = null },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.rename_subscription)) },
            text = {
                OutlinedTextField(
                    value = newName,
                    onValueChange = { newName = it },
                    label = { Text(stringResource(R.string.name)) },
                    singleLine = true,
                    shape = RoundedCornerShape(14.dp),
                    colors = wingTextFieldColors()
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        val trimmed = newName.trim()
                        if (trimmed.isNotEmpty() && trimmed != sub.name) {
                            viewModel.renameSubscription(sub, trimmed)
                        }
                        subscriptionToRename = null
                    }
                ) { Text(stringResource(R.string.save)) }
            },
            dismissButton = {
                TextButton(onClick = { subscriptionToRename = null }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    if (showSubscriptionError) {
        AlertDialog(
            onDismissRequest = { showSubscriptionError = false },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.update_failed)) },
            text = { Text(subscriptionErrorMessage) },
            confirmButton = {
                TextButton(onClick = { showSubscriptionError = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

@Composable
private fun SubscriptionHeader(
    subscription: Subscription,
    isCollapsed: Boolean,
    isUpdating: Boolean,
    onToggleCollapse: () -> Unit,
    onUpdate: () -> Unit,
    onDelete: () -> Unit,
    onRename: () -> Unit,
    onTestLatency: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }
    val chevronRotation by animateFloatAsState(
        targetValue = if (isCollapsed) 0f else 90f, label = "chevron"
    )

    Column(modifier = Modifier.fillMaxWidth()) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp)
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onToggleCollapse)
            .padding(horizontal = 8.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            modifier = Modifier.size(18.dp).rotate(chevronRotation),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = subscription.name,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )

        if (isUpdating) {
            CircularProgressIndicator(
                modifier = Modifier.size(16.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.primary
            )
        } else {
            IconButton(onClick = onUpdate, modifier = Modifier.size(32.dp)) {
                Icon(
                    imageVector = Icons.Default.Refresh,
                    contentDescription = stringResource(R.string.update),
                    modifier = Modifier.size(18.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Box {
            IconButton(onClick = { showMenu = true }, modifier = Modifier.size(32.dp)) {
                Icon(
                    imageVector = Icons.Default.MoreVert,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            WingDropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.test_latency)) },
                    onClick = {
                        showMenu = false
                        onTestLatency()
                    },
                    leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.rename)) },
                    onClick = {
                        showMenu = false
                        onRename()
                    },
                    leadingIcon = { Icon(Icons.Default.DriveFileRenameOutline, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.update)) },
                    onClick = {
                        showMenu = false
                        onUpdate()
                    },
                    leadingIcon = { Icon(Icons.Default.Refresh, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                    onClick = {
                        showMenu = false
                        onDelete()
                    },
                    leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
                )
            }
        }
    }

    // The panel's quota and expiry, under the group it belongs to. Hidden
    // while the group is collapsed, where the point is to take up less room,
    // and silent when the panel reported neither.
    if (!isCollapsed) {
        SubscriptionUsageCard(
            subscription = subscription,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp)
        )
    }
    }
}

/**
 * Context menu on the Wing radius language. DropdownMenu draws with
 * MaterialTheme.shapes.extraSmall, so re-scope just that slot to the 14dp
 * compact-row radius; colors and typography inherit unchanged.
 */
@Composable
private fun WingDropdownMenu(
    expanded: Boolean,
    onDismissRequest: () -> Unit,
    content: @Composable ColumnScope.() -> Unit
) {
    MaterialTheme(
        shapes = MaterialTheme.shapes.copy(extraSmall = RoundedCornerShape(14.dp))
    ) {
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = onDismissRequest,
            content = content
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ConfigurationRow(
    configuration: ProxyConfiguration,
    isSelected: Boolean,
    latency: com.mythaia.data.network.LatencyResult?,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTestLatency: () -> Unit,
    editingDisabled: Boolean = false
) {
    val context = LocalContext.current
    var showMenu by remember { mutableStateOf(false) }

    Box {
        // ProxyCardContent already renders the full paper card (20dp radius,
        // hairline outline, azure-tinted when selected) — attach the click
        // targets to it directly instead of nesting a second card.
        ProxyCardContent(
            configuration = configuration,
            isSelected = isSelected,
            latency = latency,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(20.dp))
                .combinedClickable(
                    onClick = onSelect,
                    onLongClick = { showMenu = true }
                )
        )

        WingDropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.test_latency)) },
                leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) },
                onClick = {
                    showMenu = false
                    onTestLatency()
                }
            )
            if (!editingDisabled) {
                // Locked-subscription proxies hide Copy Link / Edit / Delete to match
                // iOS ProxyListView's context-menu protections (the link contains
                // credentials the user shouldn't be able to extract from a managed sub).
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy_link)) },
                    leadingIcon = { Icon(Icons.Default.Share, contentDescription = null) },
                    onClick = {
                        showMenu = false
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("proxy_url", configuration.toUrl()))
                    }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.edit)) },
                    onClick = {
                        showMenu = false
                        onEdit()
                    },
                    leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                    onClick = {
                        showMenu = false
                        onDelete()
                    },
                    leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
                )
            }
        }
    }
}
