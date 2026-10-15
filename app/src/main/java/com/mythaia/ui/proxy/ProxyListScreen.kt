package com.mythaia.ui.proxy

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Handshake
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.NetworkPing
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledIconToggleButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.SubscriptionDomainHelper
import com.mythaia.ui.components.LatencyBadge
import com.mythaia.ui.components.ProxyCardContent
import com.mythaia.ui.components.SubscriptionUsageCard
import com.mythaia.ui.components.WingIconTile
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.viewmodel.ProxyGroup
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The Proxies screen. No title: the two tabs (servers, chains) sit at the
 * very top with the speed test and the overflow menu beside them, and under
 * them the groups — Default and each subscription — as a row of pills. A tap
 * on a group makes it the tunnel's group; a tap on a server pins it; the
 * Auto row at the top of every list hands the choice back to the best ping.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ProxyListScreen(viewModel: VpnViewModel) {
    val scope = rememberCoroutineScope()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val activeGroupId by viewModel.activeGroupId.collectAsState()
    val pinnedByGroup by viewModel.pinnedByGroup.collectAsState()
    val autoChoice by viewModel.autoChoice.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()
    val latencyKind by viewModel.latencyKind.collectAsState()
    val autoSelecting by viewModel.autoSelecting.collectAsState()

    var tab by rememberSaveable { mutableStateOf(0) }
    var browsingGroupId by rememberSaveable { mutableStateOf(activeGroupId) }

    var showingAddSheet by rememberSaveable { mutableStateOf(false) }
    var showingManualAddSheet by rememberSaveable { mutableStateOf(false) }
    var deepLinkPrefill by rememberSaveable { mutableStateOf<String?>(null) }
    // Ids rather than the objects: they survive a rotation, and what they
    // name is looked up fresh below, so a sheet open mid-edit stays open.
    var configurationToEditId by rememberSaveable { mutableStateOf<String?>(null) }
    var configurationToDeleteId by rememberSaveable { mutableStateOf<String?>(null) }
    var subscriptionToDeleteId by rememberSaveable { mutableStateOf<String?>(null) }
    var subscriptionToConfigureId by rememberSaveable { mutableStateOf<String?>(null) }
    val configurationToEdit = configurationToEditId?.let { id -> configurations.firstOrNull { it.id.toString() == id } }
    val configurationToDelete = configurationToDeleteId?.let { id -> configurations.firstOrNull { it.id.toString() == id } }
    val subscriptionToDelete = subscriptionToDeleteId?.let { id -> subscriptions.firstOrNull { it.id.toString() == id } }
    val subscriptionToConfigure = subscriptionToConfigureId?.let { id -> subscriptions.firstOrNull { it.id.toString() == id } }
    // The refresh lives in the view model, where a tab switch cannot cancel it.
    val updatingSubscriptionId by viewModel.updatingSubscriptionId.collectAsState()
    val subscriptionErrorMessage by viewModel.subscriptionUpdateError.collectAsState()
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var sortByLatency by rememberSaveable { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    var confirmRemoveFailed by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val resources = androidx.compose.ui.platform.LocalResources.current

    // Auto-open the Add sheet when a deep link arrives.
    val pendingDeepLink by viewModel.pendingDeepLinkUrl.collectAsState()
    LaunchedEffect(pendingDeepLink) {
        val url = pendingDeepLink ?: return@LaunchedEffect
        deepLinkPrefill = url
        showingAddSheet = true
        tab = 0
        viewModel.consumePendingDeepLink()
    }

    val groups = remember(configurations, subscriptions) { viewModel.groups() }
    // A deleted subscription leaves the browsed tab pointing at nothing.
    LaunchedEffect(groups) {
        if (groups.none { it.id == browsingGroupId }) browsingGroupId = ProxyGroup.DEFAULT_ID
    }
    val group = groups.firstOrNull { it.id == browsingGroupId } ?: groups.first()
    val subscription = group.subscriptionId?.let { id -> subscriptions.firstOrNull { it.id == id } }
    val editingDisabled = subscription != null &&
        SubscriptionDomainHelper.shouldDisableProxyEditing(subscription.url)
    val defaultGroupName = stringResource(R.string.group_default)

    fun matchesQuery(config: ProxyConfiguration): Boolean {
        if (searchQuery.isBlank()) return true
        return config.name.contains(searchQuery, ignoreCase = true) ||
            config.serverAddress.contains(searchQuery, ignoreCase = true)
    }

    val visible = remember(group, searchQuery, sortByLatency, latencyResults) {
        val filtered = group.configs.filter { matchesQuery(it) }
        if (!sortByLatency) filtered else filtered.sortedBy { config ->
            (latencyResults[config.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE
        }
    }

    fun runCheck(kind: LatencyKind) {
        viewModel.testLatencies(forConfigs = group.configs, kind = kind)
    }

    // Servers of this group that failed their last check, for "Remove non-working".
    val failedCount = remember(group, latencyResults) {
        group.configs.count {
            val result = latencyResults[it.id]
            result is LatencyResult.Failed || result is LatencyResult.Insecure
        }
    }

    fun exportGroup() {
        val title = subscription?.name ?: defaultGroupName
        scope.launch {
            val (links, _) = withContext(Dispatchers.Default) { viewModel.exportLinks(group.configs) }
            if (links.isNotEmpty()) LinkExport.share(context, links, title)
        }
    }

    /** Browsing a group is choosing it, the way Hiddify treats its profiles. */
    fun openGroup(id: String) {
        browsingGroupId = id
        if (selectedChainId != null || activeGroupId != id) viewModel.selectGroup(id)
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.background)
                    .statusBarsPadding()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 8.dp, top = 10.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SegmentedTabs(
                        selected = tab,
                        labels = listOf(stringResource(R.string.proxies), stringResource(R.string.proxy_chain)),
                        onSelect = { tab = it },
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    if (tab == 0) {
                        // The quick reachability check: TCP for servers on TCP,
                        // a QUIC probe for those on UDP (Hysteria2, TUIC).
                        IconButton(
                            onClick = { runCheck(LatencyKind.TCP) },
                            enabled = group.configs.isNotEmpty()
                        ) {
                            Icon(
                                imageVector = Icons.Default.NetworkPing,
                                contentDescription = stringResource(R.string.check_tcp_ping),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        // The plain speed test everyone knows: the real ping
                        // through the proxy, for the group on screen.
                        IconButton(
                            onClick = { runCheck(LatencyKind.HTTP) },
                            enabled = group.configs.isNotEmpty()
                        ) {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = stringResource(R.string.test_all),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        Box {
                            IconButton(onClick = { menuOpen = true }) {
                                Icon(
                                    imageVector = Icons.Default.MoreVert,
                                    contentDescription = stringResource(R.string.more_options),
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                            WingDropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.check_tcp_ping)) },
                                    leadingIcon = { Icon(Icons.Default.NetworkPing, contentDescription = null) },
                                    enabled = group.configs.isNotEmpty(),
                                    onClick = { menuOpen = false; runCheck(LatencyKind.TCP) }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.check_real_ping)) },
                                    leadingIcon = { Icon(Icons.Default.NetworkCheck, contentDescription = null) },
                                    enabled = group.configs.isNotEmpty(),
                                    onClick = { menuOpen = false; runCheck(LatencyKind.HTTP) }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.check_handshake)) },
                                    leadingIcon = { Icon(Icons.Default.Handshake, contentDescription = null) },
                                    enabled = group.configs.isNotEmpty(),
                                    onClick = { menuOpen = false; runCheck(LatencyKind.HANDSHAKE) }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.auto_select_now)) },
                                    leadingIcon = { Icon(Icons.Default.Bolt, contentDescription = null) },
                                    enabled = !autoSelecting && group.configs.any {
                                        it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3
                                    },
                                    onClick = {
                                        menuOpen = false
                                        scope.launch { viewModel.autoSelectFastest(group.id) }
                                    }
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.export_links)) },
                                    leadingIcon = { Icon(Icons.Default.Share, contentDescription = null) },
                                    enabled = group.configs.isNotEmpty(),
                                    onClick = { menuOpen = false; exportGroup() }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.remove_failed)) },
                                    leadingIcon = { Icon(Icons.Default.DeleteSweep, contentDescription = null) },
                                    enabled = failedCount > 0,
                                    onClick = { menuOpen = false; confirmRemoveFailed = true }
                                )
                                if (subscription != null) {
                                    HorizontalDivider()
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.update)) },
                                        leadingIcon = { Icon(Icons.Default.Refresh, contentDescription = null) },
                                        enabled = updatingSubscriptionId == null,
                                        onClick = {
                                            menuOpen = false
                                            viewModel.refreshSubscription(subscription)
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.group_settings)) },
                                        leadingIcon = { Icon(Icons.Default.Tune, contentDescription = null) },
                                        onClick = { menuOpen = false; subscriptionToConfigureId = subscription.id.toString() }
                                    )
                                    DropdownMenuItem(
                                        text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                                        leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
                                        onClick = { menuOpen = false; subscriptionToDeleteId = subscription.id.toString() }
                                    )
                                }
                            }
                        }
                    }
                }
                if (tab == 0 && configurations.isNotEmpty()) {
                    GroupPills(
                        groups = groups,
                        browsingId = group.id,
                        activeId = if (selectedChainId == null) activeGroupId else null,
                        defaultName = defaultGroupName,
                        onSelect = { openGroup(it) }
                    )
                }
            }
        },
        floatingActionButton = {
            if (tab == 0) {
                FloatingActionButton(
                    onClick = { showingAddSheet = true },
                    shape = RoundedCornerShape(20.dp),
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    elevation = FloatingActionButtonDefaults.elevation(
                        defaultElevation = 0.dp, pressedElevation = 0.dp,
                        focusedElevation = 0.dp, hoveredElevation = 0.dp
                    )
                ) {
                    Icon(imageVector = Icons.Default.Add, contentDescription = stringResource(R.string.add))
                }
            }
        }
    ) { innerPadding ->
        if (tab == 1) {
            Box(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
                ChainListScreen(viewModel = viewModel, embedded = true)
            }
            return@Scaffold
        }

        if (configurations.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    WingMark(modifier = Modifier.size(64.dp), color = MaterialTheme.colorScheme.primary)
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
            return@Scaffold
        }

        val groupIsActive = selectedChainId == null && activeGroupId == group.id
        val pinned = pinnedByGroup[group.id]
        val auto = autoChoice[group.id]

        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (subscription != null) {
                item(key = "usage") {
                    Column {
                        SubscriptionUsageCard(subscription = subscription)
                        com.mythaia.ui.components.SubscriptionNoticeCard(subscription = subscription, modifier = Modifier.padding(top = 8.dp))
                        if (updatingSubscriptionId == subscription.id) {
                            Row(
                                modifier = Modifier.padding(top = 8.dp, start = 4.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = stringResource(R.string.update),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }

            item(key = "search") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        placeholder = { Text(stringResource(R.string.search_proxies)) },
                        leadingIcon = {
                            Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                        },
                        trailingIcon = if (searchQuery.isNotEmpty()) {
                            {
                                IconButton(onClick = { searchQuery = "" }) {
                                    Icon(
                                        Icons.Default.Close,
                                        contentDescription = stringResource(R.string.clear),
                                        modifier = Modifier.size(18.dp)
                                    )
                                }
                            }
                        } else null,
                        singleLine = true,
                        colors = wingTextFieldColors(),
                        shape = RoundedCornerShape(18.dp),
                        modifier = Modifier.weight(1f)
                    )
                    FilledIconToggleButton(
                        checked = sortByLatency,
                        onCheckedChange = { sortByLatency = it },
                        shape = RoundedCornerShape(18.dp),
                        colors = IconButtonDefaults.filledIconToggleButtonColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
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

            // Auto, first in every group. Selected when this group is the
            // active one and has no pin.
            item(key = "auto") {
                val autoName = auto?.let { id -> group.configs.firstOrNull { it.id == id }?.name }
                AutoRow(
                    selected = groupIsActive && pinned == null,
                    busy = autoSelecting && groupIsActive,
                    subtitle = autoName?.let { stringResource(R.string.auto_prefix, it) }
                        ?: stringResource(R.string.auto_mode_hint),
                    latency = auto?.let { latencyResults[it] },
                    kindLabel = kindLabel(latencyKind),
                    onClick = { viewModel.useAuto(group.id) }
                )
            }

            if (visible.isEmpty() && group.configs.isNotEmpty()) {
                item(key = "nomatch") {
                    Text(
                        text = stringResource(R.string.no_matching_proxies),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
            if (group.configs.isEmpty()) {
                item(key = "empty") {
                    Text(
                        text = stringResource(R.string.no_servers_in_group),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            items(visible, key = { it.id }) { config ->
                ConfigurationRow(
                    configuration = config,
                    isSelected = groupIsActive && (pinned == config.id || (pinned == null && selectedConfigId == config.id)),
                    isPinned = pinned == config.id,
                    isAutoPick = pinned == null && auto == config.id,
                    latency = latencyResults[config.id],
                    editingDisabled = editingDisabled,
                    onSelect = { viewModel.pinConfiguration(config) },
                    onEdit = { configurationToEditId = config.id.toString() },
                    onDelete = { configurationToDeleteId = config.id.toString() },
                    onTestLatency = { viewModel.testLatency(forConfig = config) }
                )
            }
        }
    }

    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingAddSheet = false; deepLinkPrefill = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            AddProxyScreen(
                viewModel = viewModel,
                initialLink = deepLinkPrefill,
                onDismiss = { showingAddSheet = false; deepLinkPrefill = null },
                onShowManualAdd = {
                    showingAddSheet = false
                    deepLinkPrefill = null
                    showingManualAddSheet = true
                },
                onImport = { config ->
                    viewModel.addConfiguration(config)
                    browsingGroupId = ProxyGroup.DEFAULT_ID
                    showingAddSheet = false
                    deepLinkPrefill = null
                },
                onSubscriptionImport = { configs, sub ->
                    viewModel.addSubscription(configs, sub)
                    browsingGroupId = sub.id.toString()
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
            containerColor = MaterialTheme.colorScheme.background
        ) {
            NewServerFlow(
                onSave = { config ->
                    viewModel.addConfiguration(config)
                    browsingGroupId = ProxyGroup.DEFAULT_ID
                    showingManualAddSheet = false
                },
                onDismiss = { showingManualAddSheet = false }
            )
        }
    }

    configurationToEdit?.let { config ->
        ModalBottomSheet(
            onDismissRequest = { configurationToEditId = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            containerColor = MaterialTheme.colorScheme.background
        ) {
            if (config.outboundProtocol == OutboundProtocol.WIREGUARD) {
                WireGuardEditorScreen(
                    configuration = config,
                    onSave = { updated -> viewModel.updateConfiguration(updated); configurationToEditId = null },
                    onDismiss = { configurationToEditId = null }
                )
            } else {
                ProxyEditorScreen(
                    configuration = config,
                    onSave = { updated -> viewModel.updateConfiguration(updated); configurationToEditId = null },
                    onDismiss = { configurationToEditId = null }
                )
            }
        }
    }

    subscriptionToConfigure?.let { sub ->
        SubscriptionSettingsDialog(
            subscription = sub,
            onDismiss = { subscriptionToConfigureId = null },
            onSave = { name, sni, targets ->
                viewModel.updateSubscriptionSettings(sub, name, sni, targets)
                subscriptionToConfigureId = null
            }
        )
    }

    configurationToDelete?.let { config ->
        ConfirmDialog(
            title = stringResource(R.string.delete_proxy_title),
            text = stringResource(R.string.delete_proxy_message, config.name),
            confirmLabel = stringResource(R.string.delete),
            onConfirm = { configurationToDeleteId = null; viewModel.deleteConfiguration(config) },
            onDismiss = { configurationToDeleteId = null }
        )
    }

    subscriptionToDelete?.let { sub ->
        val count = configurations.count { it.subscriptionId == sub.id }
        ConfirmDialog(
            title = stringResource(R.string.delete_subscription_title),
            text = stringResource(R.string.delete_subscription_message, sub.name, count),
            confirmLabel = stringResource(R.string.delete),
            onConfirm = {
                subscriptionToDeleteId = null
                viewModel.deleteSubscription(sub)
                browsingGroupId = ProxyGroup.DEFAULT_ID
            },
            onDismiss = { subscriptionToDeleteId = null }
        )
    }

    if (confirmRemoveFailed) {
        val count = failedCount
        ConfirmDialog(
            title = stringResource(R.string.remove_failed_title),
            text = pluralStringResource(R.plurals.remove_failed_message, count, count) +
                if (subscription != null) "\n\n" + stringResource(R.string.remove_failed_subscription_note) else "",
            confirmLabel = stringResource(R.string.delete),
            onConfirm = {
                confirmRemoveFailed = false
                val removed = viewModel.removeFailed(group.id)
                android.widget.Toast.makeText(
                    context,
                    resources.getQuantityString(R.plurals.removed_servers, removed, removed),
                    android.widget.Toast.LENGTH_SHORT
                ).show()
            },
            onDismiss = { confirmRemoveFailed = false }
        )
    }

    subscriptionErrorMessage?.let { message ->
        AlertDialog(
            onDismissRequest = { viewModel.clearSubscriptionUpdateError() },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.update_failed)) },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = { viewModel.clearSubscriptionUpdateError() }) { Text(stringResource(R.string.ok)) }
            }
        )
    }
}

@Composable
private fun kindLabel(kind: LatencyKind): String = when (kind) {
    LatencyKind.TCP -> stringResource(R.string.latency_kind_tcp)
    LatencyKind.HANDSHAKE -> stringResource(R.string.latency_kind_handshake)
    LatencyKind.HTTP -> stringResource(R.string.latency_kind_http)
}

/** Two labels in one soft pill; the selected half is paper on the panel. */
@Composable
private fun SegmentedTabs(
    selected: Int,
    labels: List<String>,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(50),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = modifier
    ) {
        Row(modifier = Modifier.padding(4.dp)) {
            labels.forEachIndexed { index, label ->
                val isSelected = index == selected
                Surface(
                    onClick = { onSelect(index) },
                    shape = RoundedCornerShape(50),
                    color = if (isSelected) MaterialTheme.colorScheme.surface else Color.Transparent,
                    shadowElevation = if (isSelected) 1.dp else 0.dp,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        softWrap = false,
                        overflow = TextOverflow.Ellipsis,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp)
                    )
                }
            }
        }
    }
}

/** Default and each subscription as pills; the active one carries a dot. */
@Composable
private fun GroupPills(
    groups: List<ProxyGroup>,
    browsingId: String,
    activeId: String?,
    defaultName: String,
    onSelect: (String) -> Unit
) {
    LazyRow(
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(groups, key = { it.id }) { group ->
            val isBrowsing = group.id == browsingId
            val isActive = group.id == activeId
            Surface(
                onClick = { onSelect(group.id) },
                shape = RoundedCornerShape(50),
                color = if (isBrowsing) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceContainerLow,
                contentColor = if (isBrowsing) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (isActive) {
                        Box(
                            modifier = Modifier
                                .size(7.dp)
                                .clip(RoundedCornerShape(4.dp))
                                .background(
                                    if (isBrowsing) MaterialTheme.colorScheme.onPrimary
                                    else MaterialTheme.colorScheme.primary
                                )
                        )
                        Spacer(modifier = Modifier.width(7.dp))
                    }
                    Text(
                        text = if (group.isDefault) defaultName else group.name,
                        style = MaterialTheme.typography.labelLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = group.configs.size.toString(),
                        style = MaterialTheme.typography.labelMedium,
                        color = if (isBrowsing) MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.75f)
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

/** The Auto row: the best ping decides, and keeps deciding while connected. */
@Composable
private fun AutoRow(
    selected: Boolean,
    busy: Boolean,
    subtitle: String,
    latency: LatencyResult?,
    kindLabel: String,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(22.dp),
        color = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f) else MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            WingIconTile(size = 38.dp) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
                } else {
                    Icon(Icons.Default.Bolt, contentDescription = null, tint = Color.White)
                }
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.auto_mode),
                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                LatencyBadge(latency = latency)
                Text(
                    text = kindLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }
        }
    }
}

@Composable
private fun ConfirmDialog(
    title: String,
    text: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.onSurface,
        textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(confirmLabel, color = MaterialTheme.colorScheme.error) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

/** Context menu on the Wing radius language. */
@Composable
private fun WingDropdownMenu(
    expanded: Boolean,
    onDismissRequest: () -> Unit,
    content: @Composable ColumnScope.() -> Unit
) {
    MaterialTheme(shapes = MaterialTheme.shapes.copy(extraSmall = RoundedCornerShape(16.dp))) {
        DropdownMenu(expanded = expanded, onDismissRequest = onDismissRequest, content = content)
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ConfigurationRow(
    configuration: ProxyConfiguration,
    isSelected: Boolean,
    isPinned: Boolean,
    isAutoPick: Boolean,
    latency: LatencyResult?,
    editingDisabled: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTestLatency: () -> Unit
) {
    val context = LocalContext.current
    var showMenu by remember { mutableStateOf(false) }

    Box {
        Box {
            ProxyCardContent(
                configuration = configuration,
                isSelected = isSelected,
                latency = latency,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(22.dp))
                    .combinedClickable(onClick = onSelect, onLongClick = { showMenu = true })
            )
            // A pin or a bolt in the corner says how this server got chosen.
            if (isPinned || isAutoPick) {
                Icon(
                    imageVector = if (isPinned) Icons.Default.PushPin else Icons.Default.Bolt,
                    contentDescription = stringResource(if (isPinned) R.string.pinned else R.string.auto_picked),
                    tint = MaterialTheme.colorScheme.primary.copy(alpha = if (isPinned) 1f else 0.7f),
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(top = 6.dp, end = 10.dp)
                        .size(14.dp)
                )
            }
        }

        WingDropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.test_latency)) },
                leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) },
                onClick = { showMenu = false; onTestLatency() }
            )
            if (!editingDisabled) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy_link)) },
                    leadingIcon = { Icon(Icons.Default.Share, contentDescription = null) },
                    onClick = {
                        showMenu = false
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("proxy_url", configuration.toUrl())
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                            clip.description.extras = android.os.PersistableBundle().apply {
                                putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
                            }
                        }
                        clipboard.setPrimaryClip(clip)
                    }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.edit)) },
                    leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) },
                    onClick = { showMenu = false; onEdit() }
                )
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                    leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) },
                    onClick = { showMenu = false; onDelete() }
                )
            }
        }
    }
}
