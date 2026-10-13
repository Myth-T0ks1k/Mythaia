package com.mythaia.desktop.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogWindow
import androidx.compose.ui.window.rememberDialogState
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.desktop.AppState
import com.mythaia.desktop.tr
import com.mythaia.desktop.util.Qr
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.util.UUID

/** Which column the table is sorted by. */
private enum class SortKey { NONE, NAME, PROTOCOL, TRANSPORT, ADDRESS, LATENCY }

/** The Proxies screen: server table per group, and the chains tab. */
@Composable
fun ProxiesScreen(state: AppState) {
    var tab by remember { mutableStateOf(0) }
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 16.dp)) {
        SegmentedTabs(
            titles = listOf(tr("nav_proxies"), tr("chain")),
            selected = tab,
            onSelect = { tab = it }
        )
        Spacer(Modifier.height(12.dp))
        when (tab) {
            0 -> ServersTab(state)
            else -> ChainsTab(state)
        }
    }
}

@Composable
private fun SegmentedTabs(titles: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(18.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(4.dp)
    ) {
        titles.forEachIndexed { index, title ->
            val on = index == selected
            Text(
                title,
                style = MaterialTheme.typography.labelLarge,
                color = if (on) Paper else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (on) Azure else MaterialTheme.colorScheme.surfaceContainerLow)
                    .clickable { onSelect(index) }
                    .padding(horizontal = 18.dp, vertical = 9.dp)
            )
        }
    }
}

// ================================================================ servers

@Composable
private fun ServersTab(state: AppState) {
    val settings by state.settings.collectAsState()
    val configurations by state.configurations.collectAsState()
    val subscriptions by state.subscriptions.collectAsState()
    val latencies by state.latencies.collectAsState()
    val updating by state.updating.collectAsState()
    val connection by state.connection.collectAsState()

    val groups = remember(subscriptions, configurations) { state.groups() }
    var shownGroup by remember { mutableStateOf(settings.activeGroupId) }
    if (groups.none { it.id == shownGroup }) shownGroup = AppState.DEFAULT_GROUP
    val group = groups.first { it.id == shownGroup }
    val configs = remember(configurations, shownGroup) { state.groupConfigs(shownGroup) }

    var sortKey by remember { mutableStateOf(SortKey.NONE) }
    var sortAscending by remember { mutableStateOf(true) }
    var search by remember { mutableStateOf("") }
    var selected by remember { mutableStateOf<Set<UUID>>(emptySet()) }
    // Drop selections that are gone.
    val present = configs.map { it.id }.toSet()
    if (selected.any { it !in present }) selected = selected.filter { it in present }.toSet()

    val visible = remember(configs, sortKey, sortAscending, search, latencies) {
        val filtered = if (search.isBlank()) configs else configs.filter {
            it.name.contains(search, ignoreCase = true) || it.displayEndpoint.contains(search, ignoreCase = true) ||
                it.outboundProtocol.displayName.contains(search, ignoreCase = true)
        }
        val sorted = when (sortKey) {
            SortKey.NONE -> filtered
            SortKey.NAME -> filtered.sortedBy { it.name.lowercase() }
            SortKey.PROTOCOL -> filtered.sortedBy { it.outboundProtocol.displayName }
            SortKey.TRANSPORT -> filtered.sortedBy { transportLabel(it) }
            SortKey.ADDRESS -> filtered.sortedBy { it.displayEndpoint }
            SortKey.LATENCY -> filtered.sortedBy { (latencies[it.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE }
        }
        if (sortAscending || sortKey == SortKey.NONE) sorted else sorted.reversed()
    }

    var showAdd by remember { mutableStateOf(false) }
    var editor by remember { mutableStateOf<Pair<Boolean, ProxyConfiguration?>?>(null) }
    var qrOf by remember { mutableStateOf<ProxyConfiguration?>(null) }
    var editSubscription by remember { mutableStateOf<Subscription?>(null) }
    var confirmDeleteSubscription by remember { mutableStateOf<Subscription?>(null) }
    var confirmDelete by remember { mutableStateOf<Set<UUID>?>(null) }
    var renameConfig by remember { mutableStateOf<ProxyConfiguration?>(null) }

    // Group tabs and actions.
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Row(modifier = Modifier.weight(1f).horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            groups.forEach { g ->
                val on = g.id == shownGroup
                val active = g.id == settings.activeGroupId && settings.selectedChainId == null
                Row(
                    modifier = Modifier
                        .clip(RoundedCornerShape(16.dp))
                        .background(if (on) Azure else MaterialTheme.colorScheme.surfaceContainerLow)
                        .clickable { shownGroup = g.id; selected = emptySet() }
                        .padding(horizontal = 14.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (active) {
                        Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(if (on) Paper else Azure))
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(g.name, style = MaterialTheme.typography.labelLarge, color = if (on) Paper else MaterialTheme.colorScheme.onSurface, maxLines = 1)
                }
            }
        }
        Spacer(Modifier.width(8.dp))
        IconButton(onClick = { state.pingGroup(shownGroup, LatencyKind.HTTP) }) {
            Icon(Icons.Default.Speed, tr("ping_real"), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (group.subscription != null) {
            val busy = group.subscription.id in updating
            IconButton(onClick = { state.updateSubscription(group.subscription.id) }, enabled = !busy) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                else Icon(Icons.Default.Refresh, tr("update"), tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        var addMenu by remember { mutableStateOf(false) }
        Box {
            IconButton(onClick = { addMenu = true }) { Icon(Icons.Default.Add, tr("add"), tint = MaterialTheme.colorScheme.primary) }
            DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }) {
                DropdownMenuItem(text = { Text(tr("add_links")) }, onClick = { addMenu = false; showAdd = true })
                DropdownMenuItem(text = { Text(tr("add_from_clipboard")) }, onClick = { addMenu = false; state.importFromClipboard() })
                DropdownMenuItem(text = { Text(tr("scan_screen_qr")) }, onClick = { addMenu = false; state.importFromScreen() })
                DropdownMenuItem(text = { Text(tr("add_manually")) }, onClick = { addMenu = false; editor = true to null })
            }
        }
        var menu by remember { mutableStateOf(false) }
        Box {
            IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                DropdownMenuItem(text = { Text(tr("ping_real")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.HTTP) })
                DropdownMenuItem(text = { Text(tr("ping_tcp")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.TCP) })
                DropdownMenuItem(text = { Text(tr("ping_handshake")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.HANDSHAKE) })
                HorizontalDivider()
                DropdownMenuItem(text = { Text(tr("select_fastest")) }, onClick = { menu = false; state.useAuto(shownGroup) })
                DropdownMenuItem(text = { Text(tr("copy_all_links")) }, onClick = { menu = false; state.copyToClipboard(state.linksOf(configs)) })
                DropdownMenuItem(text = { Text(tr("remove_duplicates")) }, onClick = { menu = false; state.notify(tr("removed_n", state.removeDuplicates(shownGroup))) })
                DropdownMenuItem(text = { Text(tr("remove_failed")) }, onClick = { menu = false; state.notify(tr("removed_n", state.removeFailed(shownGroup))) })
                if (group.subscription != null) {
                    HorizontalDivider()
                    DropdownMenuItem(text = { Text(tr("update_all")) }, onClick = { menu = false; state.updateAllSubscriptions() })
                    DropdownMenuItem(text = { Text(tr("copy_subscription_url")) }, onClick = { menu = false; state.copyToClipboard(group.subscription.url) })
                    DropdownMenuItem(text = { Text(tr("nav_settings")) }, onClick = { menu = false; editSubscription = group.subscription })
                    DropdownMenuItem(text = { Text(tr("delete")) }, onClick = { menu = false; confirmDeleteSubscription = group.subscription })
                }
            }
        }
    }

    // Subscription quota line.
    group.subscription?.let { sub ->
        val parts = mutableListOf<String>()
        val used = (sub.upload ?: 0) + (sub.download ?: 0)
        if (sub.total != null && sub.total!! > 0) parts += tr("traffic_used", formatBytes(used), formatBytes(sub.total!!))
        else if (used > 0) parts += tr("traffic_used", formatBytes(used), tr("unlimited"))
        sub.expire?.let { parts += tr("expires", formatDate(it)) }
        sub.lastUpdate?.let { parts += tr("updated_at", formatDateTime(it)) }
        parts += tr("servers_n", configs.size)
        Text(parts.joinToString("  ·  "), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(start = 6.dp, top = 8.dp))
    }

    Spacer(Modifier.height(10.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        WingField(search, { search = it }, tr("search"), modifier = Modifier.weight(1f))
        if (selected.isNotEmpty()) {
            Spacer(Modifier.width(10.dp))
            Text(tr("selected_n", selected.size), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            TextButton(onClick = { state.copyToClipboard(state.linksOf(configs.filter { it.id in selected })) }) { Text(tr("copy_link")) }
            TextButton(onClick = { configs.filter { it.id in selected }.forEach { state.pingOne(it) } }) { Text(tr("ping")) }
            TextButton(onClick = { confirmDelete = selected }) { Text(tr("delete"), color = MaterialTheme.colorScheme.error) }
        }
    }
    Spacer(Modifier.height(10.dp))

    // The Auto row.
    val auto = state.isAuto(shownGroup)
    val autoActive = auto && settings.activeGroupId == shownGroup && settings.selectedChainId == null
    val choice = state.autoChoice(shownGroup)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(if (autoActive) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else MaterialTheme.colorScheme.surfaceContainerLow)
            .clickable { state.useAuto(shownGroup) }
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        WingIconTile(size = 34.dp) { Icon(Icons.Default.Bolt, null, tint = Paper, modifier = Modifier.size(20.dp)) }
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(tr("auto_best"), style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium), color = MaterialTheme.colorScheme.onSurface)
            Text(choice?.let { "${it.name} · ${it.outboundProtocol.displayName}" } ?: tr("auto_row_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        }
        if (autoActive) Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary)
    }
    Spacer(Modifier.height(6.dp))

    // The table.
    val liveId = connection.configuration?.id
    val pinnedId = state.pinned(shownGroup)?.id?.takeIf { settings.activeGroupId == shownGroup && settings.selectedChainId == null }
    WingPanel(modifier = Modifier.fillMaxSize()) {
        Column {
            HeaderRow(
                allSelected = visible.isNotEmpty() && visible.all { it.id in selected },
                onToggleAll = { all -> selected = if (all) visible.map { it.id }.toSet() else emptySet() },
                sortKey = sortKey, ascending = sortAscending,
                onSort = { key ->
                    if (sortKey == key) { if (sortAscending) sortAscending = false else { sortKey = SortKey.NONE; sortAscending = true } }
                    else { sortKey = key; sortAscending = true }
                }
            )
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            if (visible.isEmpty()) {
                Text(tr("empty_group"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
            }
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(visible, key = { it.id }) { config ->
                    ServerRow(
                        config = config,
                        checked = config.id in selected,
                        onCheck = { on -> selected = if (on) selected + config.id else selected - config.id },
                        pinned = pinnedId == config.id,
                        live = liveId == config.id,
                        latency = latencies[config.id],
                        onClick = { state.pin(config) },
                        onPing = { state.pingOne(config) },
                        onCopy = { runCatching { config.toUrl() }.onSuccess { state.copyToClipboard(it) } },
                        onQr = { qrOf = config },
                        onRename = { renameConfig = config },
                        onEdit = { editor = true to config },
                        onDelete = { confirmDelete = setOf(config.id) }
                    )
                }
                item { Spacer(Modifier.height(24.dp)) }
            }
        }
    }

    // Dialogs.
    editor?.let { (_, config) ->
        val scheme = MaterialTheme.colorScheme
        DialogWindow(
            onCloseRequest = { editor = null },
            title = if (config == null) tr("add_configuration") else tr("edit_configuration"),
            state = rememberDialogState(size = DpSize(560.dp, 720.dp))
        ) {
            MaterialTheme(colorScheme = scheme) {
                if (config == null) {
                    NewServerFlow(onSave = { state.saveConfiguration(it); editor = null }, onDismiss = { editor = null })
                } else {
                    ServerEditor(configuration = config, onSave = { state.saveConfiguration(it); editor = null }, onDismiss = { editor = null })
                }
            }
        }
    }
    qrOf?.let { config -> QrDialog(config, onDismiss = { qrOf = null }) }
    if (showAdd) AddDialog(onDismiss = { showAdd = false }) { text, name, sni, targets ->
        state.addText(text, name, sni, targets)
        showAdd = false
    }
    editSubscription?.let { sub ->
        SubscriptionDialog(sub, onDismiss = { editSubscription = null }) { name, sni, targets ->
            state.updateSubscriptionSettings(sub.id, name, sni, targets)
            editSubscription = null
        }
    }
    confirmDeleteSubscription?.let { sub ->
        ConfirmDialog(tr("delete_subscription_q"), onDismiss = { confirmDeleteSubscription = null }) {
            state.deleteSubscription(sub.id)
            confirmDeleteSubscription = null
            shownGroup = AppState.DEFAULT_GROUP
        }
    }
    confirmDelete?.let { ids ->
        ConfirmDialog(if (ids.size == 1) tr("delete_config_q") else tr("delete_n_q", ids.size), onDismiss = { confirmDelete = null }) {
            state.deleteConfigurations(ids)
            selected = selected - ids
            confirmDelete = null
        }
    }
    renameConfig?.let { config ->
        var name by remember(config.id) { mutableStateOf(config.name) }
        AlertDialog(
            onDismissRequest = { renameConfig = null },
            title = { Text(tr("rename")) },
            text = { WingField(name, { name = it }, tr("rename")) },
            confirmButton = { Button(onClick = { state.renameConfiguration(config, name); renameConfig = null }, enabled = name.isNotBlank()) { Text(tr("save")) } },
            dismissButton = { TextButton(onClick = { renameConfig = null }) { Text(tr("cancel")) } }
        )
    }
}

private fun transportLabel(config: ProxyConfiguration): String {
    val transport = when (config.transport) {
        "tcp", "" -> "tcp"
        else -> config.transport
    }
    val security = when {
        config.reality != null -> "reality"
        config.security == "tls" || config.tls != null || config.trojanTls != null -> "tls"
        else -> null
    }
    return listOfNotNull(transport, security).joinToString(" · ")
}

@Composable
private fun HeaderRow(
    allSelected: Boolean,
    onToggleAll: (Boolean) -> Unit,
    sortKey: SortKey,
    ascending: Boolean,
    onSort: (SortKey) -> Unit
) {
    Row(modifier = Modifier.fillMaxWidth().padding(start = 6.dp, end = 52.dp, top = 4.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = allSelected, onCheckedChange = onToggleAll, modifier = Modifier.size(36.dp))
        Spacer(Modifier.width(14.dp))
        HeaderCell(tr("col_name"), SortKey.NAME, sortKey, ascending, onSort, Modifier.weight(2.2f))
        HeaderCell(tr("protocol"), SortKey.PROTOCOL, sortKey, ascending, onSort, Modifier.weight(0.9f))
        HeaderCell(tr("transport"), SortKey.TRANSPORT, sortKey, ascending, onSort, Modifier.weight(1f))
        HeaderCell(tr("address"), SortKey.ADDRESS, sortKey, ascending, onSort, Modifier.weight(1.6f))
        HeaderCell(tr("ping"), SortKey.LATENCY, sortKey, ascending, onSort, Modifier.width(96.dp))
    }
}

@Composable
private fun HeaderCell(title: String, key: SortKey, current: SortKey, ascending: Boolean, onSort: (SortKey) -> Unit, modifier: Modifier) {
    Row(modifier = modifier.clickable { onSort(key) }, verticalAlignment = Alignment.CenterVertically) {
        Text(title, style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold), color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        if (current == key) {
            Icon(if (ascending) Icons.Default.ArrowUpward else Icons.Default.ArrowDownward, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(14.dp).padding(start = 2.dp))
        }
    }
}

@Composable
private fun ServerRow(
    config: ProxyConfiguration,
    checked: Boolean,
    onCheck: (Boolean) -> Unit,
    pinned: Boolean,
    live: Boolean,
    latency: LatencyResult?,
    onClick: () -> Unit,
    onPing: () -> Unit,
    onCopy: () -> Unit,
    onQr: () -> Unit,
    onRename: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    var menu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (pinned) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else MaterialTheme.colorScheme.surfaceContainerLow)
            .clickable { onClick() }
            .padding(start = 6.dp, end = 4.dp, top = 2.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheck, modifier = Modifier.size(36.dp))
        Box(Modifier.width(4.dp).height(30.dp).clip(RoundedCornerShape(2.dp)).background(if (live) Azure else MaterialTheme.colorScheme.surfaceContainerLow))
        Spacer(Modifier.width(10.dp))
        Text(
            config.name,
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = if (live) FontWeight.SemiBold else FontWeight.Normal),
            color = MaterialTheme.colorScheme.onSurface, maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(2.2f)
        )
        // A server whose certificate is not checked says so on its row.
        if (config.skipsCertificateCheck) {
            Text(
                tr("insecure_caps"),
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onError,
                maxLines = 1,
                modifier = Modifier
                    .padding(end = 8.dp)
                    .clip(RoundedCornerShape(6.dp))
                    .background(MaterialTheme.colorScheme.error)
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }
        Text(config.outboundProtocol.displayName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, modifier = Modifier.weight(0.9f))
        Text(transportLabel(config), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, modifier = Modifier.weight(1f))
        Text(config.displayEndpoint, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1.6f))
        Box(modifier = Modifier.width(96.dp), contentAlignment = Alignment.CenterStart) { LatencyBadge(latency) }
        if (pinned) Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
        Box {
            IconButton(onClick = { menu = true }, modifier = Modifier.size(36.dp)) { Icon(Icons.Default.MoreVert, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                DropdownMenuItem(text = { Text(tr("ping_real")) }, onClick = { menu = false; onPing() })
                DropdownMenuItem(text = { Text(tr("edit")) }, onClick = { menu = false; onEdit() })
                DropdownMenuItem(text = { Text(tr("rename")) }, onClick = { menu = false; onRename() })
                DropdownMenuItem(text = { Text(tr("copy_link")) }, onClick = { menu = false; onCopy() })
                DropdownMenuItem(text = { Text(tr("show_qr")) }, onClick = { menu = false; onQr() })
                HorizontalDivider()
                DropdownMenuItem(text = { Text(tr("delete")) }, onClick = { menu = false; onDelete() })
            }
        }
    }
}

@Composable
private fun QrDialog(config: ProxyConfiguration, onDismiss: () -> Unit) {
    val link = remember(config.id) { runCatching { config.toUrl() }.getOrNull() }
    val image = remember(link) { link?.let { Qr.encode(it, 440) } }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(config.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                if (image != null) {
                    Image(image, contentDescription = link, modifier = Modifier.size(300.dp).clip(RoundedCornerShape(12.dp)).background(androidx.compose.ui.graphics.Color.White))
                } else {
                    Text(tr("nothing_parsed"))
                }
                Spacer(Modifier.height(8.dp))
                Text(link.orEmpty().take(120), style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 3)
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(tr("ok")) } }
    )
}

// ================================================================= chains

@Composable
private fun ChainsTab(state: AppState) {
    val chains by state.chains.collectAsState()
    val settings by state.settings.collectAsState()
    val configurations by state.configurations.collectAsState()
    var editing by remember { mutableStateOf<ProxyChain?>(null) }
    var creating by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf<ProxyChain?>(null) }

    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(tr("chains_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
        Button(onClick = { creating = true }) { Text(tr("chain_new")) }
    }
    Spacer(Modifier.height(10.dp))
    WingPanel(modifier = Modifier.fillMaxSize()) {
        if (chains.isEmpty()) {
            Text(tr("chains_empty"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
        }
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(chains, key = { it.id }) { chain ->
                val byId = configurations.associateBy { it.id }
                val hops = chain.proxyIds.map { byId[it]?.name ?: "?" }
                val on = settings.selectedChainId == chain.id.toString()
                val usable = state.resolveChain(chain) != null
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(if (on) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else MaterialTheme.colorScheme.surfaceContainerLow)
                        .clickable(enabled = usable) { state.selectChain(if (on) null else chain) }
                        .padding(horizontal = 14.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    WingIconTile(size = 34.dp) { WingMark(modifier = Modifier.size(18.dp), color = Paper) }
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(chain.name, style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium), color = if (usable) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
                        Text(hops.joinToString("  →  "), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
                    }
                    if (on) Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary)
                    IconButton(onClick = { editing = chain }) { Icon(Icons.Default.MoreVert, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) }
                    IconButton(onClick = { confirmDelete = chain }) { Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
        }
    }

    if (creating || editing != null) {
        val chain = editing ?: ProxyChain(name = tr("chain_new"))
        ChainDialog(chain, configurations, onDismiss = { creating = false; editing = null }) {
            state.saveChain(it)
            creating = false
            editing = null
        }
    }
    confirmDelete?.let { chain ->
        ConfirmDialog(tr("delete_chain_q"), onDismiss = { confirmDelete = null }) {
            state.deleteChain(chain.id)
            confirmDelete = null
        }
    }
}

@Composable
private fun ChainDialog(chain: ProxyChain, all: List<ProxyConfiguration>, onDismiss: () -> Unit, onSave: (ProxyChain) -> Unit) {
    var name by remember(chain.id) { mutableStateOf(chain.name) }
    var hops by remember(chain.id) { mutableStateOf(chain.proxyIds) }
    var pickerOpen by remember { mutableStateOf(false) }
    val byId = all.associateBy { it.id }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(tr("chain")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                WingField(name, { name = it }, tr("name"))
                Text(tr("chain_order_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                hops.forEachIndexed { index, id ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("${index + 1}.", style = MaterialTheme.typography.labelLarge, modifier = Modifier.width(24.dp))
                        Text(byId[id]?.name ?: "?", modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        IconButton(onClick = { if (index > 0) hops = hops.toMutableList().apply { add(index - 1, removeAt(index)) } }, enabled = index > 0) { Icon(Icons.Default.ArrowUpward, null) }
                        IconButton(onClick = { if (index < hops.lastIndex) hops = hops.toMutableList().apply { add(index + 1, removeAt(index)) } }, enabled = index < hops.lastIndex) { Icon(Icons.Default.ArrowDownward, null) }
                        IconButton(onClick = { hops = hops.filterIndexed { i, _ -> i != index } }) { Icon(Icons.Default.Delete, null) }
                    }
                }
                Box {
                    TextButton(onClick = { pickerOpen = true }) { Text(tr("chain_add_hop")) }
                    DropdownMenu(expanded = pickerOpen, onDismissRequest = { pickerOpen = false }) {
                        all.forEach { c ->
                            DropdownMenuItem(text = { Text("${c.name} · ${c.outboundProtocol.displayName}", maxLines = 1) }, onClick = { hops = hops + c.id; pickerOpen = false })
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSave(chain.copy(name = name.trim().ifEmpty { chain.name }, proxyIds = hops)) }, enabled = hops.size >= 2) { Text(tr("save")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("cancel")) } }
    )
}

// ================================================================ dialogs

@Composable
private fun AddDialog(onDismiss: () -> Unit, onAdd: (String, String?, String?, List<String>) -> Unit) {
    var text by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var sni by remember { mutableStateOf("") }
    var targets by remember { mutableStateOf("") }
    var fronting by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(tr("add_links")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                WingField(text, { text = it }, tr("add_links"), placeholder = tr("add_hint"), singleLine = false, minLines = 5)
                Row {
                    TextButton(onClick = {
                        runCatching { Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String }
                            .getOrNull()?.let { text = if (text.isBlank()) it else text + "\n" + it }
                    }) { Text(tr("add_from_clipboard")) }
                    TextButton(onClick = { fronting = !fronting }) { Text(tr("front_sni")) }
                }
                if (text.lineSequence().any { it.trim().startsWith("http", ignoreCase = true) } || fronting) {
                    WingField(name, { name = it }, tr("subscription_name"))
                }
                if (fronting) {
                    WingField(sni, { sni = it }, tr("front_sni"))
                    WingField(targets, { targets = it }, tr("front_targets"))
                }
            }
        },
        confirmButton = {
            Button(onClick = { onAdd(text, name.ifBlank { null }, sni.ifBlank { null }, targets.split(',').map { it.trim() }.filter { it.isNotEmpty() }) }, enabled = text.isNotBlank()) { Text(tr("add")) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("cancel")) } }
    )
}

@Composable
private fun SubscriptionDialog(sub: Subscription, onDismiss: () -> Unit, onSave: (String, String?, List<String>) -> Unit) {
    var name by remember { mutableStateOf(sub.name) }
    var sni by remember { mutableStateOf(sub.frontSni.orEmpty()) }
    var targets by remember { mutableStateOf(sub.frontTargets.joinToString(", ")) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(sub.name) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(sub.url, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
                WingField(name, { name = it }, tr("subscription_name"))
                WingField(sni, { sni = it }, tr("front_sni"))
                WingField(targets, { targets = it }, tr("front_targets"))
            }
        },
        confirmButton = { Button(onClick = { onSave(name, sni.ifBlank { null }, targets.split(',').map { it.trim() }.filter { it.isNotEmpty() }) }) { Text(tr("save")) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("cancel")) } }
    )
}

@Composable
fun ConfirmDialog(question: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        text = { Text(question) },
        confirmButton = { Button(onClick = onConfirm) { Text(tr("yes")) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("cancel")) } }
    )
}
