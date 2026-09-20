package com.mythaia.desktop.ui

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
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.desktop.AppState
import com.mythaia.desktop.tr
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection

@Composable
fun ProxiesScreen(state: AppState) {
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
    val configs = remember(configurations, shownGroup, latencies) {
        state.groupConfigs(shownGroup)
    }
    var sortByLatency by remember { mutableStateOf(false) }
    val sorted = if (sortByLatency) configs.sortedBy { (latencies[it.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE } else configs
    var search by remember { mutableStateOf("") }
    val visible = if (search.isBlank()) sorted else sorted.filter {
        it.name.contains(search, ignoreCase = true) || it.displayEndpoint.contains(search, ignoreCase = true)
    }

    var showAdd by remember { mutableStateOf(false) }
    // null = closed; Optional-like holder so a null configuration (new server) can be edited too.
    var editor by remember { mutableStateOf<Pair<Boolean, ProxyConfiguration?>?>(null) }
    var editSubscription by remember { mutableStateOf<Subscription?>(null) }
    var confirmDeleteSubscription by remember { mutableStateOf<Subscription?>(null) }
    var confirmDeleteConfig by remember { mutableStateOf<ProxyConfiguration?>(null) }
    var renameConfig by remember { mutableStateOf<ProxyConfiguration?>(null) }

    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 18.dp)) {
        // Group tabs and actions.
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Row(modifier = Modifier.weight(1f).horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                groups.forEach { g ->
                    val selected = g.id == shownGroup
                    val active = g.id == settings.activeGroupId
                    Row(
                        modifier = Modifier
                            .clip(RoundedCornerShape(16.dp))
                            .background(if (selected) Azure else MaterialTheme.colorScheme.surfaceContainerLow)
                            .clickable { shownGroup = g.id }
                            .padding(horizontal = 14.dp, vertical = 9.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (active) {
                            Box(Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(if (selected) Paper else Azure))
                            Spacer(Modifier.width(8.dp))
                        }
                        Text(
                            g.name,
                            style = MaterialTheme.typography.labelLarge,
                            color = if (selected) Paper else MaterialTheme.colorScheme.onSurface,
                            maxLines = 1
                        )
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
            IconButton(onClick = { showAdd = true }) {
                Icon(Icons.Default.Add, tr("add"), tint = MaterialTheme.colorScheme.primary)
            }
            var menu by remember { mutableStateOf(false) }
            Box {
                IconButton(onClick = { menu = true }) {
                    Icon(Icons.Default.MoreVert, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text(tr("ping_real")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.HTTP) })
                    DropdownMenuItem(text = { Text(tr("ping_tcp")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.TCP) })
                    DropdownMenuItem(text = { Text(tr("ping_handshake")) }, onClick = { menu = false; state.pingGroup(shownGroup, LatencyKind.HANDSHAKE) })
                    HorizontalDivider()
                    DropdownMenuItem(text = { Text(tr("select_fastest")) }, onClick = { menu = false; state.useAuto(shownGroup) })
                    DropdownMenuItem(
                        text = { Text(tr("sort_by_latency")) },
                        trailingIcon = if (sortByLatency) ({ Icon(Icons.Default.Check, null) }) else null,
                        onClick = { menu = false; sortByLatency = !sortByLatency }
                    )
                    HorizontalDivider()
                    DropdownMenuItem(text = { Text(tr("add_manually")) }, onClick = { menu = false; editor = true to null })
                    DropdownMenuItem(text = { Text(tr("remove_duplicates")) }, onClick = {
                        menu = false
                        state.notify(tr("removed_n", state.removeDuplicates(shownGroup)))
                    })
                    DropdownMenuItem(text = { Text(tr("remove_failed")) }, onClick = {
                        menu = false
                        state.notify(tr("removed_n", state.removeFailed(shownGroup)))
                    })
                    if (group.subscription != null) {
                        HorizontalDivider()
                        DropdownMenuItem(text = { Text(tr("update_all")) }, onClick = { menu = false; state.updateAllSubscriptions() })
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
            parts += tr("servers_n", configs.size)
            Text(
                parts.joinToString("  ·  "),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 6.dp, top = 8.dp)
            )
        }

        Spacer(Modifier.height(10.dp))
        WingField(search, { search = it }, tr("search"))
        Spacer(Modifier.height(10.dp))

        val liveId = connection.configuration?.id
        LazyColumn(modifier = Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            item {
                val auto = state.isAuto(shownGroup)
                val choice = state.autoChoice(shownGroup)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(if (auto && settings.activeGroupId == shownGroup) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else MaterialTheme.colorScheme.surfaceContainerLow)
                        .clickable { state.useAuto(shownGroup) }
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    WingIconTile(size = 36.dp) { Icon(Icons.Default.Bolt, null, tint = Paper, modifier = Modifier.size(20.dp)) }
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(tr("auto_best"), style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium), color = MaterialTheme.colorScheme.onSurface)
                        Text(
                            choice?.let { "${it.name} · ${it.outboundProtocol.displayName}" } ?: tr("auto_row_hint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                    if (auto && settings.activeGroupId == shownGroup) Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary)
                }
            }
            if (visible.isEmpty()) {
                item {
                    Text(
                        tr("empty_group"),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
            items(visible, key = { it.id }) { config ->
                val pinnedHere = state.pinned(shownGroup)?.id == config.id && settings.activeGroupId == shownGroup
                ProxyRow(
                    config = config,
                    selected = pinnedHere,
                    live = liveId == config.id,
                    latency = latencies[config.id],
                    onClick = { state.pin(config) },
                    onPing = { state.pingOne(config) },
                    onCopy = {
                        runCatching { config.toUrl() }.onSuccess {
                            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(it), null)
                            state.notify(tr("copied"))
                        }
                    },
                    onRename = { renameConfig = config },
                    onEdit = { editor = true to config },
                    onDelete = { confirmDeleteConfig = config }
                )
            }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }

    editor?.let { (_, config) ->
        androidx.compose.ui.window.DialogWindow(
            onCloseRequest = { editor = null },
            title = if (config == null) tr("add_configuration") else tr("edit_configuration"),
            state = androidx.compose.ui.window.rememberDialogState(
                size = androidx.compose.ui.unit.DpSize(560.dp, 720.dp)
            )
        ) {
            ServerEditor(
                configuration = config,
                onSave = { state.saveConfiguration(it); editor = null },
                onDismiss = { editor = null }
            )
        }
    }

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
    confirmDeleteConfig?.let { config ->
        ConfirmDialog(tr("delete_config_q"), onDismiss = { confirmDeleteConfig = null }) {
            state.deleteConfiguration(config)
            confirmDeleteConfig = null
        }
    }
    renameConfig?.let { config ->
        var name by remember(config.id) { mutableStateOf(config.name) }
        AlertDialog(
            onDismissRequest = { renameConfig = null },
            title = { Text(tr("rename")) },
            text = { WingField(name, { name = it }, tr("rename")) },
            confirmButton = {
                Button(onClick = { state.renameConfiguration(config, name); renameConfig = null }, enabled = name.isNotBlank()) { Text(tr("save")) }
            },
            dismissButton = { TextButton(onClick = { renameConfig = null }) { Text(tr("cancel")) } }
        )
    }
}

@Composable
private fun ProxyRow(
    config: ProxyConfiguration,
    selected: Boolean,
    live: Boolean,
    latency: LatencyResult?,
    onClick: () -> Unit,
    onPing: () -> Unit,
    onCopy: () -> Unit,
    onRename: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    var menu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else MaterialTheme.colorScheme.surfaceContainerLow)
            .clickable { onClick() }
            .padding(start = 8.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // The azure feather bar marks the live server.
        Box(
            modifier = Modifier
                .width(4.dp)
                .height(34.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(if (live) Azure else MaterialTheme.colorScheme.surfaceContainerLow)
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                config.name,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = if (live) FontWeight.SemiBold else FontWeight.Normal),
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1
            )
            Text(
                "${config.outboundProtocol.displayName} · ${config.displayEndpoint}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
        }
        LatencyBadge(latency, modifier = Modifier.padding(horizontal = 6.dp))
        if (selected) Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(horizontal = 4.dp))
        Box {
            IconButton(onClick = { menu = true }) {
                Icon(Icons.Default.MoreVert, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                DropdownMenuItem(text = { Text(tr("ping_real")) }, onClick = { menu = false; onPing() })
                DropdownMenuItem(text = { Text(tr("copy_link")) }, onClick = { menu = false; onCopy() })
                DropdownMenuItem(text = { Text(tr("edit")) }, onClick = { menu = false; onEdit() })
                DropdownMenuItem(text = { Text(tr("rename")) }, onClick = { menu = false; onRename() })
                DropdownMenuItem(text = { Text(tr("delete")) }, onClick = { menu = false; onDelete() })
            }
        }
    }
}

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
                        runCatching {
                            Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String
                        }.getOrNull()?.let { text = if (text.isBlank()) it else text + "\n" + it }
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
            Button(
                onClick = { onAdd(text, name.ifBlank { null }, sni.ifBlank { null }, targets.split(',').map { it.trim() }.filter { it.isNotEmpty() }) },
                enabled = text.isNotBlank()
            ) { Text(tr("add")) }
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
        confirmButton = {
            Button(onClick = { onSave(name, sni.ifBlank { null }, targets.split(',').map { it.trim() }.filter { it.isNotEmpty() }) }) { Text(tr("save")) }
        },
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
