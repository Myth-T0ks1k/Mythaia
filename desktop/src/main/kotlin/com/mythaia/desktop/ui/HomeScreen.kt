package com.mythaia.desktop.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mythaia.desktop.AppState
import com.mythaia.desktop.ConnectionState
import com.mythaia.desktop.tr
import kotlinx.coroutines.delay

@Composable
fun HomeScreen(state: AppState, onOpenProxies: () -> Unit) {
    val connection by state.connection.collectAsState()
    val settings by state.settings.collectAsState()
    val latencies by state.latencies.collectAsState()
    val connectivityOk by state.connectivityOk.collectAsState()
    val connectedSince by state.connectedSince.collectAsState()
    val configurations by state.configurations.collectAsState()
    val subscriptions by state.subscriptions.collectAsState()
    val speed by state.speed.collectAsState()
    val needsElevation by state.needsElevation.collectAsState()
    if (needsElevation) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { state.needsElevation.value = false },
            text = { androidx.compose.material3.Text(tr("tun_needs_admin")) },
            confirmButton = {
                androidx.compose.material3.Button(onClick = {
                    state.needsElevation.value = false
                    state.relaunchElevated()
                }) { androidx.compose.material3.Text(tr("tun_relaunch")) }
            },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { state.needsElevation.value = false }) { androidx.compose.material3.Text(tr("cancel")) } }
        )
    }

    // A one-second tick for the counters.
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    var up by remember { mutableStateOf(0L) }
    var down by remember { mutableStateOf(0L) }
    LaunchedEffect(Unit) {
        while (true) {
            now = System.currentTimeMillis()
            up = state.stats.up.get()
            down = state.stats.down.get()
            delay(1000)
        }
    }

    val connected = connection is ConnectionState.Connected
    val connecting = connection is ConnectionState.Connecting
    val groupId = settings.activeGroupId
    val groups = remember(subscriptions, configurations) { state.groups() }
    val shown = connection.configuration ?: state.effectiveConfig(groupId)

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 32.dp, vertical = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(8.dp))

        val statusText = when (val c = connection) {
            is ConnectionState.Disconnected -> tr("disconnected")
            is ConnectionState.Connecting -> tr("connecting")
            is ConnectionState.Connected -> if (connectivityOk) tr("connected") else tr("no_internet")
            is ConnectionState.Failed -> c.message
        }
        val statusColor = when {
            connection is ConnectionState.Failed -> MaterialTheme.colorScheme.error
            connected && !connectivityOk -> MaterialTheme.colorScheme.error
            connected -> MaterialTheme.colorScheme.primary
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        }

        // The connect button: a large tile with the mark, azure when live.
        val tileColor by animateColorAsState(
            if (connected) Azure else MaterialTheme.colorScheme.surfaceContainerHigh
        )
        val markColor = if (connected) Paper else MaterialTheme.colorScheme.primary
        Box(
            modifier = Modifier
                .size(176.dp)
                .shadow(if (connected) 18.dp else 2.dp, CircleShape, spotColor = Azure.copy(alpha = 0.5f))
                .clip(CircleShape)
                .background(
                    if (connected) Brush.linearGradient(listOf(LightAzure, Azure, AzureDeep))
                    else Brush.linearGradient(listOf(tileColor, tileColor))
                )
                .clickable(enabled = !connecting) { state.toggle() },
            contentAlignment = Alignment.Center
        ) {
            if (connecting) {
                CircularProgressIndicator(color = MaterialTheme.colorScheme.primary, strokeWidth = 3.dp, modifier = Modifier.size(52.dp))
            } else {
                WingMark(modifier = Modifier.size(92.dp), color = markColor)
            }
        }
        Spacer(Modifier.height(18.dp))
        Text(
            statusText,
            style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
            color = statusColor
        )
        Text(
            if (connected || connecting) tr("disconnect") else tr("connect"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 4.dp)
        )

        Spacer(Modifier.height(26.dp))

        // Group and mode.
        Row(
            modifier = Modifier.widthIn(max = 620.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            var open by remember { mutableStateOf(false) }
            val groupName = groups.firstOrNull { it.id == groupId }?.name ?: tr("group_default")
            Box(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerLow)
                        .clickable { open = true }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(tr("group"), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(groupName, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
                    }
                    Icon(Icons.Default.KeyboardArrowDown, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                    groups.forEach { g ->
                        DropdownMenuItem(
                            text = { Text("${g.name}  ·  ${tr("servers_n", state.groupConfigs(g.id).size)}") },
                            trailingIcon = if (g.id == groupId) ({ Icon(Icons.Default.Check, null) }) else null,
                            onClick = { state.selectGroup(g.id); open = false }
                        )
                    }
                }
            }
            ModePill(
                global = settings.isGlobal,
                onChange = { global -> state.updateSettings { it.copy(routeMode = if (global) "global" else "rule") } }
            )
        }

        Spacer(Modifier.height(12.dp))

        // The live (or would-be) server.
        WingPanel(modifier = Modifier.widthIn(max = 620.dp)) {
            val autoActive = state.isAuto(groupId) && settings.selectedChainId == null
            Row(
                modifier = Modifier.fillMaxWidth().clickable { onOpenProxies() }.padding(horizontal = 18.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                WingIconTile(size = 40.dp) {
                    if (autoActive) Icon(Icons.Default.Bolt, null, tint = Paper, modifier = Modifier.size(22.dp))
                    else WingMark(modifier = Modifier.size(22.dp), color = Paper)
                }
                Spacer(Modifier.width(14.dp))
                Column(modifier = Modifier.weight(1f)) {
                    if (shown == null) {
                        Text(tr("no_server"), style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
                        Text(tr("no_servers_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    } else {
                        Text(
                            if (autoActive) tr("auto_switching", shown.name) else shown.name,
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1
                        )
                        Text(
                            "${shown.outboundProtocol.displayName} · ${shown.displayEndpoint}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    }
                }
                if (shown != null) LatencyBadge(latencies[shown.id])
            }
        }

        Spacer(Modifier.height(12.dp))

        // Counters.
        Row(modifier = Modifier.widthIn(max = 620.dp).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(tr("uptime"), connectedSince?.let { formatDuration(now - it) } ?: "—", Modifier.weight(1f))
            StatTile(tr("speed"), "↑ ${formatBytes(speed.up)}/s\n↓ ${formatBytes(speed.down)}/s", Modifier.weight(1.3f))
            StatTile(tr("upload"), formatBytes(up), Modifier.weight(1f))
            StatTile(tr("download"), formatBytes(down), Modifier.weight(1f))
        }

        Spacer(Modifier.height(18.dp))
        Text(
            (if (connected && settings.setSystemProxy) tr("system_proxy_on") else tr("system_proxy_off")) +
                "  ·  " + tr("local_ports", settings.socksPort, settings.httpPort),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun StatTile(label: String, value: String, modifier: Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(18.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(horizontal = 16.dp, vertical = 12.dp)
    ) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold),
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

/** Rules | Global, as one azure pill. */
@Composable
fun ModePill(global: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(18.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(4.dp)
    ) {
        listOf(false to tr("mode_rule"), true to tr("mode_global")).forEach { (isGlobal, label) ->
            val selected = isGlobal == global
            Text(
                label,
                style = MaterialTheme.typography.labelLarge,
                color = if (selected) Paper else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .clip(RoundedCornerShape(14.dp))
                    .background(if (selected) Azure else MaterialTheme.colorScheme.surfaceContainerLow)
                    .clickable { onChange(isGlobal) }
                    .padding(horizontal = 16.dp, vertical = 10.dp)
            )
        }
    }
}
