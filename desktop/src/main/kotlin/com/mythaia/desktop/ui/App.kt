package com.mythaia.desktop.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mythaia.desktop.AppState
import com.mythaia.desktop.ConnectionState
import com.mythaia.desktop.Notice
import com.mythaia.desktop.S
import com.mythaia.desktop.tr

private const val MAX_IMPORT_NAMES_SHOWN = 12

enum class Screen(val key: String, val icon: ImageVector) {
    HOME("nav_home", Icons.Default.Home),
    PROXIES("nav_proxies", Icons.Default.List),
    SETTINGS("nav_settings", Icons.Default.Settings),
    LOGS("nav_logs", Icons.Default.Subject)
}

@Composable
fun App(state: AppState) {
    // Reading the language here makes every string below repaint on change.
    S.lang
    var screen by remember { mutableStateOf(Screen.HOME) }
    val message by state.message.collectAsState()
    val pendingImport by state.pendingImport.collectAsState()

    pendingImport?.let { pending ->
        // What a mythaia:// or vless:// link from outside wants to add; nothing is stored until Add.
        val shown = pending.names.take(MAX_IMPORT_NAMES_SHOWN)
        val more = pending.names.size - shown.size
        AlertDialog(
            onDismissRequest = { state.dismissImport() },
            title = { Text(tr("import_link_title")) },
            text = {
                Column {
                    Text(tr("import_link_q", pending.names.size))
                    Spacer(Modifier.height(12.dp))
                    shown.forEach { Text(it, style = MaterialTheme.typography.bodyMedium, maxLines = 1) }
                    if (more > 0) Text(tr("import_link_more", more), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = { Button(onClick = { state.confirmImport() }) { Text(tr("add")) } },
            dismissButton = { TextButton(onClick = { state.dismissImport() }) { Text(tr("cancel")) } }
        )
    }

    Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(modifier = Modifier.weight(1f).fillMaxWidth()) {
                NavRail(state, screen) { screen = it }
                Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                    when (screen) {
                        Screen.HOME -> HomeScreen(state, onOpenProxies = { screen = Screen.PROXIES })
                        Screen.PROXIES -> ProxiesScreen(state)
                        Screen.SETTINGS -> SettingsScreen(state)
                        Screen.LOGS -> LogsScreen(state)
                    }
                }
            }
            StatusBar(state)
        }
        // The last notice stays composed while it fades out.
        var lastNotice by remember { mutableStateOf<Notice?>(null) }
        LaunchedEffect(message) { if (message != null) lastNotice = message }
        AnimatedVisibility(
            visible = message != null,
            enter = fadeIn(),
            exit = fadeOut(),
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 24.dp, start = 24.dp, end = 24.dp)
        ) {
            val notice = message ?: lastNotice
            Surface(
                shape = RoundedCornerShape(18.dp),
                color = MaterialTheme.colorScheme.inverseSurface,
                shadowElevation = 6.dp,
                modifier = Modifier.widthIn(max = 640.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = notice?.text.orEmpty(),
                        color = MaterialTheme.colorScheme.inverseOnSurface,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f, fill = false).padding(start = 18.dp, end = 12.dp, top = 12.dp, bottom = 12.dp)
                    )
                    val label = notice?.actionLabel
                    if (notice != null && label != null) {
                        TextButton(onClick = { state.actOnMessage(notice) }) {
                            Text(label, color = MaterialTheme.colorScheme.inversePrimary)
                        }
                        IconButton(onClick = { state.dismissMessage() }) {
                            Icon(Icons.Default.Close, contentDescription = tr("close"), tint = MaterialTheme.colorScheme.inverseOnSurface)
                        }
                    }
                }
            }
        }
    }
}

/** The v2rayN-style strip along the bottom: state, live server, speed, ports. */
@Composable
private fun StatusBar(state: AppState) {
    val connection by state.connection.collectAsState()
    val speed by state.speed.collectAsState()
    val settings by state.settings.collectAsState()
    val connectivityOk by state.connectivityOk.collectAsState()
    val live = connection.configuration
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val dotColor = when {
            connection is ConnectionState.Connected && connectivityOk -> Azure
            connection is ConnectionState.Connected -> MaterialTheme.colorScheme.error
            else -> MaterialTheme.colorScheme.outline
        }
        Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(dotColor))
        Spacer(Modifier.width(8.dp))
        Text(
            live?.let { "${it.name} · ${it.outboundProtocol.displayName}" } ?: tr("disconnected"),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            modifier = Modifier.weight(1f)
        )
        Text(
            "↑ ${formatBytes(speed.up)}/s   ↓ ${formatBytes(speed.down)}/s",
            style = MaterialTheme.typography.labelMedium.copy(fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace),
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.width(18.dp))
        Text(
            (if (settings.tunnelMode == "tun") tr("status_mode_tun") else tr("status_mode_proxy")) +
                "  ·  " + tr("local_ports", settings.socksPort, settings.httpPort) +
                "  ·  " + (if (settings.isGlobal) tr("mode_global") else tr("mode_rule")),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun NavRail(state: AppState, current: Screen, onSelect: (Screen) -> Unit) {
    val connection by state.connection.collectAsState()
    val connected = connection is ConnectionState.Connected
    Column(
        modifier = Modifier
            .width(212.dp)
            .fillMaxHeight()
            .background(MaterialTheme.colorScheme.surfaceContainerLow)
            .padding(horizontal = 14.dp, vertical = 18.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 8.dp, bottom = 22.dp)) {
            WingIconTile(size = 38.dp) {
                WingMark(modifier = Modifier.size(22.dp), color = Paper)
            }
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    tr("app_name"),
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    if (connected) tr("connected") else tr("disconnected"),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (connected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        Screen.entries.forEach { item ->
            val selected = item == current
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 3.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.12f) else MaterialTheme.colorScheme.surfaceContainerLow)
                    .clickable { onSelect(item) }
                    .padding(horizontal = 14.dp, vertical = 11.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    item.icon,
                    contentDescription = null,
                    tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    tr(item.key),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal),
                    color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                )
            }
        }
        Spacer(Modifier.weight(1f))
        if (!state.nativeAvailable) {
            Text(
                tr("native_missing"),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(8.dp)
            )
        }
        Spacer(Modifier.height(4.dp))
    }
}
