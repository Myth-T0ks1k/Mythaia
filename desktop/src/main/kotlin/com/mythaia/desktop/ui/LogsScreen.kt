package com.mythaia.desktop.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.mythaia.desktop.AppState
import com.mythaia.desktop.tr
import com.mythaia.vpn.util.MythaiaLogger
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss")

@Composable
fun LogsScreen(state: AppState) {
    val logs by state.logs.collectAsState()
    val listState = rememberLazyListState()
    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) listState.animateScrollToItem(logs.size - 1)
    }
    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 24.dp, vertical = 18.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            WingSectionTitle(tr("nav_logs"), modifier = Modifier.weight(1f))
            TextButton(onClick = { state.clearLogs() }) { Text(tr("logs_clear")) }
        }
        Spacer(Modifier.height(6.dp))
        WingPanel(modifier = Modifier.fillMaxSize()) {
            if (logs.isEmpty()) {
                Text(tr("logs_empty"), modifier = Modifier.padding(18.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            LazyColumn(state = listState, modifier = Modifier.fillMaxSize().padding(12.dp)) {
                items(logs) { line ->
                    val color = when (line.level) {
                        MythaiaLogger.Level.error -> MaterialTheme.colorScheme.error
                        MythaiaLogger.Level.warning -> if (LocalDarkTheme.current) WarningDark else WarningLight
                        MythaiaLogger.Level.info -> MaterialTheme.colorScheme.onSurface
                    }
                    val time = Instant.ofEpochMilli(line.time).atZone(ZoneId.systemDefault()).format(timeFormat)
                    Text(
                        "$time  ${line.text}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = color,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }
            }
        }
    }
}
