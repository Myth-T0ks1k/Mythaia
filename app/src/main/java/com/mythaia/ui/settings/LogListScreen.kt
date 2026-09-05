package com.mythaia.ui.settings

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.PopupProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import com.mythaia.R
import com.mythaia.ui.theme.WarningDark
import com.mythaia.ui.theme.WarningLight
import com.mythaia.viewmodel.LogsModel
import kotlinx.coroutines.flow.StateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.runtime.collectAsState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogListScreen(
    onBack: () -> Unit,
    logsModel: LogsModel = viewModel()
) {
    val context = LocalContext.current
    val logs by logsModel.logs.collectAsState()

    var selectMode by remember { mutableStateOf(false) }
    val selection = remember { mutableStateMapOf<Long, Unit>() }

    DisposableEffect(Unit) {
        logsModel.startPolling()
        onDispose { logsModel.stopPolling() }
    }

    // Toggling select mode pauses polling so the list doesn't shift while picking.
    LaunchedEffect(selectMode) {
        if (selectMode) {
            logsModel.stopPolling(clearLogs = false)
        } else {
            logsModel.startPolling()
            selection.clear()
        }
    }

    BackHandler {
        if (selectMode) selectMode = false else onBack()
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.logs)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onBackground,
                    actionIconContentColor = MaterialTheme.colorScheme.primary
                ),
                navigationIcon = {
                    IconButton(onClick = { if (selectMode) selectMode = false else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                    }
                },
                actions = {
                    if (selectMode) {
                        val label = if (selection.isEmpty()) {
                            stringResource(R.string.cancel)
                        } else {
                            stringResource(R.string.copy_count, selection.size)
                        }
                        TextButton(onClick = {
                            if (selection.isEmpty()) {
                                selectMode = false
                            } else {
                                copyToClipboard(
                                    context,
                                    logs.filter { selection.contains(it.id) }.joinToString("\n") { it.formatted() }
                                )
                                selection.clear()
                                selectMode = false
                            }
                        }) { Text(label) }
                    } else {
                        TextButton(onClick = { selectMode = true }) {
                            Text(stringResource(R.string.select))
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        if (logs.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(56.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.size(12.dp))
                    Text(
                        stringResource(R.string.no_recent_logs),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            // Wing chrome: the log stream lives inside one grouped paper card
            // (20dp corners, 1dp hairline outline, no shadow) on the bone ground.
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                shape = RoundedCornerShape(20.dp),
                color = MaterialTheme.colorScheme.surface,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
            ) {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(vertical = 4.dp)
                ) {
                    // Newest first.
                    val reversed = logs.asReversed()
                    itemsIndexed(reversed, key = { _, entry -> entry.id }) { index, entry ->
                        LogRow(
                            entry = entry,
                            selectMode = selectMode,
                            selected = selection.contains(entry.id),
                            onToggleSelect = {
                                if (selection.contains(entry.id)) selection.remove(entry.id)
                                else selection[entry.id] = Unit
                            },
                            onCopy = { copyToClipboard(context, entry.formatted()) }
                        )
                        if (index != reversed.lastIndex) {
                            HorizontalDivider(
                                thickness = 1.dp,
                                color = MaterialTheme.colorScheme.outlineVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LogRow(
    entry: LogsModel.LogEntry,
    selectMode: Boolean,
    selected: Boolean,
    onToggleSelect: () -> Unit,
    onCopy: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxSize()
            .then(
                if (selectMode) {
                    Modifier
                        .clickable { onToggleSelect() }
                        .background(
                            // Wing selection state: soft azure wash, not a gray block.
                            if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                            else Color.Transparent
                        )
                } else {
                    Modifier.clickable { showMenu = true }
                }
            )
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Icon(
            imageVector = entry.level.icon(),
            contentDescription = null,
            tint = entry.level.color(),
            modifier = Modifier
                .size(16.dp)
                .padding(top = 2.dp)
        )

        Column(modifier = Modifier.padding(start = 4.dp)) {
            Text(
                text = entry.message,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                )
            )
            Spacer(Modifier.size(2.dp))
            Text(
                text = formatTime(entry.timestamp),
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            DropdownMenu(
                expanded = showMenu,
                onDismissRequest = { showMenu = false },
                properties = PopupProperties(focusable = true)
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.copy)) },
                    onClick = {
                        onCopy()
                        showMenu = false
                    }
                )
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    clipboard.setPrimaryClip(ClipData.newPlainText("Mythaia Logs", text))
}

/**
 * Built per call rather than held.
 *
 * A formatter cached in a top-level val captures the locale at class-init
 * and keeps it after the user changes language, and SimpleDateFormat is not
 * thread-safe besides. Log rows are formatted as they are drawn, so there is
 * nothing here worth caching.
 */
private fun formatTime(timestampMs: Long): String =
    SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(timestampMs))

private fun LogsModel.LogEntry.formatted(): String {
    val time = formatTime(timestamp)
    val levelStr = when (level) {
        LogsModel.LogLevel.info -> "INFO"
        LogsModel.LogLevel.warning -> "WARN"
        LogsModel.LogLevel.error -> "ERROR"
    }
    return "$time [$levelStr] $message"
}

@Composable
private fun LogsModel.LogLevel.icon() = when (this) {
    LogsModel.LogLevel.info -> Icons.Filled.Info
    LogsModel.LogLevel.warning -> Icons.Filled.Warning
    LogsModel.LogLevel.error -> Icons.Filled.Error
}

@Composable
private fun LogsModel.LogLevel.color(): Color = when (this) {
    LogsModel.LogLevel.info -> MaterialTheme.colorScheme.onSurfaceVariant
    // Wing semantic accents: theme-aware warning orange and error red.
    LogsModel.LogLevel.warning -> if (isSystemInDarkTheme()) WarningDark else WarningLight
    LogsModel.LogLevel.error -> MaterialTheme.colorScheme.error
}
