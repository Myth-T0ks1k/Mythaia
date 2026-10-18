package com.mythaia.ui.settings

import android.text.format.Formatter
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Storefront
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Update
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.update.AppUpdater
import com.mythaia.data.update.Release
import com.mythaia.data.update.Releases
import com.mythaia.data.update.UpdateMode
import com.mythaia.data.update.UpdateState
import com.mythaia.ui.components.WingIconTile

/**
 * The update rows under About: one that checks (and says where the update
 * stands), and the switch for the daily check — off until the user turns it
 * on, so the app never calls GitHub unasked. The free build gets one row
 * that points to its store instead.
 */
@Composable
internal fun UpdateRows(divider: @Composable () -> Unit) {
    val context = LocalContext.current
    val updater = remember { AppUpdater.get(context) }
    val state by updater.state.collectAsState()
    val autoCheck by updater.autoCheck.collectAsState()
    var dialogOpen by remember { mutableStateOf(false) }
    var asked by remember { mutableStateOf(false) }

    if (updater.mode == UpdateMode.STORE) {
        UpdateRow(
            icon = Icons.Filled.Storefront,
            label = stringResource(R.string.update_store),
            subtitle = stringResource(R.string.update_version, updater.currentVersion),
            onClick = { updater.openStore(context) }
        )
        return
    }

    // A check the user started opens the dialog as soon as it finds something.
    LaunchedEffect(state) {
        if (asked && state is UpdateState.Available) {
            dialogOpen = true
            asked = false
        }
        if (state !is UpdateState.Checking && state !is UpdateState.Available) asked = false
    }

    UpdateRow(
        icon = Icons.Filled.SystemUpdate,
        label = stringResource(R.string.update_check),
        subtitle = updateSubtitle(state, updater.currentVersion),
        subtitleColor = when (state) {
            is UpdateState.Failed -> MaterialTheme.colorScheme.error
            is UpdateState.Available, is UpdateState.Ready -> MaterialTheme.colorScheme.primary
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        },
        busy = state is UpdateState.Checking,
        onClick = {
            when (val s = state) {
                is UpdateState.Idle, is UpdateState.UpToDate -> { asked = true; updater.check() }
                is UpdateState.Failed -> if (s.release == null) { asked = true; updater.check() } else dialogOpen = true
                is UpdateState.Checking -> Unit
                else -> dialogOpen = true
            }
        }
    )
    divider()
    SettingsSwitch(
        icon = Icons.Filled.Update,
        iconTint = MaterialTheme.colorScheme.primary,
        label = stringResource(R.string.update_auto),
        checked = autoCheck,
        onCheckedChange = { updater.setAutoCheck(it) }
    )
    Text(
        text = stringResource(R.string.update_auto_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 66.dp, end = 16.dp, bottom = 12.dp)
    )

    if (dialogOpen) {
        UpdateDialog(updater = updater, onDismiss = { dialogOpen = false })
    }
}

@Composable
private fun updateSubtitle(state: UpdateState, current: String): String = when (state) {
    is UpdateState.Idle -> stringResource(R.string.update_version, current)
    is UpdateState.Checking -> stringResource(R.string.update_checking)
    is UpdateState.UpToDate -> stringResource(R.string.update_latest, current)
    is UpdateState.Available -> stringResource(R.string.update_available, state.release.version.toString())
    is UpdateState.Downloading -> stringResource(R.string.update_downloading, percent(state.done, state.total))
    is UpdateState.Ready -> stringResource(R.string.update_ready, state.release.version.toString())
    is UpdateState.Failed -> state.message
}

private fun percent(done: Long, total: Long): Int =
    if (total <= 0) 0 else ((done * 100) / total).toInt().coerceIn(0, 100)

/** A settings row with a second line, the way [SettingsNavRow] draws the first. */
@Composable
private fun UpdateRow(
    icon: ImageVector,
    label: String,
    subtitle: String,
    subtitleColor: Color = MaterialTheme.colorScheme.onSurfaceVariant,
    busy: Boolean = false,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 60.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        WingIconTile(size = 34.dp) {
            Icon(imageVector = icon, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = subtitleColor,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
    }
}

/**
 * The offer an automatic check found, once per release; a later tap on the
 * Settings row brings it back. Shown over whichever screen is open.
 */
@Composable
fun UpdatePrompt() {
    val context = LocalContext.current
    val updater = remember { AppUpdater.get(context) }
    val prompt by updater.prompt.collectAsState()
    if (prompt != null) {
        UpdateDialog(updater = updater, onDismiss = { updater.dismissPrompt() })
    }
}

/** What there is to do about the release in hand: download, watch it come, install. */
@Composable
internal fun UpdateDialog(updater: AppUpdater, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val state by updater.state.collectAsState()
    val release: Release = when (val s = state) {
        is UpdateState.Available -> s.release
        is UpdateState.Downloading -> s.release
        is UpdateState.Ready -> s.release
        is UpdateState.Failed -> s.release
        else -> null
    } ?: run {
        LaunchedEffect(Unit) { onDismiss() }
        return
    }
    val allowInstalls = stringResource(R.string.update_allow_installs)
    val selfUpdating = updater.mode == UpdateMode.SELF

    AlertDialog(
        onDismissRequest = { if (state !is UpdateState.Downloading) onDismiss() },
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.onSurface,
        textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        icon = { Icon(Icons.Filled.SystemUpdate, contentDescription = null, tint = MaterialTheme.colorScheme.primary) },
        title = { Text(stringResource(R.string.update_title, release.version.toString())) },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 360.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (!selfUpdating) {
                    Text(stringResource(R.string.update_manual_only), color = MaterialTheme.colorScheme.error)
                }
                when (val s = state) {
                    is UpdateState.Downloading -> {
                        val fraction = if (s.total > 0) (s.done.toFloat() / s.total).coerceIn(0f, 1f) else null
                        if (fraction != null) {
                            LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                        } else {
                            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        }
                        Text(
                            stringResource(
                                R.string.update_size,
                                Formatter.formatShortFileSize(context, s.done),
                                Formatter.formatShortFileSize(context, s.total.coerceAtLeast(s.done))
                            ),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    is UpdateState.Ready -> {
                        Text(stringResource(R.string.update_verified), color = MaterialTheme.colorScheme.primary)
                        Text(stringResource(R.string.update_install_note), style = MaterialTheme.typography.bodySmall)
                    }
                    is UpdateState.Failed -> Text(s.message, color = MaterialTheme.colorScheme.error)
                    else -> Unit
                }
                val notes = remember(release) { Releases.summary(release.notes) }
                if (notes.isNotEmpty()) {
                    Text(notes, style = MaterialTheme.typography.bodyMedium)
                }
            }
        },
        confirmButton = {
            when (state) {
                is UpdateState.Available, is UpdateState.Failed -> if (selfUpdating) {
                    TextButton(onClick = { updater.download() }) {
                        Text(stringResource(if (state is UpdateState.Failed) R.string.update_retry else R.string.update_download_install))
                    }
                } else {
                    TextButton(onClick = { updater.openReleasePage(context, release); onDismiss() }) {
                        Text(stringResource(R.string.update_open_github))
                    }
                }
                is UpdateState.Ready -> TextButton(onClick = {
                    if (!context.packageManager.canRequestPackageInstalls()) {
                        Toast.makeText(context, allowInstalls, Toast.LENGTH_LONG).show()
                    }
                    updater.install(context)
                }) { Text(stringResource(R.string.update_install)) }
                else -> Unit
            }
        },
        dismissButton = {
            if (state is UpdateState.Downloading) {
                TextButton(onClick = { updater.reset(); onDismiss() }) { Text(stringResource(R.string.cancel)) }
            } else {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.update_later)) }
            }
        }
    )
}
