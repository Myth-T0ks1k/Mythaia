package com.mythaia.ui.proxy

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.Subscription
import com.mythaia.ui.components.wingTextFieldColors

/**
 * Name and fronting for one subscription.
 *
 * Fronting is the part a blocked panel needs: the URL stays as the panel
 * gave it, the TLS name and the hosts actually dialled come from here.
 */
@Composable
fun SubscriptionSettingsDialog(
    subscription: Subscription,
    onDismiss: () -> Unit,
    onSave: (name: String, frontSni: String?, frontTargets: List<String>) -> Unit
) {
    var name by remember(subscription.id) { mutableStateOf(subscription.name) }
    var sni by remember(subscription.id) { mutableStateOf(subscription.frontSni ?: "") }
    var targets by remember(subscription.id) { mutableStateOf(subscription.frontTargets.joinToString("\n")) }

    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.onSurface,
        textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        title = { Text(stringResource(R.string.group_settings)) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.name)) },
                    singleLine = true,
                    shape = RoundedCornerShape(14.dp),
                    colors = wingTextFieldColors(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = stringResource(R.string.fronting),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = stringResource(R.string.fronting_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp, bottom = 10.dp)
                )
                OutlinedTextField(
                    value = sni,
                    onValueChange = { sni = it },
                    label = { Text(stringResource(R.string.front_sni)) },
                    placeholder = { Text(runCatching { java.net.URL(subscription.url).host }.getOrDefault("")) },
                    singleLine = true,
                    shape = RoundedCornerShape(14.dp),
                    colors = wingTextFieldColors(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = targets,
                    onValueChange = { targets = it },
                    label = { Text(stringResource(R.string.front_targets)) },
                    placeholder = { Text("cdn.example.net\n203.0.113.10:443") },
                    minLines = 2,
                    maxLines = 6,
                    shape = RoundedCornerShape(14.dp),
                    colors = wingTextFieldColors(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSave(
                    name,
                    sni.trim().takeIf { it.isNotEmpty() },
                    targets.split('\n', ',', ';').map { it.trim() }.filter { it.isNotEmpty() }
                )
            }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}
