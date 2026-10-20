package com.mythaia.ui.proxy

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
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
    onSave: (name: String, frontSni: String?, frontTargets: List<String>, pinned: Boolean) -> Unit
) {
    var name by remember(subscription.id) { mutableStateOf(subscription.name) }
    var pinned by remember(subscription.id) { mutableStateOf(subscription.pinned) }
    var sni by remember(subscription.id) { mutableStateOf(subscription.frontSni ?: "") }
    var targets by remember(subscription.id) { mutableStateOf(subscription.frontTargets.joinToString("\n")) }
    val context = LocalContext.current

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
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                ) {
                    Text(
                        text = stringResource(R.string.subscription_pin_top),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    Switch(checked = pinned, onCheckedChange = { pinned = it })
                }
                // What the provider decided for this subscription, so a hidden
                // editor or a sort order the user did not pick has a reason.
                val managed = buildList {
                    if (subscription.hideSettings) add(stringResource(R.string.managed_hide_settings))
                    if (subscription.serverSort != null) add(stringResource(R.string.managed_sort))
                    subscription.userAgent?.let { add(stringResource(R.string.managed_user_agent, it)) }
                    if (subscription.pingOnOpen) add(stringResource(R.string.managed_ping_on_open))
                    if (subscription.autoConnect != null) add(stringResource(R.string.managed_auto_connect))
                    if (!subscription.collapsible) add(stringResource(R.string.managed_no_collapse))
                }
                if (managed.isNotEmpty()) {
                    Text(
                        text = stringResource(R.string.settings_managed_by, subscription.name) + ": " + managed.joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp)
                    )
                }
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
                // One link with the fronting in it, for another phone: opening
                // it adds the subscription already fronted.
                val targetList = targets.split('\n', ',', ';').map { it.trim() }.filter { it.isNotEmpty() }
                if (targetList.isNotEmpty() || sni.isNotBlank()) {
                    TextButton(
                        onClick = {
                            val link = com.mythaia.data.network.SubscriptionLink(
                                url = subscription.url,
                                frontSni = sni.trim().takeIf { it.isNotEmpty() },
                                frontTargets = targetList
                            ).toAppLink()
                            val clip = ClipData.newPlainText("subscription_url", link)
                            // The link holds the account's token.
                            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                                clip.description.extras = android.os.PersistableBundle().apply {
                                    putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
                                }
                            }
                            context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
                        },
                        modifier = Modifier.padding(top = 4.dp)
                    ) { Text(stringResource(R.string.copy_fronted_link)) }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSave(
                    name,
                    sni.trim().takeIf { it.isNotEmpty() },
                    targets.split('\n', ',', ';').map { it.trim() }.filter { it.isNotEmpty() },
                    pinned
                )
            }) { Text(stringResource(R.string.save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}
