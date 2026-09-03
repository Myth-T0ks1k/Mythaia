package com.mythaia.ui.proxy

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.ui.components.wingTextFieldColors
import java.util.UUID

// Wing form language: compact 14dp corners for rows/fields, 20dp for cards,
// 28dp top corners for sheets.
private val HopCardShape = RoundedCornerShape(14.dp)
private val FormCardShape = RoundedCornerShape(20.dp)
private val PickerSheetShape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChainEditorScreen(
    chain: ProxyChain?,
    configurations: List<ProxyConfiguration>,
    subscriptions: List<Subscription> = emptyList(),
    onSave: (ProxyChain) -> Unit,
    onDismiss: () -> Unit
) {
    val isEditing = chain != null
    var name by remember { mutableStateOf(chain?.name ?: "") }
    // Drop ids whose configuration no longer exists (e.g. an "invalid chain"
    // opened for editing) so row indices always match this list — otherwise
    // remove/move would operate on the wrong (invisible) entries.
    val selectedProxyIds = remember {
        mutableStateListOf<UUID>().apply {
            chain?.proxyIds
                ?.filter { id -> configurations.any { it.id == id } }
                ?.let { addAll(it) }
        }
    }
    var showingProxyPicker by remember { mutableStateOf(false) }

    val selectedProxies = remember(selectedProxyIds.toList(), configurations) {
        selectedProxyIds.mapNotNull { id -> configurations.find { it.id == id } }
    }

    val canSave = name.isNotBlank() && selectedProxies.size >= 2

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Text(
                text = stringResource(if (isEditing) R.string.edit_chain else R.string.new_chain),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            TextButton(
                onClick = {
                    val result = ProxyChain(
                        id = chain?.id ?: UUID.randomUUID(),
                        name = name.trim(),
                        proxyIds = selectedProxyIds.toList()
                    )
                    onSave(result)
                },
                enabled = canSave
            ) {
                Text(stringResource(R.string.save))
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Spacer(modifier = Modifier.height(16.dp))

        SectionLabel(stringResource(R.string.name))
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = FormCardShape,
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = HopCardShape,
                    colors = wingTextFieldColors()
                )
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            SectionLabel(stringResource(R.string.proxies_in_chain))
            IconButton(onClick = { showingProxyPicker = true }) {
                Icon(
                    Icons.Default.Add,
                    contentDescription = stringResource(R.string.add_proxy_to_chain),
                    tint = MaterialTheme.colorScheme.primary
                )
            }
        }

        if (selectedProxies.size < 2) {
            Text(
                text = stringResource(R.string.chain_min_proxies),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(bottom = 8.dp)
            )
        }

        LazyColumn(
            modifier = Modifier.weight(1f, fill = false)
        ) {
            itemsIndexed(selectedProxies, key = { _, proxy -> proxy.id }) { index, proxy ->
                Column(modifier = Modifier.fillMaxWidth()) {
                    // A subtle azure thread linking one hop card to the next,
                    // aligned with the hop-number badges.
                    if (index > 0) HopConnector()
                    ProxyChainItem(
                        index = index,
                        proxy = proxy,
                        totalCount = selectedProxies.size,
                        onRemove = { selectedProxyIds.remove(proxy.id) },
                        onMoveUp = if (index > 0) {
                            {
                                val pos = selectedProxyIds.indexOf(proxy.id)
                                if (pos > 0) {
                                    selectedProxyIds.removeAt(pos)
                                    selectedProxyIds.add(pos - 1, proxy.id)
                                }
                            }
                        } else null,
                        onMoveDown = if (index < selectedProxies.size - 1) {
                            {
                                val pos = selectedProxyIds.indexOf(proxy.id)
                                if (pos >= 0 && pos < selectedProxyIds.size - 1) {
                                    selectedProxyIds.removeAt(pos)
                                    selectedProxyIds.add(pos + 1, proxy.id)
                                }
                            }
                        } else null
                    )
                }
            }
        }

        if (selectedProxies.size >= 2) {
            Spacer(modifier = Modifier.height(16.dp))
            SectionLabel(stringResource(R.string.route_preview))
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(
                    R.string.route_preview_format,
                    selectedProxies.joinToString(" → ") { it.name }
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(modifier = Modifier.height(16.dp))
    }

    if (showingProxyPicker) {
        ModalBottomSheet(
            onDismissRequest = { showingProxyPicker = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = PickerSheetShape,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            ProxyPickerScreenContent(
                configurations = configurations,
                subscriptions = subscriptions,
                excludedIds = selectedProxyIds.toSet(),
                onSelect = { proxy ->
                    selectedProxyIds.add(proxy.id)
                    showingProxyPicker = false
                },
                onDismiss = { showingProxyPicker = false }
            )
        }
    }
}

/** Slate small-caps section header, Wing grouped-form style. */
@Composable
private fun SectionLabel(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        letterSpacing = 1.2.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 4.dp, bottom = 6.dp)
    )
}

/** Short azure segment drawn between hop cards, under the number badges. */
@Composable
private fun HopConnector() {
    Box(
        modifier = Modifier
            .padding(start = 25.dp)
            .width(2.dp)
            .height(14.dp)
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.45f))
    )
}

@Composable
private fun ProxyChainItem(
    index: Int,
    proxy: ProxyConfiguration,
    totalCount: Int,
    onRemove: () -> Unit,
    onMoveUp: (() -> Unit)? = null,
    onMoveDown: (() -> Unit)? = null
) {
    // Azure is the only accent: entry = azure, exit = muted azure tertiary,
    // intermediate hops = quiet slate container.
    val badgeColor = when {
        index == 0 -> MaterialTheme.colorScheme.primary
        index == totalCount - 1 -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.secondaryContainer
    }
    val badgeContentColor = when {
        index == 0 -> MaterialTheme.colorScheme.onPrimary
        index == totalCount - 1 -> MaterialTheme.colorScheme.onTertiary
        else -> MaterialTheme.colorScheme.onSecondaryContainer
    }

    val roleLabel = when {
        index == 0 -> stringResource(R.string.entry)
        index == totalCount - 1 -> stringResource(R.string.exit)
        else -> null
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = HopCardShape,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Surface(
                shape = CircleShape,
                color = badgeColor,
                contentColor = badgeContentColor,
                modifier = Modifier.size(24.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text(
                        text = "${index + 1}",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = proxy.name,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${proxy.serverAddress}:${proxy.serverPort}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (roleLabel != null) {
                Text(
                    text = roleLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.width(4.dp))
            }

            IconButton(
                onClick = { onMoveUp?.invoke() },
                enabled = onMoveUp != null,
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ArrowUpward,
                    contentDescription = stringResource(R.string.move_up),
                    modifier = Modifier.size(18.dp)
                )
            }
            IconButton(
                onClick = { onMoveDown?.invoke() },
                enabled = onMoveDown != null,
                modifier = Modifier.size(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.ArrowDownward,
                    contentDescription = stringResource(R.string.move_down),
                    modifier = Modifier.size(18.dp)
                )
            }
            IconButton(onClick = onRemove, modifier = Modifier.size(32.dp)) {
                Icon(
                    imageVector = Icons.Default.Close,
                    contentDescription = stringResource(R.string.delete),
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

@Composable
private fun ProxyPickerScreenContent(
    configurations: List<ProxyConfiguration>,
    subscriptions: List<Subscription>,
    excludedIds: Set<UUID>,
    onSelect: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    val available = remember(configurations, excludedIds) {
        configurations.filter { it.id !in excludedIds }
    }

    // Standalone section (configs without a subscriptionId) followed by one
    // section per subscription.
    val standalone = remember(available) { available.filter { it.subscriptionId == null } }
    val groups = remember(available, subscriptions) {
        subscriptions.mapNotNull { sub ->
            val members = available.filter { it.subscriptionId == sub.id }
            if (members.isEmpty()) null else sub to members
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
            Text(
                text = stringResource(R.string.select_proxy),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.width(64.dp))
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

        if (available.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(R.string.no_proxies_available),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.all_proxies_in_chain),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
            }
        } else {
            LazyColumn {
                if (standalone.isNotEmpty() && groups.isNotEmpty()) {
                    item { PickerSectionHeader(stringResource(R.string.standalone)) }
                }
                items(standalone.size, key = { standalone[it].id }) { index ->
                    PickerRow(proxy = standalone[index], onSelect = onSelect)
                }
                groups.forEach { (subscription, members) ->
                    item { PickerSectionHeader(subscription.name) }
                    items(members.size, key = { members[it].id }) { index ->
                        PickerRow(proxy = members[index], onSelect = onSelect)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
    }
}

@Composable
private fun PickerSectionHeader(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelMedium,
        letterSpacing = 1.2.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 12.dp, top = 16.dp, bottom = 4.dp)
    )
}

@Composable
private fun PickerRow(
    proxy: ProxyConfiguration,
    onSelect: (ProxyConfiguration) -> Unit
) {
    TextButton(
        onClick = { onSelect(proxy) },
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = proxy.name,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "${proxy.serverAddress}:${proxy.serverPort}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
