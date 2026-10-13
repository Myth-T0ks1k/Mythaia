package com.mythaia.ui.proxy

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyResult
import com.mythaia.ui.components.LatencyBadge
import com.mythaia.viewmodel.VpnViewModel

// Wing visual language: compact 14dp corners for list rows, 28dp for sheets.
private val ChainRowShape = RoundedCornerShape(22.dp)
private val SheetShape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)

/**
 * @param embedded true when shown as a tab inside the Proxies screen, which
 *   already has a top bar; the actions then sit in a slim row of their own.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChainListScreen(viewModel: VpnViewModel, embedded: Boolean = false) {
    val chains by viewModel.chainRepository.chains.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val chainLatencyResults by viewModel.chainLatencyResults.collectAsState()

    var showingAddSheet by rememberSaveable { mutableStateOf(false) }
    var showingNotEnoughProxiesAlert by rememberSaveable { mutableStateOf(false) }
    // Ids rather than the chains: they survive a rotation, and the chain
    // they name is looked up fresh, so a sheet open mid-edit stays open.
    var chainToEditId by rememberSaveable { mutableStateOf<String?>(null) }
    var chainToDeleteId by rememberSaveable { mutableStateOf<String?>(null) }
    val chainToEdit = chainToEditId?.let { id -> chains.firstOrNull { it.id.toString() == id } }
    val chainToDelete = chainToDeleteId?.let { id -> chains.firstOrNull { it.id.toString() == id } }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            if (embedded) {
                androidx.compose.foundation.layout.Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    if (chains.isNotEmpty()) {
                        IconButton(onClick = { viewModel.testAllChainLatencies() }) {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = stringResource(R.string.test_all),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                    IconButton(onClick = {
                        if (configurations.count { !it.outboundProtocol.isLayer3 } < 2) {
                            showingNotEnoughProxiesAlert = true
                        } else {
                            showingAddSheet = true
                        }
                    }) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = stringResource(R.string.new_chain),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
                return@Scaffold
            }
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    actionIconContentColor = MaterialTheme.colorScheme.primary
                ),
                title = { Text(stringResource(R.string.chains)) },
                actions = {
                    if (chains.isNotEmpty()) {
                        IconButton(onClick = { viewModel.testAllChainLatencies() }) {
                            Icon(
                                imageVector = Icons.Default.Speed,
                                contentDescription = stringResource(R.string.test_all)
                            )
                        }
                    }
                    IconButton(onClick = {
                        // A WireGuard profile cannot be a hop, so it does not
                        // count toward the two a chain needs.
                        if (configurations.count { !it.outboundProtocol.isLayer3 } < 2) {
                            showingNotEnoughProxiesAlert = true
                        } else {
                            showingAddSheet = true
                        }
                    }) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = stringResource(R.string.add)
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        if (chains.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = stringResource(R.string.no_chains),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = stringResource(R.string.tap_to_add_chain),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(chains, key = { it.id }) { chain ->
                    ChainRow(
                        chain = chain,
                        configurations = configurations,
                        isSelected = selectedChainId == chain.id,
                        latency = chainLatencyResults[chain.id],
                        onSelect = { viewModel.selectChain(chain) },
                        onEdit = { chainToEditId = chain.id.toString() },
                        onDelete = { chainToDeleteId = chain.id.toString() },
                        onTestLatency = { viewModel.testChainLatency(chain) }
                    )
                }
            }
        }
    }

    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = SheetShape,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            ChainEditorScreen(
                chain = null,
                configurations = configurations,
                subscriptions = subscriptions,
                onSave = { chain ->
                    viewModel.addChain(chain)
                    showingAddSheet = false
                },
                onDismiss = { showingAddSheet = false }
            )
        }
    }

    chainToEdit?.let { chain ->
        ModalBottomSheet(
            onDismissRequest = { chainToEditId = null },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            shape = SheetShape,
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            ChainEditorScreen(
                chain = chain,
                configurations = configurations,
                subscriptions = subscriptions,
                onSave = { updated ->
                    viewModel.updateChain(updated)
                    chainToEditId = null
                },
                onDismiss = { chainToEditId = null }
            )
        }
    }

    chainToDelete?.let { chain ->
        AlertDialog(
            onDismissRequest = { chainToDeleteId = null },
            containerColor = MaterialTheme.colorScheme.surface,
            title = { Text(stringResource(R.string.delete)) },
            text = { Text(chain.name) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.deleteChain(chain)
                    chainToDeleteId = null
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { chainToDeleteId = null }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }

    if (showingNotEnoughProxiesAlert) {
        AlertDialog(
            onDismissRequest = { showingNotEnoughProxiesAlert = false },
            containerColor = MaterialTheme.colorScheme.surface,
            title = { Text(stringResource(R.string.not_enough_proxies)) },
            text = { Text(stringResource(R.string.not_enough_proxies_message)) },
            confirmButton = {
                TextButton(onClick = { showingNotEnoughProxiesAlert = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}

/**
 * Wing chain row: a paper card (radius 14, 1dp outline, no shadow) with ink
 * name, slate route/metadata lines, and an azure check when selected. The
 * selected card's border warms to azure so state reads without any fill.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChainRow(
    chain: ProxyChain,
    configurations: List<ProxyConfiguration>,
    isSelected: Boolean,
    latency: LatencyResult?,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTestLatency: () -> Unit
) {
    var showMenu by remember { mutableStateOf(false) }

    val proxies = remember(chain.proxyIds, configurations) {
        chain.proxyIds.mapNotNull { id -> configurations.find { it.id == id } }
    }
    val isValid = proxies.size == chain.proxyIds.size && proxies.size >= 2

    val borderColor = if (isSelected) {
        MaterialTheme.colorScheme.primary.copy(alpha = 0.35f)
    } else {
        MaterialTheme.colorScheme.outline
    }

    Box {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = ChainRowShape,
            color = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f)
                    else MaterialTheme.colorScheme.surfaceContainerLow
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .combinedClickable(
                        onClick = { if (isValid) onSelect() },
                        onLongClick = { showMenu = true }
                    )
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = chain.name,
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (isValid) MaterialTheme.colorScheme.onSurface
                            else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                        )
                        if (isSelected) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Icon(
                                imageVector = Icons.Default.Check,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }

                    if (isValid) {
                        Text(
                            text = proxies.joinToString(" → ") { it.name },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1
                        )
                    } else {
                        Text(
                            text = stringResource(R.string.invalid_chain),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }

                    Row {
                        Text(
                            text = pluralStringResource(R.plurals.n_proxies, proxies.size, proxies.size),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                        )
                        if (proxies.size >= 2) {
                            Text(
                                text = " · ${proxies.first().serverAddress} → ${proxies.last().serverAddress}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                maxLines = 1
                            )
                        }
                    }
                }

                if (isValid) {
                    // Tap latency to re-test this single chain — mirrors iOS ChainListView.
                    Box(
                        modifier = Modifier.clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = null,
                            onClick = onTestLatency
                        )
                    ) {
                        LatencyBadge(latency = latency)
                    }
                }
            }
        }

        DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
            if (isValid) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.test_latency)) },
                    leadingIcon = { Icon(Icons.Default.Speed, contentDescription = null) },
                    onClick = {
                        showMenu = false
                        onTestLatency()
                    }
                )
            }
            DropdownMenuItem(
                text = { Text(stringResource(R.string.edit)) },
                onClick = {
                    showMenu = false
                    onEdit()
                },
                leadingIcon = { Icon(Icons.Default.Edit, contentDescription = null) }
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) },
                onClick = {
                    showMenu = false
                    onDelete()
                },
                leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = MaterialTheme.colorScheme.error) }
            )
        }
    }
}
