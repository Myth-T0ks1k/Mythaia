package com.mythaia.ui.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.ui.theme.LocalMythaiaDarkTheme
import com.mythaia.R
import com.mythaia.ui.components.SessionStatsRow
import com.mythaia.ui.components.LatencyBadge
import com.mythaia.ui.components.SubscriptionUsageCard
import com.mythaia.ui.components.PowerButton
import com.mythaia.ui.components.TrafficStatsRow
import com.mythaia.ui.theme.GradientConnectedEndDark
import com.mythaia.ui.theme.GradientConnectedEndLight
import com.mythaia.ui.theme.GradientConnectedStartDark
import com.mythaia.ui.theme.GradientConnectedStartLight
import com.mythaia.ui.theme.GradientDisconnectedEndDark
import com.mythaia.ui.theme.GradientDisconnectedEndLight
import com.mythaia.ui.theme.GradientDisconnectedStartDark
import com.mythaia.ui.theme.GradientDisconnectedStartLight
import com.mythaia.ui.theme.LightAzure
import com.mythaia.ui.proxy.AddProxyScreen
import com.mythaia.ui.proxy.ProxyEditorScreen
import com.mythaia.viewmodel.VpnStatus
import com.mythaia.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(viewModel: VpnViewModel, contentPadding: PaddingValues = PaddingValues()) {
    val vpnStatus by viewModel.vpnStatus.collectAsState()
    val bytesIn by viewModel.bytesIn.collectAsState()
    val bytesOut by viewModel.bytesOut.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val chains by viewModel.chainRepository.chains.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val startError by viewModel.startError.collectAsState()
    val downloadSpeed by viewModel.downloadSpeed.collectAsState()
    val uploadSpeed by viewModel.uploadSpeed.collectAsState()
    val uptimeSeconds by viewModel.uptimeSeconds.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()
    val autoSelecting by viewModel.autoSelecting.collectAsState()

    val isConnected = vpnStatus == VpnStatus.CONNECTED
    val isTransitioning = vpnStatus == VpnStatus.CONNECTING ||
            vpnStatus == VpnStatus.DISCONNECTING ||
            vpnStatus == VpnStatus.REASSERTING

    val selectedItemName = remember(selectedConfigId, selectedChainId, configurations, chains) {
        when {
            selectedChainId != null -> chains.find { it.id == selectedChainId }?.name
            selectedConfigId != null -> configurations.find { it.id == selectedConfigId }?.name
            else -> null
        }
    }

    // Only when the selected server belongs to a subscription: a standalone
    // server has no quota to report.
    val activeSubscription = remember(selectedConfigId, configurations, subscriptions) {
        val subId = selectedConfigId
            ?.let { id -> configurations.find { it.id == id } }
            ?.subscriptionId
        subId?.let { id -> subscriptions.find { it.id == id } }
    }

    var showingAddSheet by remember { mutableStateOf(false) }
    var showingManualAddSheet by remember { mutableStateOf(false) }
    var showingConfigPicker by remember { mutableStateOf(false) }
    // Shared with the SettingsScreen "Global Mode" toggle through the view
    // model, so a flip on either screen shows on both; LwipStack observes the
    // underlying pref to reload routing live.
    val isGlobalMode by viewModel.isGlobalMode.collectAsState()

    val isDark = LocalMythaiaDarkTheme.current
    val gradientStart by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedStartDark
            isConnected -> GradientConnectedStartLight
            isDark -> GradientDisconnectedStartDark
            else -> GradientDisconnectedStartLight
        },
        animationSpec = tween(600),
        label = "gradientStart"
    )
    val gradientEnd by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedEndDark
            isConnected -> GradientConnectedEndLight
            isDark -> GradientDisconnectedEndDark
            else -> GradientDisconnectedEndLight
        },
        animationSpec = tween(600),
        label = "gradientEnd"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.linearGradient(
                    colors = listOf(gradientStart, gradientEnd)
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(contentPadding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Paper segments with an azure-wash active state stay legible on
            // every gradient (bone-neutral idle and azure connected alike).
            val segmentColors = SegmentedButtonDefaults.colors(
                activeContainerColor = MaterialTheme.colorScheme.primaryContainer,
                activeContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                activeBorderColor = MaterialTheme.colorScheme.outline,
                inactiveContainerColor = MaterialTheme.colorScheme.surface,
                inactiveContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                inactiveBorderColor = MaterialTheme.colorScheme.outline
            )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.padding(top = 10.dp)) {
                SegmentedButton(
                    selected = !isGlobalMode,
                    onClick = {
                        if (isGlobalMode) viewModel.proxyMode = "rule"
                    },
                    shape = SegmentedButtonDefaults.itemShape(0, 2),
                    colors = segmentColors
                ) { Text(stringResource(R.string.proxy_mode_rule)) }
                SegmentedButton(
                    selected = isGlobalMode,
                    onClick = {
                        if (!isGlobalMode) viewModel.proxyMode = "global"
                    },
                    shape = SegmentedButtonDefaults.itemShape(1, 2),
                    colors = segmentColors
                ) { Text(stringResource(R.string.proxy_mode_global)) }
            }

            Spacer(modifier = Modifier.weight(1f))

            // When there are zero configurations, the power button bootstraps the
            // user into the Add sheet — mirrors iOS HomeView power-button-as-empty-CTA.
            val hasNoConfigurations = configurations.isEmpty() && chains.isEmpty()
            PowerButton(
                isConnected = isConnected,
                isTransitioning = isTransitioning,
                enabled = hasNoConfigurations || !viewModel.isButtonDisabled,
                onClick = {
                    if (hasNoConfigurations) {
                        showingAddSheet = true
                    } else {
                        viewModel.toggleVPN()
                    }
                }
            )

            Spacer(modifier = Modifier.height(16.dp))

            val statusTextRes = when (vpnStatus) {
                VpnStatus.DISCONNECTED -> R.string.disconnected
                VpnStatus.CONNECTING -> R.string.connecting
                VpnStatus.CONNECTED -> R.string.connected
                VpnStatus.DISCONNECTING -> R.string.disconnecting
                VpnStatus.REASSERTING -> R.string.reconnecting
            }
            // Connected status reads azure: LightAzure is the azure token built
            // for dark grounds, and the connected gradient is a dark azure
            // ground in both themes. Idle stays slate (onSurfaceVariant) on the
            // quiet bone / deep-ink gradients.
            Text(
                text = stringResource(statusTextRes),
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Medium),
                color = if (isConnected) LightAzure else MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(if (isConnected) 20.dp else 40.dp))

            AnimatedVisibility(
                visible = isConnected,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
            ) {
                // TrafficStatsRow draws its own paper tiles (outline border,
                // slate labels, ink/bone monospaced numerals) — no frosted
                // wrapper card on the gradient any more.
                Column(modifier = Modifier.fillMaxWidth().padding(bottom = 20.dp)) {
                    SessionStatsRow(
                        bytesIn = bytesIn,
                        bytesOut = bytesOut,
                        downloadSpeed = downloadSpeed,
                        uploadSpeed = uploadSpeed,
                        uptimeSeconds = uptimeSeconds,
                        contentColor = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.fillMaxWidth()
                    )
                    activeSubscription?.let { subscription ->
                        Spacer(modifier = Modifier.height(12.dp))
                        SubscriptionUsageCard(subscription = subscription)
                    }
                }
            }

            // Server chooser: a paper compact row (14dp radius, hairline
            // outline) in both states — ink title, slate chrome, with the
            // leading glyph turning azure while connected.
            if (selectedItemName != null) {
                Card(
                    onClick = { showingConfigPicker = true },
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        contentColor = MaterialTheme.colorScheme.onSurface
                    ),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.ic_network_filled),
                            contentDescription = null,
                            tint = if (isConnected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = selectedItemName,
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        // The last measurement for this server, when there is
                        // one. Shown here so the number sits next to the choice
                        // it describes rather than only on the Proxies list.
                        selectedConfigId?.let { id ->
                            latencyResults[id]?.let { result ->
                                LatencyBadge(latency = result)
                                Spacer(modifier = Modifier.width(8.dp))
                            }
                        }
                        Icon(
                            imageVector = Icons.Default.KeyboardArrowDown,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                        )
                    }
                }
            } else {
                Card(
                    onClick = { showingAddSheet = true },
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface,
                        contentColor = MaterialTheme.colorScheme.onSurface
                    ),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.Add,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = stringResource(R.string.add_a_configuration),
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f))
        }
    }

    if (showingConfigPicker) {
        ModalBottomSheet(
            onDismissRequest = { showingConfigPicker = false },
            sheetState = rememberModalBottomSheetState()
        ) {
            Column(modifier = Modifier.padding(bottom = 24.dp)) {
                Text(
                    text = stringResource(R.string.select_configuration),
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
                )

                // Subscription-grouped picker \u2014 mirrors iOS HomeView's allPickerItems
                // structure (standalone configs first, then per-subscription sections).
                val standaloneConfigs = configurations.filter { it.subscriptionId == null }
                val configsBySubscription = subscriptions.associateWith { sub ->
                    configurations.filter { it.subscriptionId == sub.id }
                }.filterValues { it.isNotEmpty() }

                standaloneConfigs.forEach { config ->
                    val isSelected = config.id == selectedConfigId && selectedChainId == null
                    Surface(
                        onClick = {
                            viewModel.setSelectedConfiguration(config)
                            showingConfigPicker = false
                        },
                        color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 24.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = config.name,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.weight(1f)
                            )
                            if (isSelected) {
                                Text(
                                    text = "\u2713",
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }

                configsBySubscription.forEach { (subscription, subConfigs) ->
                    Text(
                        text = subscription.name,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
                    )
                    subConfigs.forEach { config ->
                        val isSelected = config.id == selectedConfigId && selectedChainId == null
                        Surface(
                            onClick = {
                                viewModel.setSelectedConfiguration(config)
                                showingConfigPicker = false
                            },
                            color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 24.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = config.name,
                                    style = MaterialTheme.typography.bodyLarge,
                                    modifier = Modifier.weight(1f)
                                )
                                if (isSelected) {
                                    Text(
                                        text = "\u2713",
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }

                if (chains.isNotEmpty()) {
                    Text(
                        text = stringResource(R.string.chains),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
                    )
                }
                chains.forEach { chain ->
                    val isSelected = chain.id == selectedChainId
                    Surface(
                        onClick = {
                            viewModel.selectChain(chain)
                            showingConfigPicker = false
                        },
                        color = if (isSelected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 24.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = chain.name,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.weight(1f)
                            )
                            if (isSelected) {
                                Text(
                                    text = "\u2713",
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showingAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            AddProxyScreen(
                viewModel = viewModel,
                onDismiss = { showingAddSheet = false },
                onShowManualAdd = {
                    showingAddSheet = false
                    showingManualAddSheet = true
                },
                onImport = { config ->
                    viewModel.addConfiguration(config)
                    showingAddSheet = false
                },
                onSubscriptionImport = { configs, subscription ->
                    viewModel.addSubscription(configs, subscription)
                    showingAddSheet = false
                }
            )
        }
    }

    if (showingManualAddSheet) {
        ModalBottomSheet(
            onDismissRequest = { showingManualAddSheet = false },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ) {
            ProxyEditorScreen(
                configuration = null,
                onSave = { config ->
                    viewModel.addConfiguration(config)
                    showingManualAddSheet = false
                },
                onDismiss = { showingManualAddSheet = false }
            )
        }
    }

    if (startError != null) {
        AlertDialog(
            onDismissRequest = { viewModel.clearStartError() },
            title = { Text(stringResource(R.string.vpn_error)) },
            text = { Text(startError ?: "") },
            confirmButton = {
                TextButton(onClick = { viewModel.clearStartError() }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }
}
