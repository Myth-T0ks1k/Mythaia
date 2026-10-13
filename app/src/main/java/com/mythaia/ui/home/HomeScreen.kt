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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyResult
import com.mythaia.ui.components.LatencyBadge
import com.mythaia.ui.components.PowerButton
import com.mythaia.ui.components.SessionStatsRow
import com.mythaia.ui.components.SubscriptionUsageCard
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.proxy.NewServerFlow
import com.mythaia.ui.proxy.AddProxyScreen
import com.mythaia.ui.theme.GradientConnectedEndDark
import com.mythaia.ui.theme.GradientConnectedEndLight
import com.mythaia.ui.theme.GradientConnectedStartDark
import com.mythaia.ui.theme.GradientConnectedStartLight
import com.mythaia.ui.theme.GradientDisconnectedEndDark
import com.mythaia.ui.theme.GradientDisconnectedEndLight
import com.mythaia.ui.theme.GradientDisconnectedStartDark
import com.mythaia.ui.theme.GradientDisconnectedStartLight
import com.mythaia.ui.theme.LightAzure
import com.mythaia.ui.theme.LocalMythaiaDarkTheme
import com.mythaia.viewmodel.ProxyGroup
import com.mythaia.viewmodel.VpnStatus
import com.mythaia.viewmodel.VpnViewModel
import java.util.UUID

private const val CHAINS_GROUP_ID = "__chains__"

/**
 * The home screen: the tunnel switch, the live readout, the group the
 * tunnel draws from, and the way into Settings.
 *
 * Everything sits on one gradient. Stickers line the edges while the tunnel
 * is up — a different set each day, a festive one around a holiday — and a
 * red cross takes their place for a moment when a connection fails.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: VpnViewModel,
    contentPadding: PaddingValues = PaddingValues()
) {
    val vpnStatus by viewModel.vpnStatus.collectAsState()
    val bytesIn by viewModel.bytesIn.collectAsState()
    val bytesOut by viewModel.bytesOut.collectAsState()
    val selectedConfigId by viewModel.selectedConfigId.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val activeGroupId by viewModel.activeGroupId.collectAsState()
    val pinnedByGroup by viewModel.pinnedByGroup.collectAsState()
    val autoChoice by viewModel.autoChoice.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val chains by viewModel.chainRepository.chains.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val startError by viewModel.startError.collectAsState()
    val downloadSpeed by viewModel.downloadSpeed.collectAsState()
    val uploadSpeed by viewModel.uploadSpeed.collectAsState()
    val uptimeSeconds by viewModel.uptimeSeconds.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()
    val autoSelecting by viewModel.autoSelecting.collectAsState()
    val isGlobalMode by viewModel.isGlobalMode.collectAsState()
    val lastConnectFailed by viewModel.lastConnectFailed.collectAsState()
    val connectivityOk by viewModel.connectivityOk.collectAsState()
    val exitInfo by viewModel.exitInfo.collectAsState()
    val homeContext = androidx.compose.ui.platform.LocalContext.current
    // Re-read on every connect: the user may have changed it in between.
    var strictPrivateDns by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(vpnStatus) {
        strictPrivateDns = com.mythaia.ui.settings.SystemShortcuts.strictPrivateDns(homeContext)
    }

    val isConnected = vpnStatus == VpnStatus.CONNECTED
    val isTransitioning = vpnStatus == VpnStatus.CONNECTING ||
        vpnStatus == VpnStatus.DISCONNECTING ||
        vpnStatus == VpnStatus.REASSERTING

    val groups = remember(configurations, subscriptions) { viewModel.groups() }
    val activeGroup = groups.firstOrNull { it.id == activeGroupId } ?: groups.firstOrNull()
    val isChain = selectedChainId != null
    val activeIsAuto = !isChain && pinnedByGroup[activeGroupId] == null

    val selectedName: String? = when {
        isChain -> chains.firstOrNull { it.id == selectedChainId }?.name
        else -> selectedConfigId?.let { id -> configurations.firstOrNull { it.id == id }?.name }
    }
    val defaultGroupName = stringResource(R.string.group_default)
    fun groupName(group: ProxyGroup) = if (group.isDefault) defaultGroupName else group.name

    val activeSubscription = remember(selectedConfigId, configurations, subscriptions) {
        val subId = selectedConfigId
            ?.let { id -> configurations.find { it.id == id } }
            ?.subscriptionId
        subId?.let { id -> subscriptions.find { it.id == id } }
    }

    var showingAddSheet by rememberSaveable { mutableStateOf(false) }
    var showingManualAddSheet by rememberSaveable { mutableStateOf(false) }
    var showingPicker by rememberSaveable { mutableStateOf(false) }

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

    // The failure cross shows for a few seconds, then the edges go quiet.
    LaunchedEffect(lastConnectFailed) {
        if (lastConnectFailed) {
            kotlinx.coroutines.delay(5_000)
            viewModel.clearLastConnectFailed()
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.linearGradient(colors = listOf(gradientStart, gradientEnd)))
    ) {
        // A large, faint mark behind everything: the brand as texture.
        WingMark(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(contentPadding)
                .offset(x = 40.dp, y = (-10).dp)
                .size(260.dp)
                .alpha(if (isConnected) 0.10f else 0.06f),
            color = if (isConnected) LightAzure else MaterialTheme.colorScheme.primary
        )

        // A tunnel with no internet behind it earns the cross as much as a
        // failed start does: "connected" means nothing if nothing gets through.
        val noInternet = isConnected && connectivityOk == false
        EdgeStickers(
            visible = isConnected || lastConnectFailed,
            failed = (lastConnectFailed && !isConnected) || noInternet,
            contentPadding = contentPadding
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(contentPadding)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Brand line, then the rule/global switch on its own row so
            // neither label ever has to wrap.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                WingMark(modifier = Modifier.size(24.dp), color = if (isConnected) LightAzure else MaterialTheme.colorScheme.primary)
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleLarge,
                    color = if (isConnected) Color.White.copy(alpha = 0.92f) else MaterialTheme.colorScheme.onBackground
                )
            }
            ModePill(
                global = isGlobalMode,
                onGlobal = { viewModel.proxyMode = "global" },
                onRule = { viewModel.proxyMode = "rule" },
                onDarkGround = isConnected
            )

            Spacer(modifier = Modifier.weight(1f))

            val statusTextRes = when {
                autoSelecting && !isConnected -> R.string.measuring
                noInternet -> R.string.no_connectivity
                else -> when (vpnStatus) {
                    VpnStatus.DISCONNECTED -> R.string.disconnected
                    VpnStatus.CONNECTING -> R.string.connecting
                    VpnStatus.CONNECTED -> R.string.connected
                    VpnStatus.DISCONNECTING -> R.string.disconnecting
                    VpnStatus.REASSERTING -> R.string.reconnecting
                }
            }
            val statusText = stringResource(statusTextRes)

            val hasNoConfigurations = configurations.isEmpty() && chains.isEmpty()
            // Enabled while connecting too: that tap is the cancel.
            PowerButton(
                isConnected = isConnected,
                isTransitioning = isTransitioning || autoSelecting,
                enabled = hasNoConfigurations || !viewModel.isButtonDisabled,
                statusText = statusText,
                onClick = {
                    if (hasNoConfigurations) showingAddSheet = true else viewModel.toggleVPN()
                }
            )

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = statusText,
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Medium),
                color = when {
                    noInternet -> MaterialTheme.colorScheme.error
                    isConnected -> LightAzure
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                },
                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                modifier = Modifier.padding(horizontal = 32.dp)
            )

            Spacer(modifier = Modifier.height(if (isConnected) 18.dp else 28.dp))

            AnimatedVisibility(
                visible = isConnected,
                enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
                exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 4.dp)) {
                    SessionStatsRow(
                        bytesIn = bytesIn,
                        bytesOut = bytesOut,
                        downloadSpeed = downloadSpeed,
                        uploadSpeed = uploadSpeed,
                        uptimeSeconds = uptimeSeconds,
                        contentColor = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.fillMaxWidth()
                    )
                    exitInfo?.let { exit ->
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = stringResource(
                                R.string.exit_ip,
                                listOfNotNull(
                                    exit.countryCode?.let { com.mythaia.ui.components.flagForCountryCode(it) },
                                    exit.country,
                                    exit.ip
                                ).joinToString(" ")
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                            // Shown only while connected, on the dark connected gradient.
                            color = Color.White.copy(alpha = 0.82f),
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.refreshExitInfo() }
                                .padding(vertical = 4.dp)
                        )
                    }
                    strictPrivateDns?.let { host ->
                        Spacer(modifier = Modifier.height(10.dp))
                        PrivateDnsBanner(host = host, onOpen = { com.mythaia.ui.settings.SystemShortcuts.openNetworkSettings(homeContext) })
                    }
                    activeSubscription?.let { subscription ->
                        Spacer(modifier = Modifier.height(12.dp))
                        SubscriptionUsageCard(subscription = subscription)
                        com.mythaia.ui.components.SubscriptionNoticeCard(subscription = subscription, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            }

            Spacer(modifier = Modifier.weight(1f))

            // What the tunnel draws from: the group, and Auto or the pin.
            if (hasNoConfigurations) {
                SelectorCard(
                    modifier = Modifier.padding(horizontal = 20.dp),
                    onClick = { showingAddSheet = true }
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
            } else {
                SelectorCard(
                    modifier = Modifier.padding(horizontal = 20.dp),
                    onClick = { showingPicker = true }
                ) {
                    Icon(
                        imageVector = when {
                            isChain -> Icons.Default.Link
                            activeIsAuto -> Icons.Default.Bolt
                            else -> Icons.Default.PushPin
                        },
                        contentDescription = null,
                        tint = if (isConnected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = when {
                                isChain -> stringResource(R.string.chains)
                                activeGroup != null -> groupName(activeGroup)
                                else -> defaultGroupName
                            },
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = when {
                                isChain -> selectedName ?: ""
                                activeIsAuto && selectedName != null ->
                                    stringResource(R.string.auto_prefix, selectedName)
                                activeIsAuto -> stringResource(R.string.auto_mode)
                                else -> selectedName ?: ""
                            },
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                            color = MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    if (autoSelecting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                    } else {
                        selectedConfigId?.let { id ->
                            latencyResults[id]?.let { result ->
                                LatencyBadge(latency = result)
                                Spacer(modifier = Modifier.width(8.dp))
                            }
                        }
                    }
                    Icon(
                        imageVector = Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                    )
                }
            }

            // Settings is a tab of the navigation bar now, not a hill drawn here.
            Spacer(modifier = Modifier.height(20.dp))
        }
    }

    if (showingPicker) {
        GroupPickerSheet(
            viewModel = viewModel,
            groups = groups,
            chainsCount = chains.size,
            initialGroupId = if (isChain) CHAINS_GROUP_ID else activeGroupId,
            onDismiss = { showingPicker = false }
        )
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
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
            // The editor inside paints the background colour; matching it
            // keeps the strip under the content from showing as a white band.
            containerColor = MaterialTheme.colorScheme.background
        ) {
            NewServerFlow(
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

/** The paper compact row used for the selector and the empty-state CTA. */
@Composable
private fun SelectorCard(
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
    content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit
) {
    Card(
        onClick = onClick,
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface
        ),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            content = content
        )
    }
}

/** Rule / Global as one small pill, so the switch reads as a mode, not a setting. */
@Composable
private fun ModePill(
    global: Boolean,
    onGlobal: () -> Unit,
    onRule: () -> Unit,
    onDarkGround: Boolean
) {
    val container = if (onDarkGround) Color.White.copy(alpha = 0.12f) else MaterialTheme.colorScheme.surface
    val border = if (onDarkGround) Color.White.copy(alpha = 0.25f) else MaterialTheme.colorScheme.outline
    val active = if (onDarkGround) Color.White.copy(alpha = 0.22f) else MaterialTheme.colorScheme.primaryContainer
    val activeText = if (onDarkGround) Color.White else MaterialTheme.colorScheme.onPrimaryContainer
    val idleText = if (onDarkGround) Color.White.copy(alpha = 0.75f) else MaterialTheme.colorScheme.onSurfaceVariant

    Surface(
        shape = RoundedCornerShape(50),
        color = container,
        border = BorderStroke(1.dp, border)
    ) {
        Row(modifier = Modifier.padding(3.dp)) {
            @Composable
            fun segment(label: String, selected: Boolean, onClick: () -> Unit) {
                Surface(
                    shape = RoundedCornerShape(50),
                    color = if (selected) active else Color.Transparent,
                    modifier = Modifier.clickable(onClick = onClick)
                ) {
                    Text(
                        text = label,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (selected) activeText else idleText,
                        maxLines = 1,
                        softWrap = false,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 7.dp)
                    )
                }
            }
            segment(stringResource(R.string.proxy_mode_rule), !global, onRule)
            segment(stringResource(R.string.proxy_mode_global), global, onGlobal)
        }
    }
}

/**
 * Two columns of stickers along the edges. They keep to a narrow band so the
 * middle of the screen stays for the controls, and they never take touches.
 */
@Composable
private fun BoxScope.EdgeStickers(
    visible: Boolean,
    failed: Boolean,
    contentPadding: PaddingValues
) {
    val today = remember { StickerCalendar.forDate() }
    val stickers = if (failed) List(4) { Sticker.RED_X } else today
    val color = if (failed) MaterialTheme.colorScheme.error else LightAzure.copy(alpha = 0.9f)

    AnimatedVisibility(
        visible = visible,
        enter = fadeIn(tween(500)),
        exit = fadeOut(tween(300)),
        modifier = Modifier.matchParentSize()
    ) {
        Box(modifier = Modifier.fillMaxSize().padding(contentPadding)) {
            Column(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .fillMaxHeight(0.7f)
                    .padding(start = 10.dp),
                verticalArrangement = Arrangement.SpaceEvenly
            ) {
                stickers.forEachIndexed { index, sticker ->
                    StickerGlyph(
                        sticker = sticker,
                        color = color,
                        modifier = Modifier
                            .size(if (index % 2 == 0) 34.dp else 26.dp)
                            .alpha(if (failed) 0.95f else 0.55f)
                    )
                }
            }
            Column(
                modifier = Modifier
                    .align(Alignment.CenterEnd)
                    .fillMaxHeight(0.7f)
                    .padding(end = 10.dp),
                verticalArrangement = Arrangement.SpaceEvenly
            ) {
                stickers.asReversed().forEachIndexed { index, sticker ->
                    StickerGlyph(
                        sticker = sticker,
                        color = color,
                        modifier = Modifier
                            .size(if (index % 2 == 1) 34.dp else 26.dp)
                            .alpha(if (failed) 0.95f else 0.55f)
                    )
                }
            }
        }
    }
}

/**
 * Hiddify's picker: the groups as chips, then what the chosen group offers —
 * Auto first, then its servers. A tap on a server pins it; a tap on Auto
 * lets the group choose again.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupPickerSheet(
    viewModel: VpnViewModel,
    groups: List<ProxyGroup>,
    chainsCount: Int,
    initialGroupId: String,
    onDismiss: () -> Unit
) {
    val pinnedByGroup by viewModel.pinnedByGroup.collectAsState()
    val autoChoice by viewModel.autoChoice.collectAsState()
    val latencyResults by viewModel.latencyResults.collectAsState()
    val activeGroupId by viewModel.activeGroupId.collectAsState()
    val selectedChainId by viewModel.selectedChainId.collectAsState()
    val chains by viewModel.chainRepository.chains.collectAsState()
    val autoSelecting by viewModel.autoSelecting.collectAsState()

    var browsing by rememberSaveable { mutableStateOf(initialGroupId) }
    val defaultGroupName = stringResource(R.string.group_default)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        containerColor = MaterialTheme.colorScheme.surface
    ) {
        Column(modifier = Modifier.fillMaxHeight(0.85f)) {
            Text(
                text = stringResource(R.string.select_configuration),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
            )

            LazyRow(
                contentPadding = PaddingValues(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(groups, key = { it.id }) { group ->
                    val isActive = selectedChainId == null && activeGroupId == group.id
                    FilterChip(
                        selected = browsing == group.id,
                        // Tapping a group is choosing it: the tunnel follows
                        // this group (its pin, or Auto) even if the sheet is
                        // then closed without picking a server.
                        onClick = {
                            browsing = group.id
                            if (!(selectedChainId == null && activeGroupId == group.id)) {
                                viewModel.selectGroup(group.id)
                            }
                        },
                        label = {
                            Text(
                                text = "${if (group.isDefault) defaultGroupName else group.name} · ${group.configs.size}",
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        },
                        leadingIcon = if (isActive) {
                            { Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp)) }
                        } else null,
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                            selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            selectedLeadingIconColor = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    )
                }
                if (chainsCount > 0) {
                    item(key = CHAINS_GROUP_ID) {
                        FilterChip(
                            selected = browsing == CHAINS_GROUP_ID,
                            onClick = { browsing = CHAINS_GROUP_ID },
                            label = { Text("${stringResource(R.string.chains)} · $chainsCount") },
                            leadingIcon = if (selectedChainId != null) {
                                { Icon(Icons.Default.Check, contentDescription = null, modifier = Modifier.size(16.dp)) }
                            } else null,
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                selectedLabelColor = MaterialTheme.colorScheme.onPrimaryContainer,
                                selectedLeadingIconColor = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            if (browsing == CHAINS_GROUP_ID) {
                LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
                    items(chains, key = { it.id }) { chain ->
                        val selected = chain.id == selectedChainId
                        PickerRow(
                            title = chain.name,
                            subtitle = null,
                            selected = selected,
                            leading = { Icon(Icons.Default.Link, contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant) },
                            trailing = null,
                            onClick = {
                                viewModel.selectChain(chain)
                                onDismiss()
                            }
                        )
                    }
                }
                return@Column
            }

            val group = groups.firstOrNull { it.id == browsing } ?: return@Column
            val groupIsActive = selectedChainId == null && activeGroupId == group.id
            val pinned = pinnedByGroup[group.id]
            val auto = autoChoice[group.id]
            val candidates = group.configs

            LazyColumn(contentPadding = PaddingValues(bottom = 24.dp)) {
                item(key = "auto") {
                    val autoName = auto?.let { id -> candidates.firstOrNull { it.id == id }?.name }
                    PickerRow(
                        title = stringResource(R.string.auto_mode),
                        subtitle = autoName?.let { stringResource(R.string.auto_prefix, it) }
                            ?: stringResource(R.string.auto_mode_hint),
                        selected = groupIsActive && pinned == null,
                        leading = {
                            if (autoSelecting && groupIsActive) {
                                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(Icons.Default.Bolt, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            }
                        },
                        trailing = auto?.let { latencyResults[it] }?.let { { LatencyBadge(latency = it) } },
                        onClick = {
                            viewModel.useAuto(group.id)
                            onDismiss()
                        }
                    )
                }
                if (candidates.isEmpty()) {
                    item(key = "empty") {
                        Text(
                            text = stringResource(R.string.no_servers_in_group),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
                        )
                    }
                }
                items(candidates, key = { it.id }) { config ->
                    val isPinned = groupIsActive && pinned == config.id
                    PickerRow(
                        title = config.name,
                        subtitle = config.displayEndpoint,
                        selected = isPinned,
                        leading = {
                            Icon(
                                imageVector = if (isPinned) Icons.Default.PushPin else Icons.Default.Check,
                                contentDescription = null,
                                tint = if (isPinned) MaterialTheme.colorScheme.primary
                                else if (auto == config.id) MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
                                else Color.Transparent
                            )
                        },
                        trailing = latencyResults[config.id]?.let { { LatencyBadge(latency = it) } },
                        onClick = {
                            viewModel.pinConfiguration(config)
                            onDismiss()
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun PickerRow(
    title: String,
    subtitle: String?,
    selected: Boolean,
    leading: @Composable () -> Unit,
    trailing: (@Composable () -> Unit)?,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        color = if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f) else Color.Transparent,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) { leading() }
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            if (trailing != null) {
                Spacer(modifier = Modifier.width(8.dp))
                trailing()
            }
        }
    }
}

/**
 * Android's strict Private DNS sends every lookup over TLS to its own host,
 * past the tunnel's DNS: domain rules, ad blocking and per-domain routing go
 * blind. The app cannot switch it off, so it says so and opens the screen.
 */
@Composable
private fun PrivateDnsBanner(host: String, onOpen: () -> Unit) {
    androidx.compose.material3.Surface(
        shape = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Text(
                text = stringResource(R.string.private_dns_banner, host),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            androidx.compose.material3.TextButton(onClick = onOpen, contentPadding = PaddingValues(0.dp)) {
                Text(stringResource(R.string.private_dns_open))
            }
        }
    }
}
