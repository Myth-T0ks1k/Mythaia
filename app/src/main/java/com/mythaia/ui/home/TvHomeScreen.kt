package com.mythaia.ui.home

import android.app.UiModeManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.PushPin
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.ui.components.SessionStatsRow
import com.mythaia.ui.components.SubscriptionNoticeCard
import com.mythaia.ui.components.SubscriptionUsageCard
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.components.flagForCountryCode
import com.mythaia.ui.proxy.AddProxyScreen
import com.mythaia.ui.proxy.NewServerFlow
import com.mythaia.ui.proxy.countryLabel
import com.mythaia.ui.proxy.rememberCountrySections
import com.mythaia.ui.settings.SystemShortcuts
import com.mythaia.ui.theme.Azure
import com.mythaia.ui.theme.Bone
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
import com.mythaia.ui.theme.WarningDark
import com.mythaia.ui.theme.WarningLight
import com.mythaia.viewmodel.ProxyGroup
import com.mythaia.viewmodel.VpnStatus
import com.mythaia.viewmodel.VpnViewModel

/**
 * Whether the device is a television: [UiModeManager.getCurrentModeType] is
 * [Configuration.UI_MODE_TYPE_TELEVISION], or the system declares
 * [PackageManager.FEATURE_LEANBACK].
 */
fun isTelevision(uiModeType: Int, hasLeanbackFeature: Boolean = false): Boolean =
    uiModeType == Configuration.UI_MODE_TYPE_TELEVISION || hasLeanbackFeature

fun isTelevision(context: Context): Boolean {
    val uiModeManager = context.getSystemService(UiModeManager::class.java)
    val modeType = uiModeManager?.currentModeType
        ?: (context.resources.configuration.uiMode and Configuration.UI_MODE_TYPE_MASK)
    val leanback = context.packageManager?.hasSystemFeature(PackageManager.FEATURE_LEANBACK) == true
    return isTelevision(modeType, leanback)
}

internal fun tvStatusTextRes(
    vpnStatus: VpnStatus,
    autoSelecting: Boolean,
    noInternet: Boolean
): Int = when {
    autoSelecting && vpnStatus != VpnStatus.CONNECTED -> R.string.measuring
    noInternet -> R.string.no_connectivity
    else -> when (vpnStatus) {
        VpnStatus.DISCONNECTED -> R.string.disconnected
        VpnStatus.CONNECTING -> R.string.connecting
        VpnStatus.CONNECTED -> R.string.connected
        VpnStatus.DISCONNECTING -> R.string.disconnecting
        VpnStatus.REASSERTING -> R.string.reconnecting
    }
}

internal fun tvConnectActionRes(
    hasNoConfigurations: Boolean,
    vpnStatus: VpnStatus,
    autoSelecting: Boolean
): Int = when {
    hasNoConfigurations -> R.string.add_a_configuration
    vpnStatus == VpnStatus.CONNECTED ||
        vpnStatus == VpnStatus.CONNECTING ||
        vpnStatus == VpnStatus.REASSERTING ||
        autoSelecting -> R.string.disconnect
    else -> R.string.connect
}

/**
 * TV-first Home screen for a 10-foot (3 m) leanback experience:
 * - Left pane: hero Connect/Disconnect toggle (receives initial D-pad focus),
 *   live session readout, Rule/Global mode switcher, and direct D-pad buttons
 *   for speed testing, adding a configuration, and opening Settings.
 * - Right pane: focusable group switcher (Default, subscriptions, chains,
 *   sort and country grouping toggles) above a large focusable server list
 *   with Auto and collapsible country sections.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TvHomeScreen(
    viewModel: VpnViewModel,
    onOpenSettings: () -> Unit,
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
    val autoCountry by viewModel.autoCountry.collectAsState()
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
    val connectivityOk by viewModel.connectivityOk.collectAsState()
    val exitInfo by viewModel.exitInfo.collectAsState()
    val groupByCountry by viewModel.groupByCountry.collectAsState()
    val collapsedCountries by viewModel.collapsedCountries.collectAsState()
    val geoIpGeneration by viewModel.geoIpGeneration.collectAsState()

    val context = LocalContext.current
    var strictPrivateDns by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(vpnStatus) {
        strictPrivateDns = SystemShortcuts.strictPrivateDns(context)
    }

    val isConnected = vpnStatus == VpnStatus.CONNECTED
    val isTransitioning = vpnStatus == VpnStatus.CONNECTING ||
        vpnStatus == VpnStatus.DISCONNECTING ||
        vpnStatus == VpnStatus.REASSERTING
    val noInternet = isConnected && connectivityOk == false

    val groups = remember(configurations, subscriptions) { viewModel.groups() }
    val activeGroup = groups.firstOrNull { it.id == activeGroupId } ?: groups.first()
    val isChain = selectedChainId != null
    var browsingChains by rememberSaveable { mutableStateOf(isChain) }
    LaunchedEffect(chains.size) {
        if (chains.isEmpty()) browsingChains = false
    }
    var sortByLatency by rememberSaveable { mutableStateOf(false) }

    val activeIsAuto = !isChain && pinnedByGroup[activeGroupId] == null
    val selectedName: String? = when {
        isChain -> chains.firstOrNull { it.id == selectedChainId }?.name
        else -> selectedConfigId?.let { id -> configurations.firstOrNull { it.id == id }?.name }
    }
    val defaultGroupName = stringResource(R.string.group_default)
    fun groupName(group: ProxyGroup) = if (group.isDefault) defaultGroupName else group.name

    val scopedCountry = autoCountry[activeGroup.id]
    val scopedLabel = scopedCountry?.let { countryLabel(it) }

    val activeSubscription = remember(selectedConfigId, configurations, subscriptions) {
        val subId = selectedConfigId
            ?.let { id -> configurations.find { it.id == id } }
            ?.subscriptionId
        subId?.let { id -> subscriptions.find { it.id == id } }
    }

    var showingAddSheet by rememberSaveable { mutableStateOf(false) }
    var showingManualAddSheet by rememberSaveable { mutableStateOf(false) }

    val connectFocus = remember { FocusRequester() }
    LaunchedEffect(Unit) {
        runCatching { connectFocus.requestFocus() }
    }

    val isDark = LocalMythaiaDarkTheme.current
    val gradientStart by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedStartDark
            isConnected -> GradientConnectedStartLight
            isDark -> GradientDisconnectedStartDark
            else -> GradientDisconnectedStartLight
        },
        animationSpec = tween(600),
        label = "tvGradientStart"
    )
    val gradientEnd by animateColorAsState(
        targetValue = when {
            isConnected && isDark -> GradientConnectedEndDark
            isConnected -> GradientConnectedEndLight
            isDark -> GradientDisconnectedEndDark
            else -> GradientDisconnectedEndLight
        },
        animationSpec = tween(600),
        label = "tvGradientEnd"
    )

    val statusText = stringResource(tvStatusTextRes(vpnStatus, autoSelecting, noInternet))
    val hasNoConfigurations = configurations.isEmpty() && chains.isEmpty()
    val connectActionLabel = stringResource(tvConnectActionRes(hasNoConfigurations, vpnStatus, autoSelecting))

    val activeTargetSummary = when {
        hasNoConfigurations -> stringResource(R.string.no_proxies)
        isChain -> "${stringResource(R.string.chains)} · ${selectedName.orEmpty()}"
        activeIsAuto && scopedLabel != null ->
            stringResource(R.string.auto_in_country, scopedLabel) + (selectedName?.let { " · $it" } ?: "")
        activeIsAuto && selectedName != null ->
            stringResource(R.string.auto_prefix, selectedName)
        activeIsAuto -> stringResource(R.string.auto_mode)
        else -> selectedName ?: groupName(activeGroup)
    }

    val visibleConfigs = remember(activeGroup, sortByLatency, if (sortByLatency) latencyResults else null) {
        if (!sortByLatency) activeGroup.configs
        else activeGroup.configs.sortedBy { config ->
            (latencyResults[config.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE
        }
    }

    val sections = rememberCountrySections(
        configs = activeGroup.configs,
        enabled = groupByCountry,
        sortByLatency = sortByLatency,
        latencies = latencyResults,
        geoIpGeneration = geoIpGeneration,
        countryOf = viewModel::countryOf
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.linearGradient(colors = listOf(gradientStart, gradientEnd)))
    ) {
        WingMark(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(contentPadding)
                .offset(x = 40.dp, y = (-10).dp)
                .size(280.dp)
                .alpha(if (isConnected) 0.10f else 0.06f),
            color = if (isConnected) LightAzure else MaterialTheme.colorScheme.primary
        )

        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(contentPadding)
                .padding(horizontal = 32.dp, vertical = 22.dp),
            horizontalArrangement = Arrangement.spacedBy(28.dp)
        ) {
            // Left pane: status, primary connect toggle, live stats, mode & quick actions.
            Column(
                modifier = Modifier
                    .width(340.dp)
                    .fillMaxHeight()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(bottom = 4.dp)
                ) {
                    WingMark(
                        modifier = Modifier.size(28.dp),
                        color = if (isConnected) LightAzure else MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.headlineSmall,
                        color = if (isConnected) Color.White.copy(alpha = 0.94f) else MaterialTheme.colorScheme.onBackground
                    )
                }

                val powerButtonLabel = stringResource(R.string.power_button)
                TvFocusSurface(
                    onClick = {
                        if (hasNoConfigurations) showingAddSheet = true else viewModel.toggleVPN()
                    },
                    enabled = hasNoConfigurations || !viewModel.isButtonDisabled,
                    selected = isConnected,
                    onDarkGround = isConnected,
                    shape = RoundedCornerShape(24.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(connectFocus)
                        .semantics {
                            contentDescription = powerButtonLabel
                            stateDescription = statusText
                            role = Role.Switch
                        }
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 20.dp, vertical = 18.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier
                                    .size(64.dp)
                                    .clip(CircleShape)
                                    .background(if (isConnected) Azure else MaterialTheme.colorScheme.primaryContainer)
                            ) {
                                if (isTransitioning || autoSelecting) {
                                    CircularProgressIndicator(
                                        color = if (isConnected) Bone else MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(30.dp),
                                        strokeWidth = 3.dp
                                    )
                                } else {
                                    WingMark(
                                        modifier = Modifier.size(34.dp),
                                        color = if (isConnected) Bone else MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = statusText,
                                    style = MaterialTheme.typography.headlineMedium,
                                    color = when {
                                        noInternet -> MaterialTheme.colorScheme.error
                                        isConnected -> LightAzure
                                        else -> MaterialTheme.colorScheme.onSurface
                                    },
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = activeTargetSummary,
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(14.dp))
                                .background(
                                    if (isConnected) MaterialTheme.colorScheme.surfaceVariant
                                    else MaterialTheme.colorScheme.primary
                                )
                                .padding(vertical = 10.dp)
                        ) {
                            Text(
                                text = connectActionLabel,
                                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
                                color = if (isConnected) MaterialTheme.colorScheme.onSurface
                                else MaterialTheme.colorScheme.onPrimary
                            )
                        }
                    }
                }

                if (isConnected) {
                    Surface(
                        shape = RoundedCornerShape(20.dp),
                        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.92f),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
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
                                TvFocusSurface(
                                    onClick = { viewModel.refreshExitInfo() },
                                    onDarkGround = false,
                                    shape = RoundedCornerShape(12.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        text = stringResource(
                                            R.string.exit_ip,
                                            listOfNotNull(
                                                exit.countryCode?.let { flagForCountryCode(it) },
                                                exit.country,
                                                exit.ip
                                            ).joinToString(" ")
                                        ),
                                        style = MaterialTheme.typography.bodyLarge,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                                    )
                                }
                            }
                        }
                    }
                    activeSubscription?.let { subscription ->
                        SubscriptionUsageCard(subscription = subscription)
                        SubscriptionNoticeCard(subscription = subscription)
                    }
                }

                strictPrivateDns?.let { host ->
                    TvFocusSurface(
                        onClick = { SystemShortcuts.openNetworkSettings(context) },
                        onDarkGround = isConnected,
                        shape = RoundedCornerShape(16.dp),
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text(
                                text = stringResource(R.string.private_dns_banner, host),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = stringResource(R.string.private_dns_open),
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onErrorContainer
                            )
                        }
                    }
                }

                // Rule / Global mode switcher — two large focusable pills.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    TvModeButton(
                        label = stringResource(R.string.proxy_mode_rule),
                        selected = !isGlobalMode,
                        onDarkGround = isConnected,
                        onClick = { viewModel.proxyMode = "rule" },
                        modifier = Modifier.weight(1f)
                    )
                    TvModeButton(
                        label = stringResource(R.string.proxy_mode_global),
                        selected = isGlobalMode,
                        onDarkGround = isConnected,
                        onClick = { viewModel.proxyMode = "global" },
                        modifier = Modifier.weight(1f)
                    )
                }

                // Quick actions reachable directly with D-pad Down from Connect.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    TvActionButton(
                        icon = Icons.Default.Speed,
                        label = stringResource(R.string.test_all),
                        enabled = !browsingChains && activeGroup.configs.isNotEmpty(),
                        onDarkGround = isConnected,
                        onClick = {
                            viewModel.testLatencies(
                                forConfigs = activeGroup.configs,
                                kind = LatencyKind.HTTP
                            )
                        },
                        modifier = Modifier.weight(1f)
                    )
                    TvActionButton(
                        icon = Icons.Default.Add,
                        label = stringResource(R.string.add),
                        onDarkGround = isConnected,
                        onClick = { showingAddSheet = true },
                        modifier = Modifier.weight(1f)
                    )
                }

                TvActionButton(
                    icon = Icons.Default.Settings,
                    label = stringResource(R.string.settings),
                    onDarkGround = isConnected,
                    onClick = onOpenSettings,
                    modifier = Modifier.fillMaxWidth()
                )
            }

            // Right pane: group switcher + big focusable server list.
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight()
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    LazyRow(
                        modifier = Modifier.weight(1f),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        contentPadding = PaddingValues(vertical = 2.dp)
                    ) {
                        items(groups, key = { it.id }) { group ->
                            val selected = !browsingChains && activeGroup.id == group.id
                            TvGroupChip(
                                label = "${groupName(group)} · ${group.configs.size}",
                                selected = selected,
                                activeInTunnel = !isChain && activeGroupId == group.id,
                                onDarkGround = isConnected,
                                onClick = {
                                    browsingChains = false
                                    if (isChain || activeGroupId != group.id) {
                                        viewModel.selectGroup(group.id)
                                    }
                                }
                            )
                        }
                        if (chains.isNotEmpty()) {
                            item(key = "__chains__") {
                                TvGroupChip(
                                    label = "${stringResource(R.string.chains)} · ${chains.size}",
                                    selected = browsingChains,
                                    activeInTunnel = isChain,
                                    onDarkGround = isConnected,
                                    onClick = { browsingChains = true }
                                )
                            }
                        }
                    }

                    if (!browsingChains && activeGroup.configs.size > 1) {
                        TvIconToggle(
                            icon = Icons.AutoMirrored.Filled.Sort,
                            contentDescription = stringResource(R.string.sort_by_latency),
                            checked = sortByLatency,
                            onDarkGround = isConnected,
                            onClick = { sortByLatency = !sortByLatency }
                        )
                        TvIconToggle(
                            icon = Icons.Default.Public,
                            contentDescription = stringResource(R.string.group_by_country),
                            checked = groupByCountry,
                            onDarkGround = isConnected,
                            onClick = { viewModel.setGroupByCountry(!groupByCountry) }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                if (hasNoConfigurations) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        TvFocusSurface(
                            onClick = { showingAddSheet = true },
                            onDarkGround = isConnected,
                            shape = RoundedCornerShape(24.dp),
                            modifier = Modifier.fillMaxWidth(0.8f)
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 28.dp, vertical = 24.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(16.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Add,
                                    contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(32.dp)
                                )
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = stringResource(R.string.no_proxies),
                                        style = MaterialTheme.typography.headlineSmall,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = stringResource(R.string.add_a_configuration),
                                        style = MaterialTheme.typography.titleMedium,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                } else if (browsingChains) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        contentPadding = PaddingValues(bottom = 24.dp)
                    ) {
                        items(chains, key = { it.id }) { chain ->
                            TvChainRow(
                                chain = chain,
                                selected = selectedChainId == chain.id,
                                onDarkGround = isConnected,
                                onClick = { viewModel.selectChain(chain) }
                            )
                        }
                    }
                } else {
                    val groupIsActive = !isChain && activeGroupId == activeGroup.id
                    val pinned = pinnedByGroup[activeGroup.id]
                    val auto = autoChoice[activeGroup.id]

                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        contentPadding = PaddingValues(bottom = 24.dp)
                    ) {
                        item(key = "auto") {
                            val autoName = auto?.let { id -> activeGroup.configs.firstOrNull { it.id == id }?.name }
                            val subtitle = when {
                                groupIsActive && pinned == null && scopedLabel != null ->
                                    stringResource(R.string.auto_in_country, scopedLabel) + (autoName?.let { " · $it" } ?: "")
                                autoName != null -> stringResource(R.string.auto_prefix, autoName)
                                else -> stringResource(R.string.auto_mode_hint)
                            }
                            TvAutoRow(
                                selected = groupIsActive && pinned == null && scopedCountry == null,
                                busy = autoSelecting && groupIsActive,
                                subtitle = subtitle,
                                latency = auto?.let { latencyResults[it] },
                                onDarkGround = isConnected,
                                onClick = { viewModel.useAuto(activeGroup.id) }
                            )
                        }

                        if (activeGroup.configs.isEmpty()) {
                            item(key = "empty") {
                                Text(
                                    text = stringResource(R.string.no_servers_in_group),
                                    style = MaterialTheme.typography.titleMedium,
                                    color = if (isConnected) Color.White.copy(alpha = 0.8f)
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 20.dp)
                                )
                            }
                        }

                        fun serverItems(list: List<ProxyConfiguration>) =
                            items(list, key = { it.id }) { config ->
                                val isSelected = groupIsActive &&
                                    (pinned == config.id || (pinned == null && selectedConfigId == config.id))
                                TvServerRow(
                                    configuration = config,
                                    isSelected = isSelected,
                                    isPinned = groupIsActive && pinned == config.id,
                                    isAutoPick = groupIsActive && pinned == null && auto == config.id,
                                    latency = latencyResults[config.id],
                                    onDarkGround = isConnected,
                                    onClick = { viewModel.pinConfiguration(config) }
                                )
                            }

                        if (sections == null) {
                            serverItems(visibleConfigs)
                        } else {
                            for (section in sections) {
                                val code = section.code
                                val collapsed = viewModel.countrySectionKey(activeGroup.id, code) in collapsedCountries
                                val canAuto = code != null && section.items.any {
                                    it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3
                                }
                                val autoHere = groupIsActive && pinned == null && code != null && scopedCountry == code
                                item(key = "country-${code ?: "-"}") {
                                    TvCountryHeader(
                                        code = code,
                                        count = section.items.size,
                                        collapsed = collapsed,
                                        autoActive = autoHere,
                                        autoBusy = autoSelecting && autoHere,
                                        onDarkGround = isConnected,
                                        onToggle = { viewModel.toggleCountryCollapsed(activeGroup.id, code) },
                                        onPing = {
                                            viewModel.testLatencies(
                                                forConfigs = section.items,
                                                kind = LatencyKind.HTTP
                                            )
                                        },
                                        onAuto = if (canAuto) {
                                            {
                                                if (autoHere) viewModel.useAuto(activeGroup.id)
                                                else viewModel.useAutoIn(activeGroup.id, code)
                                            }
                                        } else null
                                    )
                                }
                                if (!collapsed) {
                                    serverItems(section.items)
                                }
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
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
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

/**
 * Focusable TV card that paints a high-contrast 2.5dp azure border and lifts
 * its container fill whenever D-pad focus lands on it, so the active target is
 * unmistakable from 3 meters away.
 */
@Composable
private fun TvFocusSurface(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    selected: Boolean = false,
    onDarkGround: Boolean = false,
    shape: Shape = RoundedCornerShape(18.dp),
    containerColor: Color? = null,
    content: @Composable () -> Unit
) {
    var focused by remember { mutableStateOf(false) }
    val defaultContainer = when {
        focused && selected -> MaterialTheme.colorScheme.primaryContainer
        focused -> MaterialTheme.colorScheme.surfaceContainerHighest
        selected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.72f)
        onDarkGround -> MaterialTheme.colorScheme.surface.copy(alpha = 0.94f)
        else -> MaterialTheme.colorScheme.surface
    }
    val border = when {
        focused -> BorderStroke(2.5.dp, if (onDarkGround) LightAzure else MaterialTheme.colorScheme.primary)
        selected -> BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary)
        else -> BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    }

    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = shape,
        color = containerColor ?: defaultContainer,
        contentColor = MaterialTheme.colorScheme.onSurface,
        border = border,
        modifier = modifier.onFocusChanged { focused = it.isFocused },
        content = content
    )
}

@Composable
private fun TvModeButton(
    label: String,
    selected: Boolean,
    onDarkGround: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    TvFocusSurface(
        onClick = onClick,
        selected = selected,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(16.dp),
        modifier = modifier.heightIn(min = 48.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            if (selected) {
                Icon(
                    imageVector = Icons.Default.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium
                ),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun TvActionButton(
    icon: ImageVector,
    label: String,
    onDarkGround: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true
) {
    TvFocusSurface(
        onClick = onClick,
        enabled = enabled,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(16.dp),
        modifier = modifier.heightIn(min = 48.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun TvGroupChip(
    label: String,
    selected: Boolean,
    activeInTunnel: Boolean,
    onDarkGround: Boolean,
    onClick: () -> Unit
) {
    TvFocusSurface(
        onClick = onClick,
        selected = selected,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(50)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (activeInTunnel) {
                Icon(
                    imageVector = Icons.Default.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
            }
            Text(
                text = label,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium
                ),
                maxLines = 1
            )
        }
    }
}

@Composable
private fun TvIconToggle(
    icon: ImageVector,
    contentDescription: String,
    checked: Boolean,
    onDarkGround: Boolean,
    onClick: () -> Unit
) {
    TvFocusSurface(
        onClick = onClick,
        selected = checked,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.size(46.dp)
    ) {
        Box(contentAlignment = Alignment.Center) {
            Icon(
                imageVector = icon,
                contentDescription = contentDescription,
                tint = if (checked) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(22.dp)
            )
        }
    }
}

@Composable
private fun TvAutoRow(
    selected: Boolean,
    busy: Boolean,
    subtitle: String,
    latency: LatencyResult?,
    onDarkGround: Boolean,
    onClick: () -> Unit
) {
    TvFocusSurface(
        onClick = onClick,
        selected = selected,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 68.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(32.dp),
                contentAlignment = Alignment.Center
            ) {
                if (busy) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.5.dp,
                        color = MaterialTheme.colorScheme.primary
                    )
                } else {
                    Icon(
                        imageVector = Icons.Default.Bolt,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(26.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.auto_mode),
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            if (latency != null) {
                Spacer(modifier = Modifier.width(12.dp))
                TvLatencyBadge(latency = latency)
            }
        }
    }
}

@Composable
private fun TvCountryHeader(
    code: String?,
    count: Int,
    collapsed: Boolean,
    autoActive: Boolean,
    autoBusy: Boolean,
    onDarkGround: Boolean,
    onToggle: () -> Unit,
    onPing: () -> Unit,
    onAuto: (() -> Unit)?
) {
    val label = countryLabel(code)
    val state = stringResource(if (collapsed) R.string.country_collapsed else R.string.country_expanded)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        TvFocusSurface(
            onClick = onToggle,
            onDarkGround = onDarkGround,
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier
                .weight(1f)
                .semantics {
                    role = Role.Button
                    stateDescription = state
                }
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold),
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = count.toString(),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.weight(1f))
                Icon(
                    imageVector = if (collapsed) Icons.Default.ExpandMore else Icons.Default.ExpandLess,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
        TvIconToggle(
            icon = Icons.Default.Speed,
            contentDescription = stringResource(R.string.country_ping, label),
            checked = false,
            onDarkGround = onDarkGround,
            onClick = onPing
        )
        if (onAuto != null) {
            TvFocusSurface(
                onClick = onAuto,
                selected = autoActive,
                onDarkGround = onDarkGround,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.size(46.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (autoBusy) {
                        CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            imageVector = Icons.Default.Bolt,
                            contentDescription = stringResource(R.string.auto_in_country, label),
                            tint = if (autoActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TvServerRow(
    configuration: ProxyConfiguration,
    isSelected: Boolean,
    isPinned: Boolean,
    isAutoPick: Boolean,
    latency: LatencyResult?,
    onDarkGround: Boolean,
    onClick: () -> Unit
) {
    TvFocusSurface(
        onClick = onClick,
        selected = isSelected,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 68.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(28.dp),
                contentAlignment = Alignment.Center
            ) {
                when {
                    isPinned -> Icon(
                        imageVector = Icons.Default.PushPin,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp)
                    )
                    isAutoPick -> Icon(
                        imageVector = Icons.Default.Bolt,
                        contentDescription = stringResource(R.string.auto_picked),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp)
                    )
                    isSelected -> Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = configuration.name,
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TvProtocolPill(configuration.outboundProtocol.displayName)
                    if (configuration.outboundProtocol == OutboundProtocol.VLESS && configuration.transport != "tcp") {
                        TvProtocolPill(configuration.transport.uppercase())
                    }
                    val security = configuration.security.uppercase()
                    if (security != "NONE") TvProtocolPill(security)
                    if (configuration.skipsCertificateCheck) {
                        Text(
                            text = stringResource(R.string.insecure_caps),
                            style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold),
                            color = MaterialTheme.colorScheme.onError,
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(MaterialTheme.colorScheme.error)
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                    Text(
                        text = configuration.displayEndpoint,
                        style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            if (latency != null) {
                Spacer(modifier = Modifier.width(12.dp))
                TvLatencyBadge(latency = latency)
            }
        }
    }
}

@Composable
private fun TvChainRow(
    chain: ProxyChain,
    selected: Boolean,
    onDarkGround: Boolean,
    onClick: () -> Unit
) {
    TvFocusSurface(
        onClick = onClick,
        selected = selected,
        onDarkGround = onDarkGround,
        shape = RoundedCornerShape(20.dp),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 68.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (selected) Icons.Default.Check else Icons.Default.Link,
                contentDescription = null,
                tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(14.dp))
            Text(
                text = chain.name,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun TvProtocolPill(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f))
            .padding(horizontal = 8.dp, vertical = 2.dp)
    )
}

@Composable
private fun TvLatencyBadge(latency: LatencyResult?) {
    when (latency) {
        is LatencyResult.Testing -> {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp),
                strokeWidth = 2.5.dp
            )
        }
        is LatencyResult.Success -> {
            val color = when {
                latency.ms < 300 -> MaterialTheme.colorScheme.primary
                latency.ms < 600 -> if (LocalMythaiaDarkTheme.current) WarningDark else WarningLight
                else -> MaterialTheme.colorScheme.error
            }
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(12.dp))
                    .background(color.copy(alpha = 0.14f))
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(color)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = stringResource(R.string.latency_ms, latency.ms),
                    style = MaterialTheme.typography.titleSmall.copy(fontFamily = FontFamily.Monospace),
                    color = color
                )
            }
        }
        is LatencyResult.Insecure -> TvQuietBadge(stringResource(R.string.insecure))
        is LatencyResult.Failed -> TvQuietBadge(stringResource(R.string.timeout))
        null -> {}
    }
}

@Composable
private fun TvQuietBadge(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f))
            .padding(horizontal = 10.dp, vertical = 6.dp)
    )
}
