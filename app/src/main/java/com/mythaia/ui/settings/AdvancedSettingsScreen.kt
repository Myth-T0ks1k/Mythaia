package com.mythaia.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.ReceiptLong
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ContentCut
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdvancedSettingsScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    var showIpv6Settings by remember { mutableStateOf(false) }
    var showEncryptedDns by remember { mutableStateOf(false) }
    var showLogs by remember { mutableStateOf(false) }
    var showFragment by remember { mutableStateOf(false) }

    val activeSubScreen = showIpv6Settings || showEncryptedDns || showLogs || showFragment
    BackHandler(enabled = activeSubScreen) {
        showIpv6Settings = false
        showEncryptedDns = false
        showLogs = false
        showFragment = false
    }

    val currentRoute = when {
        showIpv6Settings -> "ipv6"
        showEncryptedDns -> "dns"
        showLogs -> "logs"
        showFragment -> "fragment"
        else -> "root"
    }

    SubScreenHost(state = currentRoute, rootKey = "root") { route ->
        when (route) {
            "ipv6" -> Ipv6SettingsScreen(viewModel = viewModel, onBack = { showIpv6Settings = false })
            "dns" -> EncryptedDnsSettingsScreen(viewModel = viewModel, onBack = { showEncryptedDns = false })
            "logs" -> LogListScreen(onBack = { showLogs = false })
            "fragment" -> FragmentSettingsScreen(viewModel = viewModel, onBack = { showFragment = false })
            else -> AdvancedSettingsRoot(
                viewModel = viewModel,
                onBack = onBack,
                onOpenIpv6 = { showIpv6Settings = true },
                onOpenEncryptedDns = { showEncryptedDns = true },
                onOpenLogs = { showLogs = true },
                onOpenFragment = { showFragment = true }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdvancedSettingsRoot(
    viewModel: VpnViewModel,
    onBack: () -> Unit,
    onOpenIpv6: () -> Unit,
    onOpenEncryptedDns: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenFragment: () -> Unit
) {
    var experimentalEnabled by remember { mutableStateOf(viewModel.experimentalEnabled) }
    var remnawaveHWIDEnabled by remember { mutableStateOf(viewModel.remnawaveHWIDEnabled) }
    var blockQuicEnabled by remember { mutableStateOf(viewModel.blockQuicEnabled) }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.advanced_settings)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            WingSectionLabel(stringResource(R.string.network))
            WingGroupCard {
                WingSwitchRow(
                    icon = Icons.Filled.Block,
                    label = stringResource(R.string.block_quic),
                    checked = blockQuicEnabled,
                    onCheckedChange = {
                        blockQuicEnabled = it
                        viewModel.blockQuicEnabled = it
                    }
                )
                WingRowDivider()
                WingNavRow(
                    icon = Icons.Filled.Language,
                    label = stringResource(R.string.ipv6),
                    onClick = onOpenIpv6
                )
                WingRowDivider()
                WingNavRow(
                    icon = Icons.Filled.Shield,
                    label = stringResource(R.string.encrypted_dns),
                    onClick = onOpenEncryptedDns
                )
                WingRowDivider()
                WingNavRow(
                    icon = Icons.Filled.ContentCut,
                    label = stringResource(R.string.fragment_hello),
                    onClick = onOpenFragment
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            WingSectionLabel(stringResource(R.string.diagnostics))
            WingGroupCard {
                WingNavRow(
                    icon = Icons.AutoMirrored.Filled.ReceiptLong,
                    label = stringResource(R.string.logs),
                    onClick = onOpenLogs
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            WingSectionLabel(stringResource(R.string.other))
            WingGroupCard {
                WingSwitchRow(
                    icon = Icons.Filled.Fingerprint,
                    label = stringResource(R.string.remnawave_hwid),
                    checked = remnawaveHWIDEnabled,
                    onCheckedChange = {
                        remnawaveHWIDEnabled = it
                        viewModel.remnawaveHWIDEnabled = it
                    }
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            WingSectionLabel(stringResource(R.string.experimental))
            WingGroupCard {
                WingSwitchRow(
                    icon = Icons.Filled.Science,
                    label = stringResource(R.string.experimental_features),
                    checked = experimentalEnabled,
                    onCheckedChange = {
                        experimentalEnabled = it
                        viewModel.experimentalEnabled = it
                    }
                )
            }
            Text(
                text = stringResource(R.string.experimental_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 8.dp)
            )
        }
    }
}

@Composable
private fun WingSectionLabel(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.sp),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)
    )
}

@Composable
private fun WingGroupCard(content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column { content() }
    }
}

@Composable
private fun WingRowDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(start = 60.dp),
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.outlineVariant
    )
}

@Composable
private fun WingIconTile(icon: ImageVector) {
    Box(
        modifier = Modifier
            .size(28.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
    }
}

@Composable
private fun WingSwitchRow(
    icon: ImageVector,
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        WingIconTile(icon)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = wingSwitchColors()
        )
    }
}

@Composable
private fun WingNavRow(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        WingIconTile(icon)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            modifier = Modifier.size(20.dp)
        )
    }
}

@Composable
private fun wingSwitchColors() = SwitchDefaults.colors(
    checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
    checkedTrackColor = MaterialTheme.colorScheme.primary,
    uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
    uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
    uncheckedBorderColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
)
