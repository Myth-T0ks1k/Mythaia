package com.mythaia.ui.proxy

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.ui.components.WingIconTile
import com.mythaia.ui.components.WingPanel
import com.mythaia.ui.components.WingSectionTitle

/** The groups the picker shows, in the order people look for them. */
internal enum class ProtocolGroup(val titleRes: Int) {
    XRAY(R.string.proto_group_xray),
    QUIC(R.string.proto_group_quic),
    VPN(R.string.proto_group_vpn),
    TLS(R.string.proto_group_tls),
    OTHER(R.string.proto_group_other)
}

/**
 * Everything a server can be created as. WireGuard and AmneziaWG are one
 * protocol to the core (the INI decides) but two choices here, because they
 * are two different things to the person holding the config.
 */
internal enum class NewServerKind(
    val protocol: OutboundProtocol,
    val title: String,
    val badge: String,
    val descriptionRes: Int,
    val group: ProtocolGroup
) {
    VLESS(OutboundProtocol.VLESS, "VLESS", "VL", R.string.proto_desc_vless, ProtocolGroup.XRAY),
    VMESS(OutboundProtocol.VMESS, "VMess", "VM", R.string.proto_desc_vmess, ProtocolGroup.XRAY),
    TROJAN(OutboundProtocol.TROJAN, "Trojan", "TJ", R.string.proto_desc_trojan, ProtocolGroup.XRAY),
    SHADOWSOCKS(OutboundProtocol.SHADOWSOCKS, "Shadowsocks", "SS", R.string.proto_desc_ss, ProtocolGroup.XRAY),
    HYSTERIA2(OutboundProtocol.HYSTERIA2, "Hysteria2", "HY", R.string.proto_desc_hy2, ProtocolGroup.QUIC),
    TUIC(OutboundProtocol.TUIC, "TUIC v5", "TU", R.string.proto_desc_tuic, ProtocolGroup.QUIC),
    WIREGUARD(OutboundProtocol.WIREGUARD, "WireGuard", "WG", R.string.proto_desc_wg, ProtocolGroup.VPN),
    AMNEZIAWG(OutboundProtocol.WIREGUARD, "AmneziaWG", "AW", R.string.proto_desc_awg, ProtocolGroup.VPN),
    ANYTLS(OutboundProtocol.ANYTLS, "AnyTLS", "AT", R.string.proto_desc_anytls, ProtocolGroup.TLS),
    NAIVE_H2(OutboundProtocol.NAIVE_HTTP2, "NaiveProxy", "NV", R.string.proto_desc_naive_h2, ProtocolGroup.TLS),
    NAIVE_H11(OutboundProtocol.NAIVE_HTTP11, "HTTPS proxy", "H1", R.string.proto_desc_naive_h11, ProtocolGroup.TLS),
    SOCKS5(OutboundProtocol.SOCKS5, "SOCKS5", "S5", R.string.proto_desc_socks, ProtocolGroup.OTHER),
    SUDOKU(OutboundProtocol.SUDOKU, "Sudoku", "SU", R.string.proto_desc_sudoku, ProtocolGroup.OTHER),
    NOWHERE(OutboundProtocol.NOWHERE, "Nowhere", "NW", R.string.proto_desc_nowhere, ProtocolGroup.OTHER);

    val isWireGuard: Boolean get() = protocol == OutboundProtocol.WIREGUARD
}

/**
 * A new server, start to finish: pick what it is, then fill in the form made
 * for it. Closing a form goes back to the choice rather than out of the sheet,
 * so picking the wrong protocol costs one tap.
 */
@Composable
fun NewServerFlow(
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    var kindName by rememberSaveable { mutableStateOf<String?>(null) }
    val kind = kindName?.let { runCatching { NewServerKind.valueOf(it) }.getOrNull() }
    when {
        kind == null -> ProtocolPickerScreen(onPick = { kindName = it.name }, onDismiss = onDismiss)
        kind.isWireGuard -> WireGuardEditorScreen(
            configuration = null,
            amnezia = kind == NewServerKind.AMNEZIAWG,
            onSave = onSave,
            onDismiss = { kindName = null }
        )
        else -> ProxyEditorScreen(
            configuration = null,
            initialProtocol = kind.protocol,
            onSave = onSave,
            onDismiss = { kindName = null }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ProtocolPickerScreen(
    onPick: (NewServerKind) -> Unit,
    onDismiss: () -> Unit
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant
                ),
                title = { Text(stringResource(R.string.proto_pick_title)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
                    }
                }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier.padding(innerPadding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(ProtocolGroup.entries.toList(), key = { it.name }) { group ->
                val kinds = NewServerKind.entries.filter { it.group == group }
                Column {
                    WingSectionTitle(title = stringResource(group.titleRes))
                    WingPanel {
                        kinds.forEachIndexed { index, kind ->
                            ProtocolRow(kind = kind, onClick = { onPick(kind) })
                            if (index < kinds.lastIndex) {
                                HorizontalDivider(
                                    modifier = Modifier.padding(start = 68.dp),
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProtocolRow(kind: NewServerKind, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        WingIconTile(size = 38.dp) {
            Text(
                text = kind.badge,
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold
            )
        }
        Spacer(modifier = Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = kind.title,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = stringResource(kind.descriptionRes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
