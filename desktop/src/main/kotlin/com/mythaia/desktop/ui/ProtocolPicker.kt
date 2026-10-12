package com.mythaia.desktop.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.tr

/** The groups the picker shows, as on Android. */
private enum class PickerGroup(val titleKey: String) {
    XRAY("proto_group_xray"), QUIC("proto_group_quic"), VPN("proto_group_vpn"),
    TLS("proto_group_tls"), OTHER("proto_group_other")
}

/**
 * Everything a server can be created as — the Android picker's list. The
 * WireGuard family is shown but not offered: the Windows tunnel does not
 * carry layer-3 protocols yet, and a server that cannot connect is worse
 * than an honest "not here yet".
 */
private enum class PickerKind(
    val protocol: OutboundProtocol,
    val title: String,
    val badge: String,
    val descriptionKey: String,
    val group: PickerGroup,
    val available: Boolean = true
) {
    VLESS(OutboundProtocol.VLESS, "VLESS", "VL", "proto_desc_vless", PickerGroup.XRAY),
    VMESS(OutboundProtocol.VMESS, "VMess", "VM", "proto_desc_vmess", PickerGroup.XRAY),
    TROJAN(OutboundProtocol.TROJAN, "Trojan", "TJ", "proto_desc_trojan", PickerGroup.XRAY),
    SHADOWSOCKS(OutboundProtocol.SHADOWSOCKS, "Shadowsocks", "SS", "proto_desc_ss", PickerGroup.XRAY),
    HYSTERIA2(OutboundProtocol.HYSTERIA2, "Hysteria2", "HY", "proto_desc_hy2", PickerGroup.QUIC),
    TUIC(OutboundProtocol.TUIC, "TUIC v5", "TU", "proto_desc_tuic", PickerGroup.QUIC),
    WIREGUARD(OutboundProtocol.WIREGUARD, "WireGuard", "WG", "proto_desc_wg", PickerGroup.VPN, available = false),
    AMNEZIAWG(OutboundProtocol.WIREGUARD, "AmneziaWG", "AW", "proto_desc_awg", PickerGroup.VPN, available = false),
    ANYTLS(OutboundProtocol.ANYTLS, "AnyTLS", "AT", "proto_desc_anytls", PickerGroup.TLS),
    NAIVE_H2(OutboundProtocol.NAIVE_HTTP2, "NaiveProxy", "NV", "proto_desc_naive_h2", PickerGroup.TLS),
    NAIVE_H11(OutboundProtocol.NAIVE_HTTP11, "HTTPS proxy", "H1", "proto_desc_naive_h11", PickerGroup.TLS),
    SOCKS5(OutboundProtocol.SOCKS5, "SOCKS5", "S5", "proto_desc_socks", PickerGroup.OTHER),
    SUDOKU(OutboundProtocol.SUDOKU, "Sudoku", "SU", "proto_desc_sudoku", PickerGroup.OTHER),
    NOWHERE(OutboundProtocol.NOWHERE, "Nowhere", "NW", "proto_desc_nowhere", PickerGroup.OTHER)
}

/**
 * A new server, start to finish, in the editor window: pick the protocol,
 * then the form for it. Closing the form goes back to the choice.
 */
@Composable
fun NewServerFlow(onSave: (ProxyConfiguration) -> Unit, onDismiss: () -> Unit) {
    var picked by remember { mutableStateOf<OutboundProtocol?>(null) }
    val protocol = picked
    if (protocol == null) {
        ProtocolPicker(onPick = { picked = it })
    } else {
        ServerEditor(
            configuration = null,
            onSave = onSave,
            onDismiss = { picked = null },
            initialProtocol = protocol
        )
    }
}

@Composable
private fun ProtocolPicker(onPick: (OutboundProtocol) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Text(
                tr("proto_pick_title"),
                style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.padding(start = 6.dp, bottom = 4.dp)
            )
        }
        items(PickerGroup.entries.toList(), key = { it.name }) { group ->
            val kinds = PickerKind.entries.filter { it.group == group }
            Column {
                WingSectionTitle(tr(group.titleKey))
                WingPanel {
                    kinds.forEachIndexed { index, kind ->
                        PickerRow(kind, onClick = { onPick(kind.protocol) })
                        if (index < kinds.lastIndex) {
                            HorizontalDivider(
                                modifier = Modifier.padding(start = 66.dp),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PickerRow(kind: PickerKind, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(if (kind.available) Modifier.clickable(onClick = onClick) else Modifier.alpha(0.5f))
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        WingIconTile(size = 36.dp) {
            Text(kind.badge, color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                kind.title,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                if (kind.available) tr(kind.descriptionKey) else tr("proto_android_only"),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (kind.available) {
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
