package com.mythaia.desktop.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.mythaia.data.model.DomainRuleType
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.AppState
import com.mythaia.desktop.Lang
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.model.RouteTarget
import com.mythaia.desktop.tr
import com.mythaia.vpn.util.GeoIpDatabase
import java.awt.Desktop
import java.awt.FileDialog
import java.awt.Frame
import java.io.File

@Composable
fun SettingsScreen(state: AppState) {
    val settings by state.settings.collectAsState()
    val rules by state.rules.collectAsState()

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp, vertical = 20.dp)
    ) {
        Column(modifier = Modifier.widthIn(max = 720.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {

            Section(tr("settings_connection")) {
                val needsElevation by state.needsElevation.collectAsState()
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    DropdownField(
                        tr("tunnel_mode"), settings.tunnelMode,
                        listOf("proxy" to tr("mode_proxy"), "tun" to tr("mode_tun")),
                        modifier = Modifier.weight(1f)
                    ) { v -> state.updateSettings { it.copy(tunnelMode = v) } }
                }
                Text(
                    if (settings.tunnelMode == "tun") tr("tun_hint") else tr("proxy_mode_hint"),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 18.dp)
                )
                if (needsElevation) {
                    androidx.compose.material3.AlertDialog(
                        onDismissRequest = { state.needsElevation.value = false },
                        text = { Text(tr("tun_needs_admin")) },
                        confirmButton = {
                            Button(onClick = {
                                state.needsElevation.value = false
                                if (state.relaunchElevated()) kotlin.system.exitProcess(0)
                            }) { Text(tr("tun_relaunch")) }
                        },
                        dismissButton = { TextButton(onClick = { state.needsElevation.value = false }) { Text(tr("cancel")) } }
                    )
                }
                var socks by remember(settings.socksPort) { mutableStateOf(settings.socksPort.toString()) }
                var http by remember(settings.httpPort) { mutableStateOf(settings.httpPort.toString()) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    WingField(socks, { socks = it }, tr("socks_port"), modifier = Modifier.weight(1f))
                    WingField(http, { http = it }, tr("http_port"), modifier = Modifier.weight(1f))
                    TextButton(
                        onClick = {
                            val s = socks.toIntOrNull(); val h = http.toIntOrNull()
                            if (s != null && h != null && s in 1..65535 && h in 1..65535) {
                                state.updateSettings { it.copy(socksPort = s, httpPort = h) }
                            }
                        },
                        modifier = Modifier.align(Alignment.CenterVertically)
                    ) { Text(tr("save")) }
                }
                SwitchRow(tr("allow_lan"), settings.allowLan) { v -> state.updateSettings { it.copy(allowLan = v) } }
                SwitchRow(tr("auto_connect"), settings.autoConnect) { v -> state.updateSettings { it.copy(autoConnect = v) } }
                var hours by remember(settings.subscriptionUpdateHours) { mutableStateOf(settings.subscriptionUpdateHours.toString()) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    WingField(hours, { hours = it }, tr("subscription_update_hours"), modifier = Modifier.weight(1f))
                    TextButton(onClick = {
                        hours.toIntOrNull()?.takeIf { it in 0..720 }?.let { h -> state.updateSettings { it.copy(subscriptionUpdateHours = h) } }
                    }) { Text(tr("save")) }
                }
            }

            Section(tr("settings_system")) {
                SwitchRow(tr("set_system_proxy"), settings.setSystemProxy) { v -> state.updateSettings { it.copy(setSystemProxy = v) } }
                var bypass by remember(settings.proxyBypass) { mutableStateOf(settings.proxyBypass) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    WingField(bypass, { bypass = it }, tr("proxy_bypass"), modifier = Modifier.weight(1f))
                    TextButton(onClick = { state.updateSettings { it.copy(proxyBypass = bypass) } }) { Text(tr("save")) }
                }
                SwitchRow(tr("launch_at_login"), settings.launchAtLogin) { v -> state.updateSettings { it.copy(launchAtLogin = v) } }
                SwitchRow(tr("start_minimized"), settings.startMinimized) { v -> state.updateSettings { it.copy(startMinimized = v) } }
                SwitchRow(tr("close_to_tray"), settings.closeToTray) { v -> state.updateSettings { it.copy(closeToTray = v) } }
            }

            Section(tr("settings_routing")) {
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(tr("route_mode"), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    ModePill(settings.isGlobal) { g -> state.updateSettings { it.copy(routeMode = if (g) "global" else "rule") } }
                }
                SwitchRow(tr("bypass_tm"), settings.bypassTurkmenistan) { v -> state.updateSettings { it.copy(bypassTurkmenistan = v) } }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, modifier = Modifier.padding(horizontal = 18.dp))
                var geoLoaded by remember { mutableStateOf(GeoIpDatabase.isLoaded) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(tr("geoip_db"), style = MaterialTheme.typography.bodyLarge)
                        Text(if (geoLoaded) tr("geoip_loaded") else tr("geoip_missing"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = {
                        val dialog = FileDialog(null as Frame?, tr("geoip_import"), FileDialog.LOAD)
                        dialog.file = "*.mmdb"
                        dialog.isVisible = true
                        val file = dialog.file?.let { File(dialog.directory, it) }
                        if (file != null && file.isFile) {
                            state.importGeoIp(file) { geoLoaded = it }
                        }
                    }) { Text(tr("geoip_import")) }
                    if (geoLoaded) TextButton(onClick = { state.clearGeoIp(); geoLoaded = false }) { Text(tr("geoip_clear")) }
                }
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant, modifier = Modifier.padding(horizontal = 18.dp))
                RulesEditor(rules) { state.updateRules(it) }
            }

            Section(tr("settings_tls")) {
                SwitchRow(tr("fragment"), settings.fragmentEnabled) { v -> state.updateSettings { it.copy(fragmentEnabled = v) } }
                var minL by remember(settings.fragmentMinLength) { mutableStateOf(settings.fragmentMinLength.toString()) }
                var maxL by remember(settings.fragmentMaxLength) { mutableStateOf(settings.fragmentMaxLength.toString()) }
                var minI by remember(settings.fragmentMinInterval) { mutableStateOf(settings.fragmentMinInterval.toString()) }
                var maxI by remember(settings.fragmentMaxInterval) { mutableStateOf(settings.fragmentMaxInterval.toString()) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                    WingField(minL, { minL = it }, tr("fragment_length"), modifier = Modifier.weight(1f))
                    WingField(maxL, { maxL = it }, tr("max"), modifier = Modifier.weight(1f))
                    WingField(minI, { minI = it }, tr("fragment_interval"), modifier = Modifier.weight(1f))
                    WingField(maxI, { maxI = it }, tr("max"), modifier = Modifier.weight(1f))
                    TextButton(onClick = {
                        val a = minL.toIntOrNull(); val b = maxL.toIntOrNull(); val c = minI.toIntOrNull(); val d = maxI.toIntOrNull()
                        if (a != null && b != null && c != null && d != null && a >= 1 && b >= a && c >= 0 && d >= c) {
                            state.updateSettings { it.copy(fragmentMinLength = a, fragmentMaxLength = b, fragmentMinInterval = c, fragmentMaxInterval = d) }
                        }
                    }) { Text(tr("save")) }
                }
                SwitchRow(tr("allow_insecure"), settings.allowInsecure) { v -> state.updateSettings { it.copy(allowInsecure = v) } }
            }

            Section(tr("settings_dns")) {
                SwitchRow(tr("doh"), settings.dohEnabled) { v -> state.updateSettings { it.copy(dohEnabled = v) } }
                var url by remember(settings.dohUrl) { mutableStateOf(settings.dohUrl) }
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    WingField(url, { url = it }, tr("doh_url"), modifier = Modifier.weight(1f))
                    TextButton(onClick = { state.updateSettings { it.copy(dohUrl = url.trim()) } }) { Text(tr("save")) }
                }
            }

            Section(tr("settings_appearance")) {
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    DropdownField(
                        tr("language"), settings.language,
                        listOf("auto" to tr("theme_system")) + Lang.entries.map { it.code to it.title },
                        modifier = Modifier.weight(1f)
                    ) { v -> state.updateSettings { it.copy(language = v) } }
                    DropdownField(
                        tr("theme"), settings.theme,
                        listOf("system" to tr("theme_system"), "light" to tr("theme_light"), "dark" to tr("theme_dark")),
                        modifier = Modifier.weight(1f)
                    ) { v -> state.updateSettings { it.copy(theme = v) } }
                }
            }

            Section(tr("settings_about")) {
                Row(modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(tr("version", com.mythaia.desktop.APP_VERSION), style = MaterialTheme.typography.bodyLarge)
                        Text(AppPaths.dataDir.absolutePath, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { runCatching { Desktop.getDesktop().open(AppPaths.dataDir) } }) { Text(tr("open_folder")) }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Column {
        WingSectionTitle(title)
        WingPanel { Column(modifier = Modifier.padding(vertical = 6.dp)) { content() } }
    }
}

@Composable
private fun RulesEditor(rules: List<RouteRule>, onChange: (List<RouteRule>) -> Unit) {
    Column(modifier = Modifier.padding(horizontal = 18.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(tr("rules"), style = MaterialTheme.typography.bodyLarge)
        rules.forEachIndexed { index, rule ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "${typeName(rule.type)}  ·  ${rule.value}",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
                Text(actionName(rule.action), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                IconButton(onClick = { onChange(rules.filterIndexed { i, _ -> i != index }) }) {
                    Icon(Icons.Default.Delete, tr("delete"), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        var type by remember { mutableStateOf(DomainRuleType.DOMAIN_SUFFIX) }
        var value by remember { mutableStateOf("") }
        var action by remember { mutableStateOf(RouteTarget.DIRECT) }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
            DropdownField(
                tr("rule_type"), type.name,
                DomainRuleType.entries.map { it.name to typeName(it) },
                modifier = Modifier.weight(1.5f)
            ) { v -> type = DomainRuleType.valueOf(v) }
            WingField(value, { value = it }, tr("rule_value"), modifier = Modifier.weight(1.3f))
            DropdownField(
                tr("rule_action"), action.name,
                RouteTarget.entries.map { it.name to actionName(it) },
                modifier = Modifier.weight(1.2f)
            ) { v -> action = RouteTarget.valueOf(v) }
            Button(
                onClick = { onChange(rules + RouteRule(type, value.trim(), action)); value = "" },
                enabled = value.isNotBlank()
            ) { Text(tr("rule_add")) }
        }
        Spacer(Modifier.width(4.dp))
    }
}

private fun typeName(type: DomainRuleType): String = when (type) {
    DomainRuleType.DOMAIN_SUFFIX -> tr("type_suffix")
    DomainRuleType.DOMAIN_KEYWORD -> tr("type_keyword")
    DomainRuleType.IP_CIDR -> tr("type_cidr")
    DomainRuleType.IP_CIDR6 -> tr("type_cidr6")
    DomainRuleType.GEOIP -> tr("type_geoip")
}

private fun actionName(action: RouteTarget): String = when (action) {
    RouteTarget.PROXY -> tr("action_proxy")
    RouteTarget.DIRECT -> tr("action_direct")
    RouteTarget.BLOCK -> tr("action_block")
}
