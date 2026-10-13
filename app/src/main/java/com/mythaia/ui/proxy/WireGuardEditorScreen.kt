package com.mythaia.ui.proxy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.WireGuardForm
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig

/** The INI is the form's own storage shape, so it is also how the form survives a rotation. */
private val WireGuardFormSaver = Saver<WireGuardForm, String>(
    save = { it.toIni() },
    restore = { WireGuardForm.fromIni(it) }
)

/**
 * The editor for a WireGuard or AmneziaWG profile: a form with a field for
 * every key people actually set, and the raw `wg-quick` text one tap away.
 *
 * The INI stays the stored form — [WireGuardForm] reads it into fields and
 * writes it back keeping every line it has no field for — so a key a future
 * build understands, or a second peer, survives an edit made in the form.
 * Either view is validated by the same parser on save.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WireGuardEditorScreen(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit,
    /** For a new profile: open with the AmneziaWG section shown and filled with typical values. */
    amnezia: Boolean = false
) {
    // Saveable, so a rotation or a theme switch mid-edit keeps what was typed.
    var name by rememberSaveable { mutableStateOf(configuration?.name.orEmpty()) }
    var form by rememberSaveable(stateSaver = WireGuardFormSaver) {
        mutableStateOf(
            configuration?.wireGuardConfig?.let(WireGuardForm::fromIni)
                ?: WireGuardForm.blank().let {
                    if (amnezia) it.copy(jc = "4", jmin = "40", jmax = "70", s1 = "0", s2 = "0", h1 = "1", h2 = "2", h3 = "3", h4 = "4")
                    else it
                }
        )
    }
    var textMode by rememberSaveable { mutableStateOf(false) }
    var text by rememberSaveable { mutableStateOf("") }
    var showAmnezia by rememberSaveable { mutableStateOf(amnezia || form.isAmnezia) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    fun currentIni(): String = if (textMode) text else form.toIni()

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background),
                title = {
                    Text(
                        if (showAmnezia) stringResource(R.string.amneziawg_configuration)
                        else stringResource(R.string.wireguard_configuration)
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val ini = currentIni()
                        val parsed = runCatching { WireGuardConfig.parse(ini) }
                        val failure = parsed.exceptionOrNull()
                        if (failure != null) {
                            error = failure.message
                            return@IconButton
                        }
                        val peer = parsed.getOrThrow().peer
                        // Built from the loaded profile where there is one, so its
                        // id, subscription and rule-set assignment survive an edit.
                        val base = configuration ?: ProxyConfiguration.fromWireGuardConfig(ini, name)
                        onSave(
                            base.copy(
                                name = name.trim().ifBlank { base.name },
                                serverAddress = peer.endpointHost,
                                serverPort = peer.endpointPort.toUShort(),
                                outboundProtocol = OutboundProtocol.WIREGUARD,
                                wireGuardConfig = ini
                            )
                        )
                    }) {
                        Icon(Icons.Default.Check, contentDescription = stringResource(R.string.save))
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            SectionCard(title = stringResource(R.string.name)) {
                WingField(name, { name = it }, stringResource(R.string.name))
                TextButton(onClick = {
                    if (textMode) {
                        form = WireGuardForm.fromIni(text)
                        showAmnezia = showAmnezia || form.isAmnezia
                    } else {
                        text = form.toIni()
                    }
                    textMode = !textMode
                    error = null
                }) {
                    Text(stringResource(if (textMode) R.string.wg_form_mode else R.string.wg_text_mode))
                }
            }

            if (textMode) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it; error = null },
                    label = { Text(stringResource(R.string.wireguard_configuration)) },
                    placeholder = { Text(stringResource(R.string.wireguard_configuration_hint)) },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 260.dp),
                    // A key is a long run of base64, much easier to check in a fixed pitch.
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, fontSize = 13.sp),
                    isError = error != null,
                    supportingText = error?.let { { Text(it, color = MaterialTheme.colorScheme.error) } },
                    shape = FieldShape,
                    colors = wingTextFieldColors()
                )
            } else {
                WireGuardFormSections(
                    form = form,
                    onForm = { form = it; error = null },
                    showAmnezia = showAmnezia,
                    onShowAmnezia = { on ->
                        showAmnezia = on
                        if (!on) form = form.copy(jc = "", jmin = "", jmax = "", s1 = "", s2 = "", h1 = "", h2 = "", h3 = "", h4 = "")
                    }
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                }
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun WireGuardFormSections(
    form: WireGuardForm,
    onForm: (WireGuardForm) -> Unit,
    showAmnezia: Boolean,
    onShowAmnezia: (Boolean) -> Unit
) {
    SectionCard(title = stringResource(R.string.wg_interface)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                WingField(form.privateKey, { onForm(form.copy(privateKey = it)) }, stringResource(R.string.wg_private_key), secret = true)
            }
            Spacer(Modifier.width(8.dp))
            FilledTonalButton(onClick = { onForm(form.copy(privateKey = WireGuardForm.generatePrivateKey())) }) {
                Text(stringResource(R.string.wg_generate))
            }
        }
        WireGuardForm.publicKeyOf(form.privateKey)?.let { pub ->
            Text(
                text = stringResource(R.string.wg_public_key_is, pub),
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        WingField(form.addresses, { onForm(form.copy(addresses = it)) }, stringResource(R.string.wg_addresses), placeholder = "10.0.0.2/32, fd00::2/128")
        WingField(form.dns, { onForm(form.copy(dns = it)) }, stringResource(R.string.wg_dns), placeholder = "1.1.1.1")
        WingField(form.mtu, { onForm(form.copy(mtu = it)) }, stringResource(R.string.wg_mtu), placeholder = "1280", keyboardType = KeyboardType.Number)
    }

    SectionCard(title = stringResource(R.string.wg_peer)) {
        WingField(form.endpoint, { onForm(form.copy(endpoint = it)) }, stringResource(R.string.wg_endpoint), placeholder = "vpn.example.com:51820", keyboardType = KeyboardType.Uri)
        WingField(form.publicKey, { onForm(form.copy(publicKey = it)) }, stringResource(R.string.wg_peer_public_key))
        WingField(form.presharedKey, { onForm(form.copy(presharedKey = it)) }, stringResource(R.string.wg_preshared_key), secret = true)
        WingField(form.allowedIps, { onForm(form.copy(allowedIps = it)) }, stringResource(R.string.wg_allowed_ips), placeholder = "0.0.0.0/0, ::/0")
        WingField(form.keepalive, { onForm(form.copy(keepalive = it)) }, stringResource(R.string.wg_keepalive), placeholder = "25", keyboardType = KeyboardType.Number)
        WingField(form.reserved, { onForm(form.copy(reserved = it)) }, stringResource(R.string.wg_reserved), placeholder = "0,0,0")
        Text(stringResource(R.string.wg_reserved_hint), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    SectionCard(title = stringResource(R.string.wg_amnezia)) {
        SwitchRow(stringResource(R.string.wg_amnezia), showAmnezia, onShowAmnezia)
        if (showAmnezia) {
            NumberPair("Jc", form.jc, { onForm(form.copy(jc = it)) }, "Jmin", form.jmin, { onForm(form.copy(jmin = it)) })
            NumberPair("Jmax", form.jmax, { onForm(form.copy(jmax = it)) }, "S1", form.s1, { onForm(form.copy(s1 = it)) })
            NumberPair("S2", form.s2, { onForm(form.copy(s2 = it)) }, "H1", form.h1, { onForm(form.copy(h1 = it)) })
            NumberPair("H2", form.h2, { onForm(form.copy(h2 = it)) }, "H3", form.h3, { onForm(form.copy(h3 = it)) })
            NumberPair("H4", form.h4, { onForm(form.copy(h4 = it)) }, null, "", {})
        }
    }
}

/** Two short numeric fields side by side — the AmneziaWG knobs come in pairs on a phone screen. */
@Composable
private fun NumberPair(
    firstLabel: String, first: String, onFirst: (String) -> Unit,
    secondLabel: String?, second: String, onSecond: (String) -> Unit
) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(
            value = first, onValueChange = onFirst, label = { Text(firstLabel) },
            modifier = Modifier.weight(1f), singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            shape = FieldShape, colors = wingTextFieldColors()
        )
        if (secondLabel != null) {
            OutlinedTextField(
                value = second, onValueChange = onSecond, label = { Text(secondLabel) },
                modifier = Modifier.weight(1f), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                shape = FieldShape, colors = wingTextFieldColors()
            )
        } else {
            Spacer(Modifier.weight(1f))
        }
    }
}
