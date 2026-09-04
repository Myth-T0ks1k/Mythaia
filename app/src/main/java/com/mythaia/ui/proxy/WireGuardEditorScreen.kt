package com.mythaia.ui.proxy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig

private val FieldShape = RoundedCornerShape(14.dp)

/**
 * The editor for a WireGuard or AmneziaWG profile.
 *
 * WireGuard is configured by a file, not by a set of fields: a peer hands out
 * a `wg-quick` INI and the whole of it matters, including the AmneziaWG keys
 * this build would otherwise have to enumerate one by one. So the config is
 * edited as text and validated on save, which also means a key added to the
 * format later survives without a change here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WireGuardEditorScreen(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    var name by remember { mutableStateOf(configuration?.name.orEmpty()) }
    var text by remember { mutableStateOf(configuration?.wireGuardConfig.orEmpty()) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.surface,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                title = { Text(stringResource(R.string.wireguard_configuration)) },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            val parsed = runCatching { WireGuardConfig.parse(text) }
                            val failure = parsed.exceptionOrNull()
                            if (failure != null) {
                                error = failure.message
                                return@IconButton
                            }
                            val peer = parsed.getOrThrow().peer

                            // Built from the loaded profile where there is one,
                            // so its id, subscription and rule-set assignment
                            // survive an edit.
                            val base = configuration
                                ?: ProxyConfiguration.fromWireGuardConfig(text, name)
                            onSave(
                                base.copy(
                                    name = name.ifBlank { base.name },
                                    serverAddress = peer.endpointHost,
                                    serverPort = peer.endpointPort.toUShort(),
                                    outboundProtocol = com.mythaia.data.model.OutboundProtocol.WIREGUARD,
                                    wireGuardConfig = text
                                )
                            )
                        },
                        enabled = text.isNotBlank()
                    ) {
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
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.name)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = FieldShape,
                colors = wingTextFieldColors()
            )

            OutlinedTextField(
                value = text,
                onValueChange = {
                    text = it
                    error = null
                },
                label = { Text(stringResource(R.string.wireguard_configuration)) },
                placeholder = { Text(stringResource(R.string.wireguard_configuration_hint)) },
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 260.dp),
                // The INI is column-sensitive to read, and a key is a long run
                // of base64 that is much easier to check in a fixed pitch.
                textStyle = MaterialTheme.typography.bodyMedium.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp
                ),
                isError = error != null,
                supportingText = error?.let { { Text(it, color = MaterialTheme.colorScheme.error) } },
                shape = FieldShape,
                colors = wingTextFieldColors()
            )
        }
    }
}
