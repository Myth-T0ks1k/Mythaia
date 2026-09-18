package com.mythaia.ui.proxy

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.model.HttpUpgradeConfiguration
import com.mythaia.data.model.NaiveProtocol
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.vpn.util.base64UrlToByteArrayOrNull
import com.mythaia.vpn.util.hexToByteArrayOrNull
import com.mythaia.vpn.util.toBase64Url
import com.mythaia.vpn.util.toHex
import java.util.UUID

// Wing form language: compact 14dp field corners inside 20dp paper cards.
private val FieldShape = RoundedCornerShape(14.dp)
private val CardShape = RoundedCornerShape(20.dp)

/** Protocols the field-by-field form renders completely. */
private val EDITABLE_PROTOCOLS = setOf(
    OutboundProtocol.VLESS,
    OutboundProtocol.TROJAN,
    OutboundProtocol.SHADOWSOCKS,
    OutboundProtocol.SOCKS5,
    OutboundProtocol.NAIVE_HTTP11,
    OutboundProtocol.NAIVE_HTTP2
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProxyEditorScreen(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit
) {
    // Every field starts from the configuration being edited, so the sheet
    // opens on the right values instead of flashing defaults for a frame.
    val c = configuration
    var selectedProtocol by remember { mutableStateOf(c?.outboundProtocol ?: OutboundProtocol.VLESS) }
    var name by remember { mutableStateOf(c?.name ?: "") }
    var serverAddress by remember { mutableStateOf(c?.serverAddress ?: "") }
    var serverPort by remember { mutableStateOf(c?.serverPort?.toString() ?: "") }
    var uuid by remember { mutableStateOf(c?.uuid?.toString() ?: "") }
    var encryption by remember { mutableStateOf(c?.encryption ?: "none") }
    var transport by remember { mutableStateOf(c?.transport ?: "tcp") }
    var flow by remember { mutableStateOf(c?.flow ?: "") }
    var security by remember { mutableStateOf(c?.security ?: "none") }

    var wsHost by remember { mutableStateOf(c?.websocket?.host ?: "") }
    var wsPath by remember { mutableStateOf(c?.websocket?.path ?: "/") }

    var httpUpgradeHost by remember { mutableStateOf(c?.httpUpgrade?.host ?: "") }
    var httpUpgradePath by remember { mutableStateOf(c?.httpUpgrade?.path ?: "/") }

    var xhttpHost by remember { mutableStateOf(c?.xhttp?.host ?: "") }
    var xhttpPath by remember { mutableStateOf(c?.xhttp?.path ?: "/") }
    var xhttpMode by remember { mutableStateOf(c?.xhttp?.mode?.raw ?: "auto") }
    var xhttpExtra by remember { mutableStateOf(c?.xhttp?.toExtraJson() ?: "") }
    var grpcServiceName by remember { mutableStateOf(c?.grpc?.serviceName ?: "") }
    var grpcAuthority by remember { mutableStateOf(c?.grpc?.authority ?: "") }
    var grpcMultiMode by remember { mutableStateOf(c?.grpc?.multiMode ?: false) }
    var grpcUserAgent by remember { mutableStateOf(c?.grpc?.userAgent ?: "") }

    // Trojan keeps its TLS under trojanTls; the shared fields read whichever is set.
    val existingTls = c?.trojanTls ?: c?.tls
    var tlsSNI by remember { mutableStateOf(existingTls?.serverName ?: "") }
    var tlsALPN by remember { mutableStateOf(existingTls?.alpn?.joinToString(",") ?: "") }
    var tlsAllowInsecure by remember { mutableStateOf(existingTls?.allowInsecure ?: false) }
    var tlsMinVersion by remember { mutableStateOf<TlsVersion?>(existingTls?.minVersion) }
    var tlsMaxVersion by remember { mutableStateOf<TlsVersion?>(existingTls?.maxVersion) }

    var muxEnabled by remember { mutableStateOf(c?.muxEnabled ?: true) }
    var xudpEnabled by remember { mutableStateOf(c?.xudpEnabled ?: true) }

    var sni by remember { mutableStateOf(c?.reality?.serverName ?: "") }
    var publicKey by remember { mutableStateOf(c?.reality?.publicKey?.toBase64Url() ?: "") }
    var shortId by remember { mutableStateOf(c?.reality?.shortId?.toHex() ?: "") }
    var fingerprint by remember {
        mutableStateOf(c?.reality?.fingerprint ?: existingTls?.fingerprint ?: TlsFingerprint.CHROME_133)
    }

    var ssPassword by remember { mutableStateOf(c?.ssPassword ?: "") }
    var ssMethod by remember { mutableStateOf(c?.ssMethod ?: "aes-128-gcm") }

    var naiveUsername by remember { mutableStateOf(c?.naiveUsername ?: "") }
    var naivePassword by remember { mutableStateOf(c?.naivePassword ?: "") }

    var socks5Username by remember { mutableStateOf(c?.socks5Username ?: "") }
    var socks5Password by remember { mutableStateOf(c?.socks5Password ?: "") }

    var trojanPassword by remember { mutableStateOf(c?.trojanPassword ?: "") }

    val isShadowsocks = selectedProtocol == OutboundProtocol.SHADOWSOCKS
    val isSocks5 = selectedProtocol == OutboundProtocol.SOCKS5
    val isNaive = selectedProtocol.isNaive
    val isTrojan = selectedProtocol == OutboundProtocol.TROJAN
    val isVless = selectedProtocol == OutboundProtocol.VLESS
    val isReality = security == "reality"
    val isTLS = security == "tls"

    // The field-by-field form covers these; anything else (Hysteria2, VMess,
    // AnyTLS, TUIC, WireGuard...) came from a link and only its name and
    // address can be edited here, so no field it does not render is lost.
    val fullEditor = selectedProtocol in EDITABLE_PROTOCOLS

    val portValue = serverPort.trim().toIntOrNull()
    val portValid = portValue != null && portValue in 1..65535
    val publicKeyBytes = publicKey.trim().base64UrlToByteArrayOrNull()
    val publicKeyValid = publicKeyBytes != null && publicKeyBytes.size == 32
    val shortIdBytes = shortId.trim().hexToByteArrayOrNull()
    val shortIdValid = shortIdBytes != null && shortIdBytes.size <= 8
    val xhttpExtraValid = xhttpExtra.isBlank() ||
        runCatching { org.json.JSONObject(xhttpExtra) }.isSuccess

    val isValid = name.isNotBlank() &&
            serverAddress.isNotBlank() &&
            portValid &&
            (!fullEditor || when {
                isNaive -> naiveUsername.isNotEmpty() && naivePassword.isNotEmpty()
                isShadowsocks -> ssPassword.isNotEmpty()
                isSocks5 -> true
                isTrojan -> trojanPassword.isNotEmpty()
                else -> runCatching { UUID.fromString(uuid.trim()) }.isSuccess &&
                        (!isReality || (sni.isNotBlank() && publicKeyValid && shortIdValid)) &&
                        (transport != "xhttp" || xhttpExtraValid)
            })

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                    actionIconContentColor = MaterialTheme.colorScheme.primary
                ),
                title = {
                    Text(
                        if (configuration != null) stringResource(R.string.edit_configuration)
                        else stringResource(R.string.add_configuration)
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.cancel))
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val trimmedName = name.trim()
                        val typedAddress = serverAddress.trim()
                        val bareAddress = if (typedAddress.startsWith("[") && typedAddress.endsWith("]"))
                            typedAddress.drop(1).dropLast(1) else typedAddress
                        val port = (portValue ?: return@IconButton).toUShort()

                        // A protocol this form does not render: keep everything
                        // the link carried and change only what is shown.
                        if (!fullEditor) {
                            val base = configuration ?: return@IconButton
                            onSave(base.copy(name = trimmedName, serverAddress = bareAddress, serverPort = port))
                            return@IconButton
                        }

                        val needsUuid =
                            !(isShadowsocks || isNaive || isSocks5 || isTrojan)
                        val parsedUUID = if (!needsUuid) {
                            configuration?.uuid ?: UUID.randomUUID()
                        } else {
                            runCatching { UUID.fromString(uuid.trim()) }.getOrNull() ?: return@IconButton
                        }

                        val alpnList = tlsALPN.split(",").map { it.trim() }
                            .filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }

                        // Sub-configurations start from what is stored, so a
                        // setting the form does not show (ECH, fragment, early
                        // data, headers) survives a save.
                        var tlsConfiguration: TlsConfiguration? = null
                        if (isTLS && isVless) {
                            tlsConfiguration = (configuration?.tls ?: TlsConfiguration(serverName = bareAddress)).copy(
                                serverName = tlsSNI.trim().ifEmpty { bareAddress },
                                alpn = alpnList,
                                allowInsecure = tlsAllowInsecure,
                                fingerprint = fingerprint,
                                minVersion = tlsMinVersion,
                                maxVersion = tlsMaxVersion
                            )
                        }

                        // Trojan: TLS is mandatory. Build from the shared
                        // tlsSNI/tlsALPN/fingerprint state.
                        var trojanTlsConfiguration: TlsConfiguration? = null
                        if (isTrojan) {
                            trojanTlsConfiguration = (configuration?.trojanTls ?: TlsConfiguration(serverName = bareAddress)).copy(
                                serverName = tlsSNI.trim().ifEmpty { bareAddress },
                                alpn = alpnList,
                                fingerprint = fingerprint
                            )
                            tlsConfiguration = trojanTlsConfiguration
                        }

                        var realityConfiguration: RealityConfiguration? = null
                        if (isReality && isVless) {
                            val pk = publicKeyBytes ?: return@IconButton
                            val sid = shortIdBytes ?: return@IconButton
                            realityConfiguration = RealityConfiguration(
                                serverName = sni.trim(),
                                publicKey = pk,
                                shortId = sid,
                                fingerprint = fingerprint
                            )
                        }

                        var wsConfiguration: WebSocketConfiguration? = null
                        if (transport == "ws" && isVless) {
                            val host = wsHost.trim().ifEmpty { bareAddress }
                            wsConfiguration = (configuration?.websocket ?: WebSocketConfiguration(host = host))
                                .copy(host = host, path = wsPath.trim().ifEmpty { "/" })
                        }

                        var httpUpgradeConfiguration: HttpUpgradeConfiguration? = null
                        if (transport == "httpupgrade" && isVless) {
                            val host = httpUpgradeHost.trim().ifEmpty { bareAddress }
                            httpUpgradeConfiguration = (configuration?.httpUpgrade ?: HttpUpgradeConfiguration(host = host))
                                .copy(host = host, path = httpUpgradePath.trim().ifEmpty { "/" })
                        }

                        var xhttpConfiguration: XHttpConfiguration? = null
                        if (transport == "xhttp" && isVless) {
                            val host = xhttpHost.trim().ifEmpty { bareAddress }
                            val mode = XHttpMode.fromRaw(xhttpMode)
                            xhttpConfiguration = XHttpConfiguration.fromExtraJson(
                                host = host, path = xhttpPath.trim().ifEmpty { "/" }, mode = mode, extraJson = xhttpExtra
                            )
                        }

                        var grpcConfiguration: com.mythaia.vpn.protocol.grpc.GrpcConfiguration? = null
                        if (transport == "grpc" && isVless) {
                            grpcConfiguration = com.mythaia.vpn.protocol.grpc.GrpcConfiguration(
                                serviceName = grpcServiceName,
                                authority = grpcAuthority,
                                multiMode = grpcMultiMode,
                                userAgent = grpcUserAgent
                            )
                        }

                        val naiveProto = when (selectedProtocol) {
                            OutboundProtocol.NAIVE_HTTP11 -> NaiveProtocol.HTTP11
                            OutboundProtocol.NAIVE_HTTP2 -> NaiveProtocol.HTTP2
                            else -> null
                        }

                        val nonVless = isShadowsocks || isNaive || isSocks5 || isTrojan

                        // Built from the loaded configuration where there is
                        // one, so a field this editor does not surface —
                        // password, the Hysteria2 bandwidth pair, the VMess
                        // cipher — survives a save instead of being dropped.
                        val config = (configuration ?: ProxyConfiguration(
                            name = name,
                            serverAddress = serverAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = encryption
                        )).copy(
                            id = configuration?.id ?: UUID.randomUUID(),
                            name = trimmedName,
                            serverAddress = bareAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = if (nonVless) "none" else encryption,
                            transport = if (nonVless) "tcp" else transport,
                            // Vision needs a TLS or Reality layer to ride on.
                            flow = if (nonVless || security == "none") null else flow.ifEmpty { null },
                            security = when {
                                isNaive || isShadowsocks || isSocks5 -> "none"
                                isTrojan -> "tls"
                                else -> security
                            },
                            tls = tlsConfiguration,
                            reality = realityConfiguration,
                            websocket = wsConfiguration,
                            httpUpgrade = httpUpgradeConfiguration,
                            xhttp = xhttpConfiguration,
                            grpc = grpcConfiguration,
                            muxEnabled = if (nonVless) false else muxEnabled,
                            xudpEnabled = if (nonVless) false else xudpEnabled,
                            subscriptionId = configuration?.subscriptionId,
                            outboundProtocol = selectedProtocol,
                            ssPassword = if (isShadowsocks) ssPassword else null,
                            ssMethod = if (isShadowsocks) ssMethod else null,
                            socks5Username = if (isSocks5) socks5Username.ifEmpty { null } else null,
                            socks5Password = if (isSocks5) socks5Password.ifEmpty { null } else null,
                            naiveUsername = if (isNaive) naiveUsername else null,
                            naivePassword = if (isNaive) naivePassword else null,
                            naiveProtocol = naiveProto,
                            trojanPassword = if (isTrojan) trojanPassword else null,
                            trojanTls = if (isTrojan) trojanTlsConfiguration else null,
                            // Preserve the original testseed rather than resetting to default.
                            testseed = configuration?.testseed ?: listOf(900u, 500u, 900u, 256u)
                        )
                        onSave(config)
                    }, enabled = isValid) {
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
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.name)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = FieldShape,
                    colors = wingTextFieldColors()
                )
            }

            if (!fullEditor) {
                Text(
                    text = stringResource(R.string.edit_limited_protocol, selectedProtocol.displayName),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 4.dp)
                )
            }

            if (fullEditor) SectionCard(title = stringResource(R.string.protocol_label)) {
                DropdownField(
                    label = stringResource(R.string.protocol_label),
                    selectedValue = selectedProtocol.name,
                    options = listOf(
                        OutboundProtocol.VLESS.name to "VLESS",
                        OutboundProtocol.TROJAN.name to "Trojan",
                        OutboundProtocol.SHADOWSOCKS.name to "Shadowsocks",
                        OutboundProtocol.SOCKS5.name to "SOCKS5",
                        OutboundProtocol.NAIVE_HTTP11.name to "HTTPS",
                        OutboundProtocol.NAIVE_HTTP2.name to "HTTP2"
                    ),
                    onSelect = { value ->
                        val nextProtocol = OutboundProtocol.valueOf(value)
                        selectedProtocol = nextProtocol
                        if (nextProtocol != OutboundProtocol.VLESS) {
                            flow = ""
                            transport = "tcp"
                            security = if (nextProtocol == OutboundProtocol.TROJAN) "tls" else "none"
                        }
                    }
                )
            }

            SectionCard(title = stringResource(R.string.server)) {
                OutlinedTextField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = { Text(stringResource(R.string.address)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    shape = FieldShape,
                    colors = wingTextFieldColors()
                )
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it },
                    label = { Text(stringResource(R.string.port)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = serverPort.isNotEmpty() && !portValid,
                    supportingText = if (serverPort.isNotEmpty() && !portValid) {
                        { Text(stringResource(R.string.invalid_port)) }
                    } else null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    shape = FieldShape,
                    colors = wingTextFieldColors()
                )

                if (!fullEditor) {
                    // Nothing else is editable for this protocol.
                } else if (isNaive) {
                    OutlinedTextField(
                        value = naiveUsername,
                        onValueChange = { naiveUsername = it },
                        label = { Text(stringResource(R.string.username)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                    OutlinedTextField(
                        value = naivePassword,
                        onValueChange = { naivePassword = it },
                        label = { Text(stringResource(R.string.password)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                } else if (isSocks5) {
                    OutlinedTextField(
                        value = socks5Username,
                        onValueChange = { socks5Username = it },
                        label = { Text(stringResource(R.string.username)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                    OutlinedTextField(
                        value = socks5Password,
                        onValueChange = { socks5Password = it },
                        label = { Text(stringResource(R.string.password)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                } else if (isShadowsocks) {
                    OutlinedTextField(
                        value = ssPassword,
                        onValueChange = { ssPassword = it },
                        label = { Text(stringResource(R.string.password)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                    DropdownField(
                        label = stringResource(R.string.method),
                        selectedValue = ssMethod,
                        options = listOf(
                            "none" to stringResource(R.string.none),
                            "aes-128-gcm" to "AES-128-GCM",
                            "aes-256-gcm" to "AES-256-GCM",
                            "chacha20-ietf-poly1305" to "ChaCha20-Poly1305",
                            "2022-blake3-aes-128-gcm" to "BLAKE3-AES-128-GCM",
                            "2022-blake3-aes-256-gcm" to "BLAKE3-AES-256-GCM",
                            "2022-blake3-chacha20-poly1305" to "BLAKE3-ChaCha20-Poly1305"
                        ),
                        onSelect = { ssMethod = it }
                    )
                } else if (isTrojan) {
                    // Trojan exposes only a password here; TLS SNI/ALPN/fingerprint
                    // live in the shared TLS section below.
                    OutlinedTextField(
                        value = trojanPassword,
                        onValueChange = { trojanPassword = it },
                        label = { Text(stringResource(R.string.password)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                } else {
                    OutlinedTextField(
                        value = uuid,
                        onValueChange = { uuid = it },
                        label = { Text(stringResource(R.string.uuid)) },
                        isError = uuid.isNotEmpty() && runCatching { UUID.fromString(uuid.trim()) }.isFailure,
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = FieldShape,
                        colors = wingTextFieldColors()
                    )
                    DropdownField(
                        label = stringResource(R.string.encryption),
                        selectedValue = encryption,
                        options = listOf("none" to stringResource(R.string.none)),
                        onSelect = { encryption = it }
                    )
                }
            }

            // Only VLESS exposes a user-selectable transport. Trojan mandates
            // TCP+TLS; Naive/SOCKS5/Shadowsocks have no transport knob.
            if (isVless) {
                SectionCard(title = stringResource(R.string.transport)) {
                    DropdownField(
                        label = stringResource(R.string.transport),
                        selectedValue = transport,
                        options = listOf(
                            "tcp" to "TCP",
                            "ws" to "WebSocket",
                            "httpupgrade" to "HTTPUpgrade",
                            "xhttp" to "XHTTP",
                            "grpc" to "gRPC"
                        ),
                        onSelect = {
                            transport = it
                            if (flow.isNotEmpty() && it != "tcp") flow = ""
                        }
                    )

                    if (transport == "ws") {
                        OutlinedTextField(
                            value = wsHost,
                            onValueChange = { wsHost = it },
                            label = { Text(stringResource(R.string.host)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = wsPath,
                            onValueChange = { wsPath = it },
                            label = { Text(stringResource(R.string.path)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                    }

                    if (transport == "httpupgrade") {
                        OutlinedTextField(
                            value = httpUpgradeHost,
                            onValueChange = { httpUpgradeHost = it },
                            label = { Text(stringResource(R.string.host)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = httpUpgradePath,
                            onValueChange = { httpUpgradePath = it },
                            label = { Text(stringResource(R.string.path)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                    }

                    if (transport == "xhttp") {
                        OutlinedTextField(
                            value = xhttpHost,
                            onValueChange = { xhttpHost = it },
                            label = { Text(stringResource(R.string.host)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = xhttpPath,
                            onValueChange = { xhttpPath = it },
                            label = { Text(stringResource(R.string.path)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        DropdownField(
                            label = stringResource(R.string.mode),
                            selectedValue = xhttpMode,
                            options = listOf(
                                "auto" to stringResource(R.string.auto),
                                "packet-up" to "Packet Up",
                                "stream-up" to "Stream Up",
                                "stream-one" to "Stream One"
                            ),
                            onSelect = { xhttpMode = it }
                        )
                        OutlinedTextField(
                            value = xhttpExtra,
                            onValueChange = { xhttpExtra = it },
                            label = { Text(stringResource(R.string.extra_json)) },
                            isError = !xhttpExtraValid,
                            supportingText = if (!xhttpExtraValid) {
                                { Text(stringResource(R.string.invalid_json)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 2,
                            maxLines = 6,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                    }

                    if (transport == "grpc") {
                        OutlinedTextField(
                            value = grpcServiceName,
                            onValueChange = { grpcServiceName = it },
                            label = { Text(stringResource(R.string.grpc_service_name)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = grpcAuthority,
                            onValueChange = { grpcAuthority = it },
                            label = { Text(stringResource(R.string.grpc_authority)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        DropdownField(
                            label = stringResource(R.string.mode),
                            selectedValue = if (grpcMultiMode) "multi" else "gun",
                            options = listOf(
                                "gun" to "Gun",
                                "multi" to "Multi"
                            ),
                            onSelect = { grpcMultiMode = (it == "multi") }
                        )
                        OutlinedTextField(
                            value = grpcUserAgent,
                            onValueChange = { grpcUserAgent = it },
                            label = { Text(stringResource(R.string.user_agent)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                    }

                    if (!isShadowsocks && transport == "tcp" && (isTLS || isReality)) {
                        DropdownField(
                            label = stringResource(R.string.flow),
                            selectedValue = flow,
                            options = listOf(
                                "" to stringResource(R.string.none),
                                "xtls-rprx-vision" to "Vision",
                                "xtls-rprx-vision-udp443" to "Vision with UDP 443"
                            ),
                            onSelect = { flow = it }
                        )
                        SwitchRow(
                            label = "Mux",
                            checked = muxEnabled,
                            onCheckedChange = {
                                muxEnabled = it
                                if (!it) xudpEnabled = false
                            }
                        )
                        if (muxEnabled) {
                            SwitchRow(
                                label = "XUDP",
                                checked = xudpEnabled,
                                onCheckedChange = { xudpEnabled = it }
                            )
                        }
                    }
                }
            }

            if (isVless || isTrojan) {
                SectionCard(title = stringResource(R.string.tls)) {
                    // For Trojan the TLS layer is mandatory: don't show the
                    // none/TLS/Reality picker, just render the TLS fields directly.
                    if (!isTrojan) {
                        DropdownField(
                            label = stringResource(R.string.security),
                            selectedValue = security,
                            options = listOf(
                                "none" to stringResource(R.string.none),
                                "tls" to "TLS",
                                "reality" to "Reality"
                            ),
                            onSelect = { security = it }
                        )
                    }

                    if (isTLS || isTrojan) {
                        OutlinedTextField(
                            value = tlsSNI,
                            onValueChange = { tlsSNI = it },
                            label = { Text(stringResource(R.string.sni)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = tlsALPN,
                            onValueChange = { tlsALPN = it },
                            label = { Text(stringResource(R.string.alpn)) },
                            placeholder = { Text("h2,http/1.1") },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        if (!isTrojan) {
                            SwitchRow(
                                label = stringResource(R.string.allow_insecure),
                                checked = tlsAllowInsecure,
                                onCheckedChange = { tlsAllowInsecure = it }
                            )
                        }
                        FingerprintDropdown(
                            selected = fingerprint,
                            onSelect = { fingerprint = it }
                        )
                        if (!isTrojan) {
                            DropdownField(
                                label = stringResource(R.string.min_tls_version),
                                selectedValue = tlsMinVersion?.name ?: "ANY",
                                options = listOf(
                                    "ANY" to stringResource(R.string.any_version),
                                    TlsVersion.TLS12.name to "TLS 1.2",
                                    TlsVersion.TLS13.name to "TLS 1.3"
                                ),
                                onSelect = { value ->
                                    tlsMinVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                                }
                            )
                            DropdownField(
                                label = stringResource(R.string.max_tls_version),
                                selectedValue = tlsMaxVersion?.name ?: "ANY",
                                options = listOf(
                                    "ANY" to stringResource(R.string.any_version),
                                    TlsVersion.TLS12.name to "TLS 1.2",
                                    TlsVersion.TLS13.name to "TLS 1.3"
                                ),
                                onSelect = { value ->
                                    tlsMaxVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                                }
                            )
                        }
                    }

                    if (isReality) {
                        OutlinedTextField(
                            value = sni,
                            onValueChange = { sni = it },
                            label = { Text(stringResource(R.string.sni)) },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = publicKey,
                            onValueChange = { publicKey = it },
                            label = { Text(stringResource(R.string.public_key)) },
                            isError = publicKey.isNotEmpty() && !publicKeyValid,
                            supportingText = if (publicKey.isNotEmpty() && !publicKeyValid) {
                                { Text(stringResource(R.string.invalid_public_key)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = shortId,
                            onValueChange = { shortId = it },
                            label = { Text(stringResource(R.string.short_id)) },
                            isError = !shortIdValid,
                            supportingText = if (!shortIdValid) {
                                { Text(stringResource(R.string.invalid_short_id)) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        FingerprintDropdown(
                            selected = fingerprint,
                            onSelect = { fingerprint = it }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

/**
 * Wing grouped-form section: a slate small-caps header above a paper card
 * (radius 20, 1dp outline border, no shadow) holding the section's fields.
 */
@Composable
private fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = title.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            letterSpacing = 1.2.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)
        )
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = CardShape,
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                content = content
            )
        }
    }
}

@Composable
private fun SwitchRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DropdownField(
    label: String,
    selectedValue: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val displayText = options.find { it.first == selectedValue }?.second ?: selectedValue

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = displayText,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
            shape = FieldShape,
            colors = wingTextFieldColors()
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            options.forEach { (value, display) ->
                DropdownMenuItem(
                    text = { Text(display) },
                    onClick = {
                        onSelect(value)
                        expanded = false
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FingerprintDropdown(
    selected: TlsFingerprint,
    onSelect: (TlsFingerprint) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it }
    ) {
        OutlinedTextField(
            value = selected.displayName,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.fingerprint)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
            shape = FieldShape,
            colors = wingTextFieldColors()
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            TlsFingerprint.pickerFingerprints.forEach { fp ->
                DropdownMenuItem(
                    text = { Text(fp.displayName) },
                    onClick = {
                        onSelect(fp)
                        expanded = false
                    }
                )
            }
        }
    }
}
