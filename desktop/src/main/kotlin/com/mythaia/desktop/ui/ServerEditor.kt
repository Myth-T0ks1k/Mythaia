package com.mythaia.desktop.ui

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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.HttpUpgradeConfiguration
import com.mythaia.data.model.NaiveProtocol
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.vpn.protocol.grpc.GrpcConfiguration
import com.mythaia.vpn.protocol.sudoku.SudokuAeadMethod
import com.mythaia.vpn.protocol.sudoku.SudokuAsciiMode
import com.mythaia.vpn.protocol.sudoku.SudokuHttpMaskMode
import com.mythaia.vpn.protocol.sudoku.SudokuMultiplex
import com.mythaia.vpn.util.base64UrlToByteArrayOrNull
import com.mythaia.vpn.util.hexToByteArrayOrNull
import com.mythaia.vpn.util.toBase64Url
import com.mythaia.vpn.util.toHex
import java.util.UUID
import com.mythaia.desktop.tr

// Wing form language: 18dp fields inside soft 24dp panels.
private val EditorFieldShape = RoundedCornerShape(18.dp)
private val EditorCardShape = RoundedCornerShape(24.dp)

/** Every protocol the app dials, except WireGuard, which has a file editor of its own. */
private val EditorEDITABLE_PROTOCOLS = listOf(
    OutboundProtocol.VLESS,
    OutboundProtocol.VMESS,
    OutboundProtocol.TROJAN,
    OutboundProtocol.SHADOWSOCKS,
    OutboundProtocol.SOCKS5,
    OutboundProtocol.HYSTERIA2,
    OutboundProtocol.TUIC,
    OutboundProtocol.ANYTLS,
    OutboundProtocol.NOWHERE,
    OutboundProtocol.SUDOKU,
    OutboundProtocol.NAIVE_HTTP11,
    OutboundProtocol.NAIVE_HTTP2
)

/**
 * The field-by-field editor for a server.
 *
 * Every protocol the app speaks is here, each with the fields its links
 * carry. Sub-configurations are built with `copy()` from what is stored, so
 * a setting the form does not show (ECH, a FinalMask fragment, early data,
 * headers, Sudoku padding tables) survives a save instead of being dropped.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServerEditor(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit,
    /** For a new server: the protocol picked on the protocol picker. */
    initialProtocol: OutboundProtocol? = null
) {
    // Every field starts from the configuration being edited, so the sheet
    // opens on the right values instead of flashing defaults for a frame.
    val c = configuration
    var selectedProtocol by remember { mutableStateOf(c?.outboundProtocol ?: initialProtocol ?: OutboundProtocol.VLESS) }
    var name by remember { mutableStateOf(c?.name ?: "") }
    var serverAddress by remember { mutableStateOf(c?.serverAddress ?: "") }
    var serverPort by remember { mutableStateOf(c?.serverPort?.toString() ?: "") }
    var uuid by remember { mutableStateOf(c?.uuid?.toString() ?: "") }
    var encryption by remember { mutableStateOf(c?.encryption ?: "none") }
    var transport by remember { mutableStateOf(c?.transport ?: "tcp") }
    var flow by remember { mutableStateOf(c?.flow ?: "") }
    var security by remember {
        mutableStateOf(
            c?.security ?: when (initialProtocol) {
                OutboundProtocol.TROJAN, OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC,
                OutboundProtocol.ANYTLS, OutboundProtocol.NOWHERE -> "tls"
                // A new VLESS server is far more often Reality or TLS than bare.
                OutboundProtocol.VLESS -> "reality"
                else -> "none"
            }
        )
    }

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
    // Xray 26's replacements for allowInsecure, and ECH.
    var tlsPins by remember { mutableStateOf(existingTls?.pinnedCertSha256?.joinToString(", ") ?: "") }
    var tlsVerifyName by remember { mutableStateOf(existingTls?.verifyName ?: "") }
    var tlsEch by remember { mutableStateOf(existingTls?.echConfig ?: "") }

    // Per-server ClientHello fragmentation: follow the global setting, off, or its own.
    val existingFragment = existingTls?.fragment
    var fragmentMode by remember {
        mutableStateOf(
            when {
                existingFragment == null -> "default"
                !existingFragment.isEnabled -> "off"
                else -> "custom"
            }
        )
    }
    var fragmentLengths by remember {
        mutableStateOf(
            existingFragment?.takeIf { it.isEnabled }?.let { f ->
                f.lengthSteps.ifEmpty { listOf(rangeText(f.lengthRange)) }.joinToString(", ")
            } ?: "3"
        )
    }
    var fragmentDelays by remember {
        mutableStateOf(
            existingFragment?.takeIf { it.isEnabled }?.let { f ->
                f.delaySteps.ifEmpty { listOf(rangeText(f.intervalRange)) }.joinToString(", ")
            } ?: "1"
        )
    }
    var fragmentMaxSplit by remember {
        mutableStateOf(existingFragment?.takeIf { it.isEnabled }?.maxSplit?.toString() ?: "2")
    }

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

    // Hysteria2, AnyTLS, Nowhere and TUIC authenticate with one password (a
    // key, for Nowhere); TUIC pairs it with a UUID.
    var password by remember { mutableStateOf(c?.password ?: "") }
    var vmessSecurity by remember { mutableStateOf(c?.vmessSecurity ?: "auto") }
    var hyUp by remember { mutableStateOf(c?.hysteriaUpMbps?.toString() ?: "") }
    var hyDown by remember { mutableStateOf(c?.hysteriaDownMbps?.toString() ?: "") }
    var obfs by remember { mutableStateOf(c?.obfuscation ?: "none") }
    var obfsPassword by remember { mutableStateOf(c?.obfuscationPassword ?: "") }
    var nowhereUp by remember { mutableStateOf(c?.nowhereUplink ?: "udp") }
    var nowhereDown by remember { mutableStateOf(c?.nowhereDownlink ?: "udp") }
    var nowhereMux by remember { mutableStateOf(c?.nowhereMultiplex ?: false) }

    var sudokuKey by remember { mutableStateOf(c?.sudokuKey ?: "") }
    var sudokuAead by remember { mutableStateOf(c?.sudokuAeadMethod ?: SudokuAeadMethod.CHACHA20_POLY1305.id) }
    var sudokuAscii by remember { mutableStateOf(c?.sudokuAsciiMode ?: SudokuAsciiMode.PREFER_ENTROPY.id) }
    var sudokuPure by remember { mutableStateOf(c?.sudokuEnablePureDownlink ?: true) }
    var sudokuMux by remember { mutableStateOf(c?.sudokuMultiplex ?: SudokuMultiplex.OFF.id) }
    var sudokuMaskDisable by remember { mutableStateOf(c?.sudokuHttpMaskDisable ?: false) }
    var sudokuMaskMode by remember { mutableStateOf(c?.sudokuHttpMaskMode ?: SudokuHttpMaskMode.LEGACY.id) }
    var sudokuMaskTls by remember { mutableStateOf(c?.sudokuHttpMaskTls ?: false) }
    var sudokuMaskHost by remember { mutableStateOf(c?.sudokuHttpMaskHost ?: "") }
    var sudokuMaskPath by remember { mutableStateOf(c?.sudokuHttpMaskPathRoot ?: "") }

    val isShadowsocks = selectedProtocol == OutboundProtocol.SHADOWSOCKS
    val isSocks5 = selectedProtocol == OutboundProtocol.SOCKS5
    val isNaive = selectedProtocol.isNaive
    val isTrojan = selectedProtocol == OutboundProtocol.TROJAN
    val isVless = selectedProtocol == OutboundProtocol.VLESS
    val isVmess = selectedProtocol == OutboundProtocol.VMESS
    val isHysteria2 = selectedProtocol == OutboundProtocol.HYSTERIA2
    val isTuic = selectedProtocol == OutboundProtocol.TUIC
    val isAnyTls = selectedProtocol == OutboundProtocol.ANYTLS
    val isNowhere = selectedProtocol == OutboundProtocol.NOWHERE
    val isSudoku = selectedProtocol == OutboundProtocol.SUDOKU
    val isReality = security == "reality"
    val isTLS = security == "tls"

    // Protocols where TLS is the protocol itself, not an option.
    val tlsMandatory = isTrojan || isHysteria2 || isTuic || isAnyTls || isNowhere
    // Protocols that pick TLS on or off.
    val tlsOptional = isVless || isVmess
    val showsTls = tlsMandatory || tlsOptional

    val fullEditor = selectedProtocol in EditorEDITABLE_PROTOCOLS

    val portValue = serverPort.trim().toIntOrNull()
    val portValid = portValue != null && portValue in 1..65535
    val uuidValid = runCatching { UUID.fromString(uuid.trim()) }.isSuccess
    val publicKeyBytes = publicKey.trim().base64UrlToByteArrayOrNull()
    val publicKeyValid = publicKeyBytes != null && publicKeyBytes.size == 32
    val shortIdBytes = shortId.trim().hexToByteArrayOrNull()
    val shortIdValid = shortIdBytes != null && shortIdBytes.size <= 8
    val pinsList = tlsPins.split(',', ' ', ';').map { it.trim().replace(":", "").lowercase() }.filter { it.isNotEmpty() }
    val pinsValid = pinsList.all { pin -> pin.length == 64 && pin.all { it in '0'..'9' || it in 'a'..'f' } }
    val fragmentLengthSteps = rangeSteps(fragmentLengths)
    val fragmentDelaySteps = rangeSteps(fragmentDelays)
    val fragmentMaxSplitValue = fragmentMaxSplit.trim().ifEmpty { "0" }.toIntOrNull()
    val fragmentValid = fragmentMode != "custom" ||
        (fragmentLengthSteps != null && fragmentLengthSteps.isNotEmpty() && fragmentDelaySteps != null &&
            fragmentMaxSplitValue != null && fragmentMaxSplitValue >= 0)
    val xhttpExtraValid = xhttpExtra.isBlank() ||
        runCatching { org.json.JSONObject(xhttpExtra) }.isSuccess
    // Brutal needs both directions; BBR needs neither.
    val mbpsValid = (hyUp.isBlank() || hyUp.trim().toIntOrNull()?.let { it > 0 } == true) &&
        (hyDown.isBlank() || hyDown.trim().toIntOrNull()?.let { it > 0 } == true) &&
        (hyUp.isBlank() == hyDown.isBlank())

    val isValid = name.isNotBlank() &&
            serverAddress.isNotBlank() &&
            portValid &&
            pinsValid && fragmentValid &&
            (!fullEditor || when {
                isNaive -> naiveUsername.isNotEmpty() && naivePassword.isNotEmpty()
                isShadowsocks -> ssPassword.isNotEmpty()
                isSocks5 -> true
                isTrojan -> trojanPassword.isNotEmpty()
                isHysteria2 -> password.isNotEmpty() && mbpsValid && (obfs == "none" || obfsPassword.isNotEmpty())
                isAnyTls || isNowhere -> password.isNotEmpty()
                isTuic -> uuidValid && password.isNotEmpty()
                isSudoku -> sudokuKey.isNotBlank()
                isVmess -> uuidValid
                else -> uuidValid &&
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
                        if (configuration != null) tr("edit_configuration")
                        else tr("add_configuration")
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = tr("cancel"))
                    }
                },
                actions = {
                    IconButton(onClick = {
                        val trimmedName = name.trim()
                        val typedAddress = serverAddress.trim()
                        val bareAddress = if (typedAddress.startsWith("[") && typedAddress.endsWith("]"))
                            typedAddress.drop(1).dropLast(1) else typedAddress
                        val port = (portValue ?: return@IconButton).toUShort()

                        if (!fullEditor) {
                            val base = configuration ?: return@IconButton
                            onSave(base.copy(name = trimmedName, serverAddress = bareAddress, serverPort = port))
                            return@IconButton
                        }

                        val needsUuid = isVless || isVmess || isTuic
                        val parsedUUID = if (!needsUuid) {
                            configuration?.uuid ?: UUID.randomUUID()
                        } else {
                            runCatching { UUID.fromString(uuid.trim()) }.getOrNull() ?: return@IconButton
                        }

                        val alpnList = tlsALPN.split(",").map { it.trim() }
                            .filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }
                        val baseTls = configuration?.tls ?: TlsConfiguration(serverName = bareAddress)
                        val sniOrAddress = tlsSNI.trim().ifEmpty { bareAddress }

                        // The TLS layer, for every protocol that has one.
                        var tlsConfiguration: TlsConfiguration? = null
                        if ((tlsOptional && isTLS) || isHysteria2 || isTuic || isAnyTls) {
                            tlsConfiguration = baseTls.copy(
                                serverName = sniOrAddress,
                                alpn = alpnList,
                                allowInsecure = tlsAllowInsecure,
                                fingerprint = fingerprint,
                                minVersion = if (isVless) tlsMinVersion else baseTls.minVersion,
                                maxVersion = if (isVless) tlsMaxVersion else baseTls.maxVersion
                            )
                        }
                        if (isNowhere) {
                            // Nowhere pins neither a fingerprint nor a version.
                            tlsConfiguration = baseTls.copy(serverName = sniOrAddress, alpn = alpnList)
                        }

                        val fragmentSetting: FragmentSettings? = when (fragmentMode) {
                            "off" -> FragmentSettings(isEnabled = false)
                            "custom" -> {
                                val lengths = fragmentLengthSteps.orEmpty()
                                val delays = fragmentDelaySteps.orEmpty()
                                val firstLength = parseStep(lengths.firstOrNull() ?: "3") ?: (3..3)
                                val firstDelay = parseStep(delays.firstOrNull() ?: "0") ?: (0..0)
                                FragmentSettings(
                                    isEnabled = true,
                                    minLength = firstLength.first, maxLength = firstLength.last,
                                    minInterval = firstDelay.first, maxInterval = firstDelay.last,
                                    lengthSteps = lengths, delaySteps = delays,
                                    maxSplit = fragmentMaxSplitValue ?: 0
                                )
                            }
                            else -> null
                        }
                        fun TlsConfiguration.withExtras(): TlsConfiguration = copy(
                            pinnedCertSha256 = pinsList.takeIf { it.isNotEmpty() },
                            verifyName = tlsVerifyName.trim().ifEmpty { null },
                            echConfig = tlsEch.trim().ifEmpty { null },
                            fragment = if (fragmentApplies(selectedProtocol, security)) fragmentSetting else fragment
                        )
                        tlsConfiguration = tlsConfiguration?.withExtras()

                        var trojanTlsConfiguration: TlsConfiguration? = null
                        if (isTrojan) {
                            trojanTlsConfiguration = (configuration?.trojanTls ?: TlsConfiguration(serverName = bareAddress)).copy(
                                serverName = sniOrAddress,
                                alpn = alpnList,
                                allowInsecure = tlsAllowInsecure,
                                fingerprint = fingerprint
                            ).withExtras()
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

                        // VLESS, VMess and Trojan share the stream transports.
                        val streamProtocol = isVless || isVmess || isTrojan
                        val effectiveTransport = when {
                            streamProtocol -> transport
                            isTuic -> "quic"
                            else -> "tcp"
                        }

                        var wsConfiguration: WebSocketConfiguration? = null
                        if (effectiveTransport == "ws" && streamProtocol) {
                            val host = wsHost.trim().ifEmpty { bareAddress }
                            wsConfiguration = (configuration?.websocket ?: WebSocketConfiguration(host = host))
                                .copy(host = host, path = wsPath.trim().ifEmpty { "/" })
                        }
                        var httpUpgradeConfiguration: HttpUpgradeConfiguration? = null
                        if (transport == "httpupgrade" && streamProtocol) {
                            val host = httpUpgradeHost.trim().ifEmpty { bareAddress }
                            httpUpgradeConfiguration = (configuration?.httpUpgrade ?: HttpUpgradeConfiguration(host = host))
                                .copy(host = host, path = httpUpgradePath.trim().ifEmpty { "/" })
                        }
                        var xhttpConfiguration: XHttpConfiguration? = null
                        if (transport == "xhttp" && streamProtocol) {
                            val host = xhttpHost.trim().ifEmpty { bareAddress }
                            xhttpConfiguration = XHttpConfiguration.fromExtraJson(
                                host = host, path = xhttpPath.trim().ifEmpty { "/" },
                                mode = XHttpMode.fromRaw(xhttpMode), extraJson = xhttpExtra
                            )
                        }
                        var grpcConfiguration: GrpcConfiguration? = null
                        if (transport == "grpc" && streamProtocol) {
                            grpcConfiguration = GrpcConfiguration(
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
                        val usesPassword = isHysteria2 || isTuic || isAnyTls || isNowhere
                        val effectiveSecurity = when {
                            tlsMandatory -> "tls"
                            tlsOptional -> security
                            else -> "none"
                        }

                        val config = (configuration ?: ProxyConfiguration(
                            name = trimmedName,
                            serverAddress = bareAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = encryption
                        )).copy(
                            id = configuration?.id ?: UUID.randomUUID(),
                            name = trimmedName,
                            serverAddress = bareAddress,
                            serverPort = port,
                            uuid = parsedUUID,
                            encryption = if (isVless) encryption.trim().ifEmpty { "none" } else "none",
                            transport = effectiveTransport,
                            // Vision needs a TLS or Reality layer to ride on.
                            flow = if (isVless && effectiveSecurity != "none" && transport == "tcp") flow.ifEmpty { null } else null,
                            security = effectiveSecurity,
                            tls = tlsConfiguration,
                            reality = if (isVless) realityConfiguration else null,
                            websocket = wsConfiguration,
                            httpUpgrade = httpUpgradeConfiguration,
                            xhttp = xhttpConfiguration,
                            grpc = grpcConfiguration,
                            muxEnabled = if (isVless) muxEnabled else false,
                            xudpEnabled = if (isVless) xudpEnabled else false,
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
                            password = if (usesPassword) password else null,
                            vmessSecurity = if (isVmess) vmessSecurity.takeIf { it != "auto" } else null,
                            hysteriaUpMbps = if (isHysteria2) hyUp.trim().toIntOrNull() else null,
                            hysteriaDownMbps = if (isHysteria2) hyDown.trim().toIntOrNull() else null,
                            obfuscation = if (isHysteria2 && obfs != "none") obfs else null,
                            obfuscationPassword = if (isHysteria2 && obfs != "none") obfsPassword else null,
                            nowhereUplink = if (isNowhere) nowhereUp else null,
                            nowhereDownlink = if (isNowhere) nowhereDown else null,
                            nowhereMultiplex = isNowhere && nowhereMux,
                            sudokuKey = if (isSudoku) sudokuKey.trim() else null,
                            sudokuAeadMethod = if (isSudoku) sudokuAead else null,
                            sudokuAsciiMode = if (isSudoku) sudokuAscii else null,
                            sudokuEnablePureDownlink = if (isSudoku) sudokuPure else true,
                            sudokuMultiplex = if (isSudoku) sudokuMux else null,
                            sudokuHttpMaskDisable = isSudoku && sudokuMaskDisable,
                            sudokuHttpMaskMode = if (isSudoku) sudokuMaskMode else null,
                            sudokuHttpMaskTls = isSudoku && sudokuMaskTls,
                            sudokuHttpMaskHost = if (isSudoku) sudokuMaskHost.trim().ifEmpty { null } else null,
                            sudokuHttpMaskPathRoot = if (isSudoku) sudokuMaskPath.trim().ifEmpty { null } else null,
                            testseed = configuration?.testseed ?: listOf(900u, 500u, 900u, 256u)
                        )
                        onSave(config)
                    }, enabled = isValid) {
                        Icon(Icons.Default.Check, contentDescription = tr("save"))
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            EditorSectionCard(title = tr("name")) {
                EditorWingField(value = name, onValueChange = { name = it }, label = tr("name"))
            }

            if (!fullEditor) {
                Text(
                    text = tr("edit_limited_protocol", selectedProtocol.displayName),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 4.dp)
                )
            }

            if (fullEditor) EditorSectionCard(title = tr("protocol_label")) {
                EditorDropdownField(
                    label = tr("protocol_label"),
                    selectedValue = selectedProtocol.name,
                    options = EditorEDITABLE_PROTOCOLS.map { it.name to it.displayName },
                    onSelect = { value ->
                        val next = OutboundProtocol.valueOf(value)
                        selectedProtocol = next
                        if (next != OutboundProtocol.VLESS) {
                            flow = ""
                            if (next != OutboundProtocol.VMESS && next != OutboundProtocol.TROJAN) transport = "tcp"
                            security = when (next) {
                                OutboundProtocol.TROJAN, OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC,
                                OutboundProtocol.ANYTLS, OutboundProtocol.NOWHERE -> "tls"
                                OutboundProtocol.VMESS -> if (security == "reality") "none" else security
                                else -> "none"
                            }
                        }
                    }
                )
            }

            EditorSectionCard(title = tr("server")) {
                EditorWingField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = tr("address"),
                    keyboardType = KeyboardType.Uri
                )
                OutlinedTextField(
                    value = serverPort,
                    onValueChange = { serverPort = it },
                    label = { Text(tr("port")) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    isError = serverPort.isNotEmpty() && !portValid,
                    supportingText = if (serverPort.isNotEmpty() && !portValid) {
                        { Text(tr("invalid_port")) }
                    } else null,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    shape = EditorFieldShape,
                    colors = wingTextFieldColors()
                )

                when {
                    !fullEditor -> {}
                    isNaive -> {
                        EditorWingField(naiveUsername, { naiveUsername = it }, tr("username"))
                        EditorWingField(naivePassword, { naivePassword = it }, tr("password"), secret = true)
                    }
                    isSocks5 -> {
                        EditorWingField(socks5Username, { socks5Username = it }, tr("username"))
                        EditorWingField(socks5Password, { socks5Password = it }, tr("password"), secret = true)
                    }
                    isShadowsocks -> {
                        EditorWingField(ssPassword, { ssPassword = it }, tr("password"), secret = true)
                        EditorDropdownField(
                            label = tr("method"),
                            selectedValue = ssMethod,
                            options = listOf(
                                "none" to tr("none"),
                                "aes-128-gcm" to "AES-128-GCM",
                                "aes-256-gcm" to "AES-256-GCM",
                                "chacha20-ietf-poly1305" to "ChaCha20-Poly1305",
                                "2022-blake3-aes-128-gcm" to "BLAKE3-AES-128-GCM",
                                "2022-blake3-aes-256-gcm" to "BLAKE3-AES-256-GCM",
                                "2022-blake3-chacha20-poly1305" to "BLAKE3-ChaCha20-Poly1305"
                            ),
                            onSelect = { ssMethod = it }
                        )
                    }
                    isTrojan -> {
                        EditorWingField(trojanPassword, { trojanPassword = it }, tr("password"), secret = true)
                    }
                    isHysteria2 -> {
                        EditorWingField(password, { password = it }, tr("password"), secret = true)
                        EditorWingField(hyUp, { hyUp = it }, tr("up_mbps"), keyboardType = KeyboardType.Number)
                        EditorWingField(hyDown, { hyDown = it }, tr("down_mbps"), keyboardType = KeyboardType.Number)
                        Text(
                            text = tr("bandwidth_hint"),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (mbpsValid) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error
                        )
                        EditorDropdownField(
                            label = tr("obfuscation"),
                            selectedValue = obfs,
                            options = listOf("none" to tr("none"), "salamander" to "Salamander"),
                            onSelect = { obfs = it }
                        )
                        if (obfs != "none") {
                            EditorWingField(obfsPassword, { obfsPassword = it }, tr("obfs_password"), secret = true)
                        }
                    }
                    isTuic -> {
                        EditorUuidField(uuid, { uuid = it }, uuidValid)
                        EditorWingField(password, { password = it }, tr("password"), secret = true)
                    }
                    isAnyTls -> {
                        EditorWingField(password, { password = it }, tr("password"), secret = true)
                    }
                    isNowhere -> {
                        EditorWingField(password, { password = it }, tr("key"), secret = true)
                        EditorDropdownField(
                            label = tr("uplink_carrier"),
                            selectedValue = nowhereUp,
                            options = listOf("udp" to "UDP", "tcp" to "TCP"),
                            onSelect = { nowhereUp = it }
                        )
                        EditorDropdownField(
                            label = tr("downlink_carrier"),
                            selectedValue = nowhereDown,
                            options = listOf("udp" to "UDP", "tcp" to "TCP"),
                            onSelect = { nowhereDown = it }
                        )
                        if (nowhereUp == "tcp" || nowhereDown == "tcp") {
                            EditorSwitchRow(tr("multiplex"), nowhereMux) { nowhereMux = it }
                        }
                    }
                    isSudoku -> {
                        EditorWingField(sudokuKey, { sudokuKey = it }, tr("key"), secret = true)
                        EditorDropdownField(
                            label = tr("aead_method"),
                            selectedValue = sudokuAead,
                            options = SudokuAeadMethod.entries.map { it.id to it.displayName },
                            onSelect = { sudokuAead = it }
                        )
                        EditorDropdownField(
                            label = tr("ascii_mode"),
                            selectedValue = sudokuAscii,
                            options = SudokuAsciiMode.entries.map { it.id to it.displayName },
                            onSelect = { sudokuAscii = it }
                        )
                        EditorDropdownField(
                            label = tr("multiplex"),
                            selectedValue = sudokuMux,
                            options = SudokuMultiplex.entries.map { it.id to it.displayName },
                            onSelect = { sudokuMux = it }
                        )
                        EditorSwitchRow(tr("pure_downlink"), sudokuPure) { sudokuPure = it }
                        EditorSwitchRow(tr("http_mask"), !sudokuMaskDisable) { sudokuMaskDisable = !it }
                        if (!sudokuMaskDisable) {
                            EditorDropdownField(
                                label = tr("mode"),
                                selectedValue = sudokuMaskMode,
                                options = SudokuHttpMaskMode.entries.map { it.id to it.displayName },
                                onSelect = { sudokuMaskMode = it }
                            )
                            EditorSwitchRow(tr("tls"), sudokuMaskTls) { sudokuMaskTls = it }
                            EditorWingField(sudokuMaskHost, { sudokuMaskHost = it }, tr("mask_host"))
                            EditorWingField(sudokuMaskPath, { sudokuMaskPath = it }, tr("mask_path"))
                        }
                    }
                    isVmess -> {
                        EditorUuidField(uuid, { uuid = it }, uuidValid)
                        EditorDropdownField(
                            label = tr("cipher"),
                            selectedValue = vmessSecurity,
                            options = listOf(
                                "auto" to tr("auto"),
                                "aes-128-gcm" to "AES-128-GCM",
                                "chacha20-poly1305" to "ChaCha20-Poly1305",
                                "none" to tr("none"),
                                "zero" to "Zero"
                            ),
                            onSelect = { vmessSecurity = it }
                        )
                    }
                    else -> {
                        EditorUuidField(uuid, { uuid = it }, uuidValid)
                        EditorWingField(
                            value = encryption,
                            onValueChange = { encryption = it },
                            label = tr("encryption"),
                            placeholder = "none"
                        )
                    }
                }
            }

            // VLESS, VMess and Trojan choose among the stream transports.
            if (isVless || isVmess || isTrojan) {
                EditorSectionCard(title = tr("transport")) {
                    EditorDropdownField(
                        label = tr("transport"),
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
                        EditorWingField(wsHost, { wsHost = it }, tr("host"))
                        EditorWingField(wsPath, { wsPath = it }, tr("path"))
                    }
                    if (transport == "httpupgrade") {
                        EditorWingField(httpUpgradeHost, { httpUpgradeHost = it }, tr("host"))
                        EditorWingField(httpUpgradePath, { httpUpgradePath = it }, tr("path"))
                    }
                    if (transport == "xhttp") {
                        EditorWingField(xhttpHost, { xhttpHost = it }, tr("host"))
                        EditorWingField(xhttpPath, { xhttpPath = it }, tr("path"))
                        EditorDropdownField(
                            label = tr("mode"),
                            selectedValue = xhttpMode,
                            options = listOf(
                                "auto" to tr("auto"),
                                "packet-up" to "Packet Up",
                                "stream-up" to "Stream Up",
                                "stream-one" to "Stream One"
                            ),
                            onSelect = { xhttpMode = it }
                        )
                        OutlinedTextField(
                            value = xhttpExtra,
                            onValueChange = { xhttpExtra = it },
                            label = { Text(tr("extra_json")) },
                            isError = !xhttpExtraValid,
                            supportingText = if (!xhttpExtraValid) {
                                { Text(tr("invalid_json")) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            minLines = 2,
                            maxLines = 6,
                            shape = EditorFieldShape,
                            colors = wingTextFieldColors()
                        )
                    }
                    if (transport == "grpc") {
                        EditorWingField(grpcServiceName, { grpcServiceName = it }, tr("grpc_service_name"))
                        EditorWingField(grpcAuthority, { grpcAuthority = it }, tr("grpc_authority"))
                        EditorDropdownField(
                            label = tr("mode"),
                            selectedValue = if (grpcMultiMode) "multi" else "gun",
                            options = listOf("gun" to "Gun", "multi" to "Multi"),
                            onSelect = { grpcMultiMode = (it == "multi") }
                        )
                        EditorWingField(grpcUserAgent, { grpcUserAgent = it }, tr("user_agent"))
                    }

                    if (isVless && transport == "tcp" && (isTLS || isReality)) {
                        EditorDropdownField(
                            label = tr("flow"),
                            selectedValue = flow,
                            options = listOf(
                                "" to tr("none"),
                                "xtls-rprx-vision" to "Vision",
                                "xtls-rprx-vision-udp443" to "Vision with UDP 443"
                            ),
                            onSelect = { flow = it }
                        )
                        EditorSwitchRow("Mux", muxEnabled) {
                            muxEnabled = it
                            if (!it) xudpEnabled = false
                        }
                        if (muxEnabled) {
                            EditorSwitchRow("XUDP", xudpEnabled) { xudpEnabled = it }
                        }
                    }
                }
            }

            if (showsTls) {
                EditorSectionCard(title = tr("tls")) {
                    if (tlsOptional) {
                        EditorDropdownField(
                            label = tr("security"),
                            selectedValue = security,
                            options = if (isVless) listOf(
                                "none" to tr("none"),
                                "tls" to "TLS",
                                "reality" to "Reality"
                            ) else listOf(
                                "none" to tr("none"),
                                "tls" to "TLS"
                            ),
                            onSelect = { security = it }
                        )
                    }

                    if (isTLS || tlsMandatory) {
                        EditorWingField(tlsSNI, { tlsSNI = it }, tr("sni"))
                        EditorWingField(tlsALPN, { tlsALPN = it }, tr("alpn"), placeholder = "h2,http/1.1")
                        if (!isNowhere) {
                            EditorSwitchRow(tr("allow_insecure"), tlsAllowInsecure) { tlsAllowInsecure = it }
                            EditorFingerprintDropdown(selected = fingerprint, onSelect = { fingerprint = it })
                            OutlinedTextField(
                                value = tlsPins,
                                onValueChange = { tlsPins = it },
                                label = { Text(tr("pinned_cert")) },
                                isError = !pinsValid,
                                supportingText = {
                                    Text(tr(if (pinsValid) "pinned_cert_hint" else "invalid_pins"))
                                },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                shape = EditorFieldShape,
                                colors = wingTextFieldColors()
                            )
                            EditorWingField(tlsVerifyName, { tlsVerifyName = it }, tr("verify_name"))
                            EditorWingField(tlsEch, { tlsEch = it }, tr("ech_config"))
                        }
                        if (isVless) {
                            EditorDropdownField(
                                label = tr("min_tls_version"),
                                selectedValue = tlsMinVersion?.name ?: "ANY",
                                options = listOf(
                                    "ANY" to tr("any_version"),
                                    TlsVersion.TLS12.name to "TLS 1.2",
                                    TlsVersion.TLS13.name to "TLS 1.3"
                                ),
                                onSelect = { value ->
                                    tlsMinVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                                }
                            )
                            EditorDropdownField(
                                label = tr("max_tls_version"),
                                selectedValue = tlsMaxVersion?.name ?: "ANY",
                                options = listOf(
                                    "ANY" to tr("any_version"),
                                    TlsVersion.TLS12.name to "TLS 1.2",
                                    TlsVersion.TLS13.name to "TLS 1.3"
                                ),
                                onSelect = { value ->
                                    tlsMaxVersion = if (value == "ANY") null else TlsVersion.valueOf(value)
                                }
                            )
                        }
                    }

                    if (isReality && isVless) {
                        EditorWingField(sni, { sni = it }, tr("sni"))
                        OutlinedTextField(
                            value = publicKey,
                            onValueChange = { publicKey = it },
                            label = { Text(tr("public_key")) },
                            isError = publicKey.isNotEmpty() && !publicKeyValid,
                            supportingText = if (publicKey.isNotEmpty() && !publicKeyValid) {
                                { Text(tr("invalid_public_key")) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = EditorFieldShape,
                            colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = shortId,
                            onValueChange = { shortId = it },
                            label = { Text(tr("short_id")) },
                            isError = !shortIdValid,
                            supportingText = if (!shortIdValid) {
                                { Text(tr("invalid_short_id")) }
                            } else null,
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = EditorFieldShape,
                            colors = wingTextFieldColors()
                        )
                        EditorFingerprintDropdown(selected = fingerprint, onSelect = { fingerprint = it })
                    }
                }
            }

            if (fullEditor && fragmentApplies(selectedProtocol, security)) {
                EditorSectionCard(title = tr("fragment_section")) {
                    EditorDropdownField(
                        label = tr("fragment_mode"),
                        selectedValue = fragmentMode,
                        options = listOf(
                            "default" to tr("fragment_default"),
                            "off" to tr("fragment_off"),
                            "custom" to tr("fragment_custom")
                        ),
                        onSelect = { fragmentMode = it }
                    )
                    if (fragmentMode == "custom") {
                        OutlinedTextField(
                            value = fragmentLengths,
                            onValueChange = { fragmentLengths = it },
                            label = { Text(tr("fragment_lengths")) },
                            isError = fragmentLengthSteps == null || fragmentLengthSteps.isEmpty(),
                            supportingText = { Text(tr("fragment_steps_hint")) },
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            shape = EditorFieldShape, colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = fragmentDelays,
                            onValueChange = { fragmentDelays = it },
                            label = { Text(tr("fragment_delays")) },
                            isError = fragmentDelaySteps == null,
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            shape = EditorFieldShape, colors = wingTextFieldColors()
                        )
                        EditorWingField(
                            fragmentMaxSplit, { fragmentMaxSplit = it },
                            tr("fragment_max_split"), keyboardType = KeyboardType.Number
                        )
                    }
                    Text(
                        text = tr("fragment_server_hint"),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

/** A single-line text field in the Wing shape. */
@Composable
private fun EditorWingField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    secret: Boolean = false,
    placeholder: String? = null,
    keyboardType: KeyboardType = KeyboardType.Text
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = if (secret) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        shape = EditorFieldShape,
        colors = wingTextFieldColors()
    )
}

@Composable
private fun EditorUuidField(value: String, onValueChange: (String) -> Unit, valid: Boolean) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(tr("uuid")) },
        isError = value.isNotEmpty() && !valid,
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        shape = EditorFieldShape,
        colors = wingTextFieldColors()
    )
}

/** A Mythaia section: feather-marked title above a soft panel of fields. */
@Composable
private fun EditorSectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        WingSectionTitle(title = title)
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = EditorCardShape,
            color = MaterialTheme.colorScheme.surfaceContainerLow
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
private fun EditorSwitchRow(
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
private fun EditorDropdownField(
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
            shape = EditorFieldShape,
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
private fun EditorFingerprintDropdown(
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
            label = { Text(tr("fingerprint")) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
            shape = EditorFieldShape,
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

/**
 * Whether the ClientHello fragment setting reaches the wire for this server:
 * it applies to a TLS handshake dialled directly, which is VLESS, VMess and
 * Trojan over TLS and AnyTLS. Reality builds its own hello and QUIC protocols
 * have no TCP hello to split.
 */
private fun fragmentApplies(protocol: OutboundProtocol, security: String): Boolean = when (protocol) {
    OutboundProtocol.VLESS, OutboundProtocol.VMESS -> security == "tls"
    OutboundProtocol.TROJAN, OutboundProtocol.ANYTLS -> true
    else -> false
}

/** `3` or `100-200`, as FinalMask writes a step. */
private fun parseStep(text: String): IntRange? {
    val ends = text.trim().split("-").map { it.trim() }
    if (ends.size !in 1..2 || ends.any { it.isEmpty() }) return null
    val low = ends[0].toIntOrNull() ?: return null
    val high = (if (ends.size == 2) ends[1].toIntOrNull() else low) ?: return null
    if (low < 0 || high < low) return null
    return low..high
}

/** A comma-separated list of steps, or null when any of them does not parse. Empty text is an empty list. */
private fun rangeSteps(text: String): List<String>? {
    val items = text.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    return if (items.all { parseStep(it) != null }) items else null
}

private fun rangeText(range: IntRange): String =
    if (range.first == range.last) range.first.toString() else "${range.first}-${range.last}"
