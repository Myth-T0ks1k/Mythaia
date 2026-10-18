package com.mythaia.ui.proxy

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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.HopInterval
import com.mythaia.data.model.HttpUpgradeConfiguration
import com.mythaia.data.model.NaiveProtocol
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.PortUnion
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.ui.components.WingSectionTitle
import com.mythaia.ui.components.wingTextFieldColors
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
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.SwitchDefaults
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Wing form language: 18dp fields inside soft 24dp panels.
internal val FieldShape = RoundedCornerShape(18.dp)
internal val CardShape = RoundedCornerShape(24.dp)

/** Every protocol the app dials, except WireGuard, which has a file editor of its own. */
private val EDITABLE_PROTOCOLS = listOf(
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
fun ProxyEditorScreen(
    configuration: ProxyConfiguration?,
    onSave: (ProxyConfiguration) -> Unit,
    onDismiss: () -> Unit,
    /** For a new server: the protocol picked on [ProtocolPickerScreen]. */
    initialProtocol: OutboundProtocol? = null
) {
    // Every field starts from the configuration being edited, so the sheet
    // opens on the right values instead of flashing defaults for a frame.
    // Saveable, so a rotation or a theme switch mid-edit keeps what was typed.
    val c = configuration
    var selectedProtocol by rememberSaveable { mutableStateOf(c?.outboundProtocol ?: initialProtocol ?: OutboundProtocol.VLESS) }
    var name by rememberSaveable { mutableStateOf(c?.name ?: "") }
    var serverAddress by rememberSaveable { mutableStateOf(c?.serverAddress ?: "") }
    var serverPort by rememberSaveable { mutableStateOf(c?.serverPort?.toString() ?: "") }
    var uuid by rememberSaveable { mutableStateOf(c?.uuid?.toString() ?: "") }
    var encryption by rememberSaveable { mutableStateOf(c?.encryption ?: "none") }
    var transport by rememberSaveable { mutableStateOf(c?.transport ?: "tcp") }
    var flow by rememberSaveable { mutableStateOf(c?.flow ?: "") }
    var security by rememberSaveable {
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

    var wsHost by rememberSaveable { mutableStateOf(c?.websocket?.host ?: "") }
    var wsPath by rememberSaveable { mutableStateOf(c?.websocket?.path ?: "/") }
    var httpUpgradeHost by rememberSaveable { mutableStateOf(c?.httpUpgrade?.host ?: "") }
    var httpUpgradePath by rememberSaveable { mutableStateOf(c?.httpUpgrade?.path ?: "/") }
    var xhttpHost by rememberSaveable { mutableStateOf(c?.xhttp?.host ?: "") }
    var xhttpPath by rememberSaveable { mutableStateOf(c?.xhttp?.path ?: "/") }
    var xhttpMode by rememberSaveable { mutableStateOf(c?.xhttp?.mode?.raw ?: "auto") }
    var xhttpExtra by rememberSaveable { mutableStateOf(c?.xhttp?.toExtraJson() ?: "") }
    var grpcServiceName by rememberSaveable { mutableStateOf(c?.grpc?.serviceName ?: "") }
    var grpcAuthority by rememberSaveable { mutableStateOf(c?.grpc?.authority ?: "") }
    var grpcMultiMode by rememberSaveable { mutableStateOf(c?.grpc?.multiMode ?: false) }
    var grpcUserAgent by rememberSaveable { mutableStateOf(c?.grpc?.userAgent ?: "") }

    // Trojan keeps its TLS under trojanTls; the shared fields read whichever is set.
    val existingTls = c?.trojanTls ?: c?.tls
    var tlsSNI by rememberSaveable { mutableStateOf(existingTls?.serverName ?: "") }
    var tlsALPN by rememberSaveable { mutableStateOf(existingTls?.alpn?.joinToString(",") ?: "") }
    var tlsAllowInsecure by rememberSaveable { mutableStateOf(existingTls?.allowInsecure ?: false) }
    var tlsMinVersion by rememberSaveable { mutableStateOf<TlsVersion?>(existingTls?.minVersion) }
    var tlsMaxVersion by rememberSaveable { mutableStateOf<TlsVersion?>(existingTls?.maxVersion) }
    // Xray 26's replacements for allowInsecure, and ECH.
    var tlsPins by rememberSaveable { mutableStateOf(existingTls?.pinnedCertSha256?.joinToString(", ") ?: "") }
    var tlsVerifyName by rememberSaveable { mutableStateOf(existingTls?.verifyName ?: "") }
    var tlsEch by rememberSaveable { mutableStateOf(existingTls?.echConfig ?: "") }

    // Per-server ClientHello fragmentation: follow the global setting, off, or its own.
    val existingFragment = existingTls?.fragment
    var fragmentMode by rememberSaveable {
        mutableStateOf(
            when {
                existingFragment == null -> "default"
                !existingFragment.isEnabled -> "off"
                else -> "custom"
            }
        )
    }
    var fragmentLengths by rememberSaveable {
        mutableStateOf(
            existingFragment?.takeIf { it.isEnabled }?.let { f ->
                f.lengthSteps.ifEmpty { listOf(rangeText(f.lengthRange)) }.joinToString(", ")
            } ?: "3"
        )
    }
    var fragmentDelays by rememberSaveable {
        mutableStateOf(
            existingFragment?.takeIf { it.isEnabled }?.let { f ->
                f.delaySteps.ifEmpty { listOf(rangeText(f.intervalRange)) }.joinToString(", ")
            } ?: "1"
        )
    }
    var fragmentMaxSplit by rememberSaveable {
        mutableStateOf(existingFragment?.takeIf { it.isEnabled }?.maxSplit?.toString() ?: "2")
    }

    var muxEnabled by rememberSaveable { mutableStateOf(c?.muxEnabled ?: true) }
    var xudpEnabled by rememberSaveable { mutableStateOf(c?.xudpEnabled ?: true) }

    var sni by rememberSaveable { mutableStateOf(c?.reality?.serverName ?: "") }
    var publicKey by rememberSaveable { mutableStateOf(c?.reality?.publicKey?.toBase64Url() ?: "") }
    var shortId by rememberSaveable { mutableStateOf(c?.reality?.shortId?.toHex() ?: "") }
    var fingerprint by rememberSaveable {
        mutableStateOf(c?.reality?.fingerprint ?: existingTls?.fingerprint ?: TlsFingerprint.CHROME_133)
    }

    var ssPassword by rememberSaveable { mutableStateOf(c?.ssPassword ?: "") }
    var ssMethod by rememberSaveable { mutableStateOf(c?.ssMethod ?: "aes-128-gcm") }
    var naiveUsername by rememberSaveable { mutableStateOf(c?.naiveUsername ?: "") }
    var naivePassword by rememberSaveable { mutableStateOf(c?.naivePassword ?: "") }
    var socks5Username by rememberSaveable { mutableStateOf(c?.socks5Username ?: "") }
    var socks5Password by rememberSaveable { mutableStateOf(c?.socks5Password ?: "") }
    var trojanPassword by rememberSaveable { mutableStateOf(c?.trojanPassword ?: "") }

    // Hysteria2, AnyTLS, Nowhere and TUIC authenticate with one password (a
    // key, for Nowhere); TUIC pairs it with a UUID.
    var password by rememberSaveable { mutableStateOf(c?.password ?: "") }
    var vmessSecurity by rememberSaveable { mutableStateOf(c?.vmessSecurity ?: "auto") }
    var hyUp by rememberSaveable { mutableStateOf(c?.hysteriaUpMbps?.toString() ?: "") }
    var hyDown by rememberSaveable { mutableStateOf(c?.hysteriaDownMbps?.toString() ?: "") }
    var hyPorts by rememberSaveable { mutableStateOf(c?.hysteriaPorts ?: "") }
    var hyHop by rememberSaveable {
        mutableStateOf(c?.takeIf { it.hysteriaHopInterval != null }?.hysteriaHop?.toString() ?: "")
    }
    var obfs by rememberSaveable { mutableStateOf(c?.obfuscation ?: "none") }
    var obfsPassword by rememberSaveable { mutableStateOf(c?.obfuscationPassword ?: "") }
    var nowhereUp by rememberSaveable { mutableStateOf(c?.nowhereUplink ?: "udp") }
    var nowhereDown by rememberSaveable { mutableStateOf(c?.nowhereDownlink ?: "udp") }
    var nowhereMux by rememberSaveable { mutableStateOf(c?.nowhereMultiplex ?: false) }

    var sudokuKey by rememberSaveable { mutableStateOf(c?.sudokuKey ?: "") }
    var sudokuAead by rememberSaveable { mutableStateOf(c?.sudokuAeadMethod ?: SudokuAeadMethod.CHACHA20_POLY1305.id) }
    var sudokuAscii by rememberSaveable { mutableStateOf(c?.sudokuAsciiMode ?: SudokuAsciiMode.PREFER_ENTROPY.id) }
    var sudokuPure by rememberSaveable { mutableStateOf(c?.sudokuEnablePureDownlink ?: true) }
    var sudokuMux by rememberSaveable { mutableStateOf(c?.sudokuMultiplex ?: SudokuMultiplex.OFF.id) }
    var sudokuMaskDisable by rememberSaveable { mutableStateOf(c?.sudokuHttpMaskDisable ?: false) }
    var sudokuMaskMode by rememberSaveable { mutableStateOf(c?.sudokuHttpMaskMode ?: SudokuHttpMaskMode.LEGACY.id) }
    var sudokuMaskTls by rememberSaveable { mutableStateOf(c?.sudokuHttpMaskTls ?: false) }
    var sudokuMaskHost by rememberSaveable { mutableStateOf(c?.sudokuHttpMaskHost ?: "") }
    var sudokuMaskPath by rememberSaveable { mutableStateOf(c?.sudokuHttpMaskPathRoot ?: "") }

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
    // Naive is always TLS; its section carries the name, "allow insecure"
    // and the pin, since the scheme fixes the ALPN.
    val showsTls = tlsMandatory || tlsOptional || isNaive

    val fullEditor = selectedProtocol in EDITABLE_PROTOCOLS

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
    // Port hopping: a list of more than one port, and an interval only with it.
    val hopPorts = PortUnion.parse(hyPorts)?.takeIf { it.hops }
    val hopPortsValid = hyPorts.isBlank() || hopPorts != null
    val hopInterval = HopInterval.parse(hyHop)
    val hopIntervalValid = hyHop.isBlank() || hopInterval != null

    val isValid = name.isNotBlank() &&
            serverAddress.isNotBlank() &&
            portValid &&
            pinsValid && fragmentValid &&
            (!fullEditor || when {
                isNaive -> naiveUsername.isNotEmpty() && naivePassword.isNotEmpty()
                isShadowsocks -> ssPassword.isNotEmpty()
                isSocks5 -> true
                isTrojan -> trojanPassword.isNotEmpty()
                isHysteria2 -> password.isNotEmpty() && mbpsValid && hopPortsValid && hopIntervalValid &&
                    (obfs == "none" || obfsPassword.isNotEmpty())
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
                            tlsConfiguration = baseTls.copy(
                                serverName = sniOrAddress,
                                alpn = alpnList,
                                allowInsecure = tlsAllowInsecure
                            )
                        }
                        if (isNaive) {
                            // The ALPN follows the scheme (h2 or http/1.1), so it is not kept here.
                            tlsConfiguration = baseTls.copy(
                                serverName = sniOrAddress,
                                allowInsecure = tlsAllowInsecure
                            )
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
                            hysteriaPorts = if (isHysteria2) hopPorts?.toString() else null,
                            hysteriaHopInterval = if (isHysteria2 && hopPorts != null) hopInterval?.min else null,
                            hysteriaHopIntervalMax = if (isHysteria2 && hopPorts != null) {
                                hopInterval?.takeIf { it.max != it.min }?.max
                            } else null,
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
                WingField(value = name, onValueChange = { name = it }, label = stringResource(R.string.name))
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
                    options = EDITABLE_PROTOCOLS.map { it.name to it.displayName },
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

            SectionCard(title = stringResource(R.string.server)) {
                WingField(
                    value = serverAddress,
                    onValueChange = { serverAddress = it },
                    label = stringResource(R.string.address),
                    keyboardType = KeyboardType.Uri
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

                when {
                    !fullEditor -> {}
                    isNaive -> {
                        WingField(naiveUsername, { naiveUsername = it }, stringResource(R.string.username))
                        WingField(naivePassword, { naivePassword = it }, stringResource(R.string.password), secret = true)
                    }
                    isSocks5 -> {
                        WingField(socks5Username, { socks5Username = it }, stringResource(R.string.username))
                        WingField(socks5Password, { socks5Password = it }, stringResource(R.string.password), secret = true)
                    }
                    isShadowsocks -> {
                        WingField(ssPassword, { ssPassword = it }, stringResource(R.string.password), secret = true)
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
                    }
                    isTrojan -> {
                        WingField(trojanPassword, { trojanPassword = it }, stringResource(R.string.password), secret = true)
                    }
                    isHysteria2 -> {
                        WingField(password, { password = it }, stringResource(R.string.password), secret = true)
                        WingField(hyUp, { hyUp = it }, stringResource(R.string.up_mbps), keyboardType = KeyboardType.Number)
                        WingField(hyDown, { hyDown = it }, stringResource(R.string.down_mbps), keyboardType = KeyboardType.Number)
                        Text(
                            text = stringResource(R.string.bandwidth_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (mbpsValid) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error
                        )
                        WingField(hyPorts, { hyPorts = it }, stringResource(R.string.port_hopping), placeholder = "20000-30000")
                        Text(
                            text = stringResource(if (hopPortsValid) R.string.port_hopping_hint else R.string.invalid_port_list),
                            style = MaterialTheme.typography.bodySmall,
                            color = if (hopPortsValid) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error
                        )
                        if (hyPorts.isNotBlank()) {
                            WingField(hyHop, { hyHop = it }, stringResource(R.string.hop_interval), placeholder = "30")
                            Text(
                                text = stringResource(R.string.hop_interval_hint),
                                style = MaterialTheme.typography.bodySmall,
                                color = if (hopIntervalValid) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error
                            )
                        }
                        DropdownField(
                            label = stringResource(R.string.obfuscation),
                            selectedValue = obfs,
                            options = listOf("none" to stringResource(R.string.none), "salamander" to "Salamander"),
                            onSelect = { obfs = it }
                        )
                        if (obfs != "none") {
                            WingField(obfsPassword, { obfsPassword = it }, stringResource(R.string.obfs_password), secret = true)
                        }
                    }
                    isTuic -> {
                        UuidField(uuid, { uuid = it }, uuidValid)
                        WingField(password, { password = it }, stringResource(R.string.password), secret = true)
                    }
                    isAnyTls -> {
                        WingField(password, { password = it }, stringResource(R.string.password), secret = true)
                    }
                    isNowhere -> {
                        WingField(password, { password = it }, stringResource(R.string.key), secret = true)
                        DropdownField(
                            label = stringResource(R.string.uplink_carrier),
                            selectedValue = nowhereUp,
                            options = listOf("udp" to "UDP", "tcp" to "TCP"),
                            onSelect = { nowhereUp = it }
                        )
                        DropdownField(
                            label = stringResource(R.string.downlink_carrier),
                            selectedValue = nowhereDown,
                            options = listOf("udp" to "UDP", "tcp" to "TCP"),
                            onSelect = { nowhereDown = it }
                        )
                        if (nowhereUp == "tcp" || nowhereDown == "tcp") {
                            SwitchRow(stringResource(R.string.multiplex), nowhereMux) { nowhereMux = it }
                        }
                    }
                    isSudoku -> {
                        WingField(sudokuKey, { sudokuKey = it }, stringResource(R.string.key), secret = true)
                        DropdownField(
                            label = stringResource(R.string.aead_method),
                            selectedValue = sudokuAead,
                            options = SudokuAeadMethod.entries.map { it.id to it.displayName },
                            onSelect = { sudokuAead = it }
                        )
                        DropdownField(
                            label = stringResource(R.string.ascii_mode),
                            selectedValue = sudokuAscii,
                            options = SudokuAsciiMode.entries.map { it.id to it.displayName },
                            onSelect = { sudokuAscii = it }
                        )
                        DropdownField(
                            label = stringResource(R.string.multiplex),
                            selectedValue = sudokuMux,
                            options = SudokuMultiplex.entries.map { it.id to it.displayName },
                            onSelect = { sudokuMux = it }
                        )
                        SwitchRow(stringResource(R.string.pure_downlink), sudokuPure) { sudokuPure = it }
                        SwitchRow(stringResource(R.string.http_mask), !sudokuMaskDisable) { sudokuMaskDisable = !it }
                        if (!sudokuMaskDisable) {
                            DropdownField(
                                label = stringResource(R.string.mode),
                                selectedValue = sudokuMaskMode,
                                options = SudokuHttpMaskMode.entries.map { it.id to it.displayName },
                                onSelect = { sudokuMaskMode = it }
                            )
                            SwitchRow(stringResource(R.string.tls), sudokuMaskTls) { sudokuMaskTls = it }
                            WingField(sudokuMaskHost, { sudokuMaskHost = it }, stringResource(R.string.mask_host))
                            WingField(sudokuMaskPath, { sudokuMaskPath = it }, stringResource(R.string.mask_path))
                        }
                    }
                    isVmess -> {
                        UuidField(uuid, { uuid = it }, uuidValid)
                        DropdownField(
                            label = stringResource(R.string.cipher),
                            selectedValue = vmessSecurity,
                            options = listOf(
                                "auto" to stringResource(R.string.auto),
                                "aes-128-gcm" to "AES-128-GCM",
                                "chacha20-poly1305" to "ChaCha20-Poly1305",
                                "none" to stringResource(R.string.none),
                                "zero" to "Zero"
                            ),
                            onSelect = { vmessSecurity = it }
                        )
                    }
                    else -> {
                        UuidField(uuid, { uuid = it }, uuidValid)
                        WingField(
                            value = encryption,
                            onValueChange = { encryption = it },
                            label = stringResource(R.string.encryption),
                            placeholder = "none"
                        )
                    }
                }
            }

            // VLESS, VMess and Trojan choose among the stream transports.
            if (isVless || isVmess || isTrojan) {
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
                        WingField(wsHost, { wsHost = it }, stringResource(R.string.host))
                        WingField(wsPath, { wsPath = it }, stringResource(R.string.path))
                    }
                    if (transport == "httpupgrade") {
                        WingField(httpUpgradeHost, { httpUpgradeHost = it }, stringResource(R.string.host))
                        WingField(httpUpgradePath, { httpUpgradePath = it }, stringResource(R.string.path))
                    }
                    if (transport == "xhttp") {
                        WingField(xhttpHost, { xhttpHost = it }, stringResource(R.string.host))
                        WingField(xhttpPath, { xhttpPath = it }, stringResource(R.string.path))
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
                        WingField(grpcServiceName, { grpcServiceName = it }, stringResource(R.string.grpc_service_name))
                        WingField(grpcAuthority, { grpcAuthority = it }, stringResource(R.string.grpc_authority))
                        DropdownField(
                            label = stringResource(R.string.mode),
                            selectedValue = if (grpcMultiMode) "multi" else "gun",
                            options = listOf("gun" to "Gun", "multi" to "Multi"),
                            onSelect = { grpcMultiMode = (it == "multi") }
                        )
                        WingField(grpcUserAgent, { grpcUserAgent = it }, stringResource(R.string.user_agent))
                    }

                    if (isVless && transport == "tcp" && (isTLS || isReality)) {
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
                        SwitchRow("Mux", muxEnabled) {
                            muxEnabled = it
                            if (!it) xudpEnabled = false
                        }
                        if (muxEnabled) {
                            SwitchRow("XUDP", xudpEnabled) { xudpEnabled = it }
                        }
                    }
                }
            }

            if (showsTls) {
                SectionCard(title = stringResource(R.string.tls)) {
                    if (tlsOptional) {
                        DropdownField(
                            label = stringResource(R.string.security),
                            selectedValue = security,
                            options = if (isVless) listOf(
                                "none" to stringResource(R.string.none),
                                "tls" to "TLS",
                                "reality" to "Reality"
                            ) else listOf(
                                "none" to stringResource(R.string.none),
                                "tls" to "TLS"
                            ),
                            onSelect = { security = it }
                        )
                    }

                    if (isTLS || tlsMandatory || isNaive) {
                        WingField(tlsSNI, { tlsSNI = it }, stringResource(R.string.sni))
                        if (!isNaive) {
                            WingField(tlsALPN, { tlsALPN = it }, stringResource(R.string.alpn), placeholder = "h2,http/1.1")
                        }
                        // Every protocol with a certificate to check offers to
                        // skip the check, as other clients do, with the danger
                        // spelled out beside the switch.
                        InsecureSwitch(tlsAllowInsecure) { tlsAllowInsecure = it }
                        // Nowhere and Naive pin neither a fingerprint nor ECH.
                        if (!isNowhere && !isNaive) {
                            FingerprintDropdown(selected = fingerprint, onSelect = { fingerprint = it })
                        }
                        OutlinedTextField(
                            value = tlsPins,
                            onValueChange = { tlsPins = it },
                            label = { Text(stringResource(R.string.pinned_cert)) },
                            isError = !pinsValid,
                            supportingText = {
                                Text(stringResource(if (pinsValid) R.string.pinned_cert_hint else R.string.invalid_pins))
                            },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            shape = FieldShape,
                            colors = wingTextFieldColors()
                        )
                        WingField(tlsVerifyName, { tlsVerifyName = it }, stringResource(R.string.verify_name))
                        if (!isNowhere && !isNaive) {
                            WingField(tlsEch, { tlsEch = it }, stringResource(R.string.ech_config))
                        }
                        if (isVless) {
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

                    if (isReality && isVless) {
                        WingField(sni, { sni = it }, stringResource(R.string.sni))
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
                        FingerprintDropdown(selected = fingerprint, onSelect = { fingerprint = it })
                    }
                }
            }

            if (fullEditor && fragmentApplies(selectedProtocol, security)) {
                SectionCard(title = stringResource(R.string.fragment_section)) {
                    DropdownField(
                        label = stringResource(R.string.fragment_mode),
                        selectedValue = fragmentMode,
                        options = listOf(
                            "default" to stringResource(R.string.fragment_default),
                            "off" to stringResource(R.string.fragment_off),
                            "custom" to stringResource(R.string.fragment_custom)
                        ),
                        onSelect = { fragmentMode = it }
                    )
                    if (fragmentMode == "custom") {
                        OutlinedTextField(
                            value = fragmentLengths,
                            onValueChange = { fragmentLengths = it },
                            label = { Text(stringResource(R.string.fragment_lengths)) },
                            isError = fragmentLengthSteps == null || fragmentLengthSteps.isEmpty(),
                            supportingText = { Text(stringResource(R.string.fragment_steps_hint)) },
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            shape = FieldShape, colors = wingTextFieldColors()
                        )
                        OutlinedTextField(
                            value = fragmentDelays,
                            onValueChange = { fragmentDelays = it },
                            label = { Text(stringResource(R.string.fragment_delays)) },
                            isError = fragmentDelaySteps == null,
                            modifier = Modifier.fillMaxWidth(), singleLine = true,
                            shape = FieldShape, colors = wingTextFieldColors()
                        )
                        WingField(
                            fragmentMaxSplit, { fragmentMaxSplit = it },
                            stringResource(R.string.fragment_max_split), keyboardType = KeyboardType.Number
                        )
                    }
                    Text(
                        text = stringResource(R.string.fragment_server_hint),
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
internal fun WingField(
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
        shape = FieldShape,
        colors = wingTextFieldColors()
    )
}

@Composable
private fun UuidField(value: String, onValueChange: (String) -> Unit, valid: Boolean) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.uuid)) },
        isError = value.isNotEmpty() && !valid,
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        shape = FieldShape,
        colors = wingTextFieldColors()
    )
}

/** A Mythaia section: feather-marked title above a soft panel of fields. */
@Composable
internal fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        WingSectionTitle(title = title)
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = CardShape,
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
internal fun SwitchRow(
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

/**
 * "Allow insecure" with the danger in plain sight: INSECURE in red capitals
 * beside the switch, and once it is on, what it gives away and the safer
 * way (a pinned certificate, which is checked even with this on).
 */
@Composable
internal fun InsecureSwitch(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                Text(
                    text = stringResource(R.string.allow_insecure),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = stringResource(R.string.insecure_caps),
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    ),
                    color = MaterialTheme.colorScheme.error
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedTrackColor = MaterialTheme.colorScheme.error,
                    checkedThumbColor = MaterialTheme.colorScheme.onError
                )
            )
        }
        if (checked) {
            Surface(
                color = MaterialTheme.colorScheme.errorContainer,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
            ) {
                Row(modifier = Modifier.padding(12.dp)) {
                    Icon(
                        imageVector = Icons.Filled.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(end = 10.dp).size(22.dp)
                    )
                    Column {
                        Text(
                            text = stringResource(R.string.insecure_caps),
                            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.Black),
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                        Text(
                            text = stringResource(R.string.insecure_explained),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DropdownField(
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
