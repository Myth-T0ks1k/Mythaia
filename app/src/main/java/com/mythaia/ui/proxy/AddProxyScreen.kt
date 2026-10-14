package com.mythaia.ui.proxy

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.Subscription
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.SubscriptionDomainHelper
import com.mythaia.ui.components.WingMark
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.viewmodel.VpnViewModel

private enum class ImportMethod(val titleResId: Int, val icon: ImageVector) {
    QR_CODE(R.string.qr_code, Icons.Default.QrCodeScanner),
    LINK(R.string.link, Icons.Default.Link),
    MANUAL(R.string.manual, Icons.Default.Edit);
}

private enum class LinkType(val titleResId: Int) {
    SUBSCRIPTION(R.string.subscription),
    HTTPS_PROXY(R.string.https_proxy),
    HTTP2_PROXY(R.string.http2_proxy);
}

@Composable
fun AddProxyScreen(
    viewModel: VpnViewModel,
    onDismiss: () -> Unit,
    onShowManualAdd: () -> Unit,
    onImport: (ProxyConfiguration) -> Unit,
    onSubscriptionImport: (List<ProxyConfiguration>, Subscription) -> Unit,
    initialLink: String? = null
) {
    val context = LocalContext.current

    // When opened via a deep link, start directly on the Link method with the URL pre-filled.
    // Saveable, so a rotation or a theme switch keeps what was pasted.
    var selectedMethod by rememberSaveable { mutableStateOf<ImportMethod?>(if (initialLink != null) ImportMethod.LINK else null) }
    var linkURL by rememberSaveable(stateSaver = BoundedTextSaver) { mutableStateOf(initialLink ?: "") }
    var linkType by rememberSaveable { mutableStateOf(LinkType.SUBSCRIPTION) }

    // A deep link that arrives while the sheet is already open replaces
    // whatever was typed; without this it was silently dropped.
    LaunchedEffect(initialLink) {
        if (initialLink != null) {
            linkURL = initialLink
            selectedMethod = ImportMethod.LINK
        }
    }
    // The download runs in the view model, so its spinner is read from there.
    val isLoading by viewModel.subscriptionImporting.collectAsState()
    var showLinkError by rememberSaveable { mutableStateOf(false) }
    var linkErrorMessage by rememberSaveable { mutableStateOf("") }
    var showQrScanner by rememberSaveable { mutableStateOf(false) }

    // A TV has no camera, so offering to scan a QR code there would open a
    // screen that can only fail. Checked by feature rather than by form factor:
    // a tablet without a camera is in the same position.
    val availableMethods = remember(context) {
        val hasCamera = context.packageManager
            .hasSystemFeature(android.content.pm.PackageManager.FEATURE_CAMERA_ANY)
        if (hasCamera) ImportMethod.entries else ImportMethod.entries.filter { it != ImportMethod.QR_CODE }
    }
    var showRemnawaveHWIDAlert by rememberSaveable { mutableStateOf(false) }
    var pendingSubscriptionURL by rememberSaveable { mutableStateOf("") }
    // Proxy links from a pasted list, held while the HWID prompt for its
    // subscription is up: importing one closes the sheet, prompt and all.
    var heldProxyLinks by rememberSaveable(stateSaver = BoundedLinksSaver) { mutableStateOf<List<String>>(emptyList()) }

    // Fronting for the subscription download: shown only for an http(s)
    // link imported as a subscription, folded away until wanted.
    var frontingExpanded by rememberSaveable { mutableStateOf(false) }
    var frontSni by rememberSaveable { mutableStateOf("") }
    var frontTargetsText by rememberSaveable { mutableStateOf("") }
    fun frontTargets(): List<String> =
        frontTargetsText.split('\n', ',', ';').map { it.trim() }.filter { it.isNotEmpty() }
    // A group name the link carried (`name=`), kept once the link is unpacked,
    // with the URL it belongs to: a different link pasted after it is not named by it.
    var linkGroupName by rememberSaveable { mutableStateOf<String?>(null) }
    var linkGroupNameUrl by rememberSaveable { mutableStateOf("") }

    // A link with its fronting written in (`…#front=…&sni=…` or
    // mythaia://import?url=…&front=…): unpacked into the fields below, so the
    // URL shows as the panel gave it and the fronting can be checked or edited
    // before anything is downloaded.
    LaunchedEffect(linkURL) {
        val single = com.mythaia.data.network.LinkExtractor.extract(linkURL.trim()).singleOrNull()
            ?: return@LaunchedEffect
        val link = com.mythaia.data.network.SubscriptionLink.parse(single) ?: return@LaunchedEffect
        if (!link.isFronted) return@LaunchedEffect
        linkType = LinkType.SUBSCRIPTION
        frontSni = link.frontSni.orEmpty()
        frontTargetsText = link.frontTargets.joinToString("\n")
        linkGroupName = link.name
        linkGroupNameUrl = link.url
        frontingExpanded = true
        linkURL = link.url
    }

    val isContinueDisabled = when (selectedMethod) {
        ImportMethod.LINK -> linkURL.isBlank() || isLoading
        null -> true
        else -> false
    }

    // Auto-paste from clipboard when link method selected. Accepts a bare
    // http:// URL so users can paste a raw subscription endpoint.
    LaunchedEffect(selectedMethod) {
        if (selectedMethod == ImportMethod.LINK && linkURL.isEmpty()) {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString()?.trim()
            if (clip != null) {
                // A whole message, a list, or another client's import link: take
                // the links out of it. JSON and WireGuard INI go in as they are.
                val links = com.mythaia.data.network.LinkExtractor.extract(clip)
                linkURL = when {
                    com.mythaia.data.network.XrayJsonImporter.looksLikeJson(clip) -> clip
                    ProxyConfiguration.looksLikeWireGuardConfig(clip) -> clip
                    links.isNotEmpty() -> links.joinToString("\n")
                    else -> linkURL
                }
            }
        }
    }

    // In the view model's scope, not this sheet's: the host closes the sheet
    // on the first proxy of a pasted list, and a download launched here was
    // cancelled with it — and the subscription silently never added.
    fun fetchSubscription(url: String, withRemnawaveHWID: Boolean) {
        // Fronting the link carries (from a QR code or a pasted list, which
        // skip the fields) fills in what the fields leave empty.
        val link = com.mythaia.data.network.SubscriptionLink.parse(url)
        viewModel.importSubscription(
            url = link?.url ?: url,
            withRemnawaveHWID = withRemnawaveHWID,
            frontSni = frontSni.trim().takeIf { it.isNotEmpty() } ?: link?.frontSni,
            frontTargets = frontTargets().ifEmpty { link?.frontTargets.orEmpty() },
            onImported = onSubscriptionImport,
            onFailed = { message ->
                linkErrorMessage = message
                showLinkError = true
            },
            name = link?.name ?: linkGroupName?.takeIf { linkGroupNameUrl == (link?.url ?: url) }
        )
    }

    /**
     * Adds [configs] in one write and hands the last to [onImport], which
     * closes the sheet. One onImport per server meant one full save of the
     * store each: a list of thousands froze the app.
     */
    fun importAll(configs: List<ProxyConfiguration>) {
        if (configs.isEmpty()) return
        if (configs.size > 1) viewModel.addConfigurations(configs.dropLast(1))
        onImport(configs.last())
    }

    /** Adds every link that parses; returns how many did not. */
    fun importProxyLinks(links: List<String>): Int {
        var failures = 0
        val parsed = links.mapNotNull { link ->
            runCatching { ProxyConfiguration.fromUrl(link) }
                .onFailure { failures++ }
                .getOrNull()
        }
        importAll(parsed)
        return failures
    }

    fun importFromString(string: String, fromQr: Boolean) {
        val trimmed = string.trim()

        // Xray / v2ray JSON: a whole config or one outbound. Every proxy
        // outbound in it is imported.
        if (com.mythaia.data.network.XrayJsonImporter.looksLikeJson(trimmed)) {
            try {
                importAll(com.mythaia.data.network.XrayJsonImporter.parse(trimmed))
            } catch (e: Exception) {
                linkErrorMessage = e.message ?: context.getString(R.string.invalid_url)
                showLinkError = true
            }
            return
        }

        // A WireGuard peer hands out a wg-quick INI, not a link, so a paste is
        // recognised by its shape before any scheme matching happens.
        if (ProxyConfiguration.looksLikeWireGuardConfig(trimmed)) {
            try {
                onImport(ProxyConfiguration.fromWireGuardConfig(trimmed))
            } catch (e: Exception) {
                linkErrorMessage = e.message ?: context.getString(R.string.invalid_url)
                showLinkError = true
            }
            return
        }

        // Several links at once (a pasted list or message): every proxy link is
        // added, and the first subscription URL, if any, is fetched.
        val extracted = com.mythaia.data.network.LinkExtractor.extract(trimmed)
        if (extracted.size > 1) {
            val proxies = extracted.filter { !it.startsWith("http://") && !it.startsWith("https://") }
            val subscription = extracted.firstOrNull { it.startsWith("http://") || it.startsWith("https://") }
            // The subscription first: its download outlives the sheet, which
            // the host closes on the first proxy link added below.
            if (subscription != null) importFromString(subscription, fromQr)
            if (showRemnawaveHWIDAlert) {
                // The prompt for it would close with the sheet: the proxies
                // wait for the answer.
                heldProxyLinks = proxies
                return
            }
            val failures = importProxyLinks(proxies)
            if (subscription == null && failures > 0 && failures == proxies.size) {
                linkErrorMessage = context.getString(R.string.invalid_url)
                showLinkError = true
            }
            return
        }
        if (extracted.size == 1 && extracted[0] != trimmed) {
            importFromString(extracted[0], fromQr)
            return
        }

        val isHTTP = trimmed.startsWith("http://") || trimmed.startsWith("https://")
        // QR codes don't expose the segmented picker, so default to subscription
        // for any http(s) URL.
        val effectiveLinkType = if (fromQr) LinkType.SUBSCRIPTION else linkType

        // A definite single-proxy URL is one whose scheme is parsable and is NOT
        // http(s) — for http(s) URLs the user's link-type selection decides.
        val isDefiniteProxy = ProxyConfiguration.canParseUrl(trimmed) && !isHTTP

        // A link with fronting written in is a subscription whatever the picker says.
        val isFrontedSubscription = com.mythaia.data.network.SubscriptionLink.isFrontedLink(trimmed)

        if (isDefiniteProxy || (isHTTP && effectiveLinkType != LinkType.SUBSCRIPTION && !isFrontedSubscription)) {
            val naiveProtocol: OutboundProtocol? = when (effectiveLinkType) {
                LinkType.HTTPS_PROXY -> OutboundProtocol.NAIVE_HTTP11
                LinkType.HTTP2_PROXY -> OutboundProtocol.NAIVE_HTTP2
                LinkType.SUBSCRIPTION -> null
            }
            try {
                val config = ProxyConfiguration.fromUrl(trimmed, naiveProtocol)
                onImport(config)
            } catch (e: Exception) {
                linkErrorMessage = e.message ?: context.getString(
                    if (fromQr) R.string.invalid_qr_code else R.string.invalid_url
                )
                showLinkError = true
            }
        } else {
            // Treat as subscription URL. Some panels require the HWID header to
            // release configs — prompt the user to enable it first if needed.
            val requiresRemnawaveHWID = SubscriptionDomainHelper.shouldRequireRemnawaveHWID(
                com.mythaia.data.network.SubscriptionLink.parse(trimmed)?.url ?: trimmed
            )
            if (requiresRemnawaveHWID && !viewModel.remnawaveHWIDEnabled) {
                pendingSubscriptionURL = trimmed
                showRemnawaveHWIDAlert = true
                return
            }
            fetchSubscription(trimmed, withRemnawaveHWID = requiresRemnawaveHWID)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(20.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            WingMark(
                modifier = Modifier.size(24.dp),
                color = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.width(10.dp))
            Text(
                text = stringResource(R.string.add_proxy),
                style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = onDismiss) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = stringResource(R.string.cancel),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        availableMethods.forEach { method ->
            val isSelected = selectedMethod == method
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                shape = RoundedCornerShape(14.dp),
                color = if (isSelected) {
                    MaterialTheme.colorScheme.primary.copy(alpha = 0.08f)
                } else {
                    MaterialTheme.colorScheme.surface
                },
                border = BorderStroke(
                    width = 1.dp,
                    color = if (isSelected) {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.45f)
                    } else {
                        MaterialTheme.colorScheme.outline
                    }
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable {
                            selectedMethod = if (isSelected) null else method
                        }
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = method.icon,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = stringResource(method.titleResId),
                        style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Medium),
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    if (isSelected) {
                        Icon(
                            imageVector = Icons.Default.Check,
                            contentDescription = null,
                            modifier = Modifier.size(20.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }

        if (selectedMethod == ImportMethod.LINK) {
            Spacer(modifier = Modifier.height(12.dp))

            val trimmedUrl = linkURL.trim()
            if (trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
                SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                    LinkType.entries.forEachIndexed { index, type ->
                        SegmentedButton(
                            selected = linkType == type,
                            onClick = { linkType = type },
                            shape = SegmentedButtonDefaults.itemShape(index, LinkType.entries.size),
                            colors = SegmentedButtonDefaults.colors(
                                activeContainerColor = MaterialTheme.colorScheme.primaryContainer,
                                activeContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                                activeBorderColor = MaterialTheme.colorScheme.outline,
                                inactiveContainerColor = MaterialTheme.colorScheme.surface,
                                inactiveContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                                inactiveBorderColor = MaterialTheme.colorScheme.outline
                            )
                        ) {
                            Text(stringResource(type.titleResId))
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            OutlinedTextField(
                value = linkURL,
                onValueChange = { linkURL = it },
                label = { Text(stringResource(R.string.link)) },
                modifier = Modifier.fillMaxWidth(),
                // Several links can come in at once from a pasted message.
                maxLines = 4,
                shape = RoundedCornerShape(14.dp),
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                colors = wingTextFieldColors()
            )
            Text(
                text = stringResource(R.string.supports_proxy_link),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 6.dp, start = 4.dp)
            )

            if ((trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) &&
                linkType == LinkType.SUBSCRIPTION
            ) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { frontingExpanded = !frontingExpanded }
                        .padding(vertical = 6.dp, horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.fronting),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f)
                    )
                    Icon(
                        imageVector = if (frontingExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
                if (frontingExpanded) {
                    Text(
                        text = stringResource(R.string.fronting_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 4.dp, bottom = 4.dp)
                    )
                    Text(
                        text = stringResource(R.string.fronting_link_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 4.dp, bottom = 8.dp)
                    )
                    OutlinedTextField(
                        value = frontSni,
                        onValueChange = { frontSni = it },
                        label = { Text(stringResource(R.string.front_sni)) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        shape = RoundedCornerShape(14.dp),
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                        colors = wingTextFieldColors()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = frontTargetsText,
                        onValueChange = { frontTargetsText = it },
                        label = { Text(stringResource(R.string.front_targets)) },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2,
                        maxLines = 5,
                        shape = RoundedCornerShape(14.dp),
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                        colors = wingTextFieldColors()
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Button(
            onClick = {
                when (selectedMethod) {
                    ImportMethod.QR_CODE -> showQrScanner = true
                    ImportMethod.LINK -> importFromString(linkURL, fromQr = false)
                    ImportMethod.MANUAL -> onShowManualAdd()
                    null -> {}
                }
            },
            enabled = !isContinueDisabled,
            modifier = Modifier
                .fillMaxWidth()
                .height(50.dp),
            shape = RoundedCornerShape(14.dp)
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            } else {
                Text(
                    text = stringResource(R.string.continue_action),
                    style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold)
                )
            }
        }
    }

    if (showQrScanner) {
        com.mythaia.ui.scanner.QrScannerScreen(
            onResult = { code ->
                showQrScanner = false
                importFromString(code, fromQr = true)
            },
            onDismiss = { showQrScanner = false }
        )
    }

    if (showLinkError) {
        AlertDialog(
            onDismissRequest = { showLinkError = false },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.import_failed)) },
            text = { Text(linkErrorMessage) },
            confirmButton = {
                TextButton(onClick = { showLinkError = false }) {
                    Text(stringResource(R.string.ok))
                }
            }
        )
    }

    // Remnawave HWID opt-in prompt for subscription URLs that require a
    // device-bound `x-hwid` header.
    if (showRemnawaveHWIDAlert) {
        // Either answer lets the proxy links held back for the prompt in.
        fun dismissAndFlush() {
            showRemnawaveHWIDAlert = false
            val held = heldProxyLinks
            heldProxyLinks = emptyList()
            importProxyLinks(held)
        }
        AlertDialog(
            onDismissRequest = { dismissAndFlush() },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.remnawave_hwid)) },
            text = { Text(stringResource(R.string.remnawave_hwid_prompt)) },
            confirmButton = {
                TextButton(onClick = {
                    // The dialog is presented as enabling the setting — persist it
                    // so the user isn't re-prompted and later updates send the HWID.
                    viewModel.remnawaveHWIDEnabled = true
                    fetchSubscription(pendingSubscriptionURL, withRemnawaveHWID = true)
                    dismissAndFlush()
                }) {
                    Text(stringResource(R.string.enable))
                }
            },
            dismissButton = {
                TextButton(onClick = { dismissAndFlush() }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

/**
 * The most pasted text the sheet keeps across a rotation or a trip to the
 * background. The saved state goes through a Binder transaction with a
 * limit of about a megabyte: a list of thousands of links went over it, and
 * the activity crashed with TransactionTooLargeException when it stopped.
 * Longer text is simply not restored.
 */
private const val MAX_SAVED_TEXT = 64 * 1024

private val BoundedTextSaver = Saver<String, String>(
    save = { if (it.length <= MAX_SAVED_TEXT) it else "" },
    restore = { it }
)

private val BoundedLinksSaver = Saver<List<String>, ArrayList<String>>(
    save = { links -> if (links.sumOf { it.length } <= MAX_SAVED_TEXT) ArrayList(links) else ArrayList() },
    restore = { it }
)
