package com.argsment.anywhere.ui.proxy

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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import com.argsment.anywhere.R
import com.argsment.anywhere.data.model.OutboundProtocol
import com.argsment.anywhere.data.model.Subscription
import com.argsment.anywhere.data.model.ProxyConfiguration
import com.argsment.anywhere.data.network.SubscriptionDomainHelper
import com.argsment.anywhere.data.network.SubscriptionFetcher
import com.argsment.anywhere.ui.components.WingMark
import com.argsment.anywhere.ui.components.wingTextFieldColors
import com.argsment.anywhere.viewmodel.VpnViewModel
import kotlinx.coroutines.launch
import java.net.URL

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
    val scope = rememberCoroutineScope()

    // When opened via a deep link, start directly on the Link method with the URL pre-filled.
    var selectedMethod by remember { mutableStateOf<ImportMethod?>(if (initialLink != null) ImportMethod.LINK else null) }
    var linkURL by remember { mutableStateOf(initialLink ?: "") }
    var linkType by remember { mutableStateOf(LinkType.SUBSCRIPTION) }
    var isLoading by remember { mutableStateOf(false) }
    var showLinkError by remember { mutableStateOf(false) }
    var linkErrorMessage by remember { mutableStateOf("") }
    var showQrScanner by remember { mutableStateOf(false) }
    var showRemnawaveHWIDAlert by remember { mutableStateOf(false) }
    var pendingSubscriptionURL by remember { mutableStateOf("") }

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
            if (clip != null && (ProxyConfiguration.canParseUrl(clip) || clip.startsWith("http://"))) {
                linkURL = clip
            }
        }
    }

    fun fetchSubscription(url: String, withRemnawaveHWID: Boolean) {
        isLoading = true
        scope.launch {
            try {
                val hwid = if (withRemnawaveHWID) viewModel.deviceIdentifier else null
                val result = SubscriptionFetcher.fetch(url, remnawaveHWID = hwid)
                val name = result.name
                    ?: runCatching { URL(url).host }.getOrNull()
                    ?: context.getString(R.string.subscription)
                val subscription = Subscription(
                    name = name,
                    url = url,
                    lastUpdate = System.currentTimeMillis(),
                    upload = result.upload,
                    download = result.download,
                    total = result.total,
                    expire = result.expire
                )
                onSubscriptionImport(result.configurations, subscription)
            } catch (e: Exception) {
                linkErrorMessage = e.message ?: context.getString(R.string.import_failed)
                showLinkError = true
            }
            isLoading = false
        }
    }

    fun importFromString(string: String, fromQr: Boolean) {
        val trimmed = string.trim()
        val isHTTP = trimmed.startsWith("http://") || trimmed.startsWith("https://")
        // QR codes don't expose the segmented picker, so default to subscription
        // for any http(s) URL.
        val effectiveLinkType = if (fromQr) LinkType.SUBSCRIPTION else linkType

        // A definite single-proxy URL is one whose scheme is parsable and is NOT
        // http(s) — for http(s) URLs the user's link-type selection decides.
        val isDefiniteProxy = ProxyConfiguration.canParseUrl(trimmed) && !isHTTP

        if (isDefiniteProxy || (isHTTP && effectiveLinkType != LinkType.SUBSCRIPTION)) {
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
            val requiresRemnawaveHWID = SubscriptionDomainHelper.shouldRequireRemnawaveHWID(trimmed)
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

        ImportMethod.entries.forEach { method ->
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
                singleLine = true,
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
        com.argsment.anywhere.ui.scanner.QrScannerScreen(
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
        AlertDialog(
            onDismissRequest = { showRemnawaveHWIDAlert = false },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.remnawave_hwid)) },
            text = { Text(stringResource(R.string.remnawave_hwid_prompt)) },
            confirmButton = {
                TextButton(onClick = {
                    showRemnawaveHWIDAlert = false
                    // The dialog is presented as enabling the setting — persist it
                    // so the user isn't re-prompted and later updates send the HWID.
                    viewModel.remnawaveHWIDEnabled = true
                    fetchSubscription(pendingSubscriptionURL, withRemnawaveHWID = true)
                }) {
                    Text(stringResource(R.string.enable))
                }
            },
            dismissButton = {
                TextButton(onClick = { showRemnawaveHWIDAlert = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}
