package com.mythaia.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyResult
import com.mythaia.ui.theme.Azure
import com.mythaia.ui.theme.AzureDeep
import com.mythaia.ui.theme.LightAzure
import com.mythaia.ui.theme.LocalMythaiaDarkTheme
import com.mythaia.ui.theme.WarningDark
import com.mythaia.ui.theme.WarningLight

/**
 * A server row in the Wing language.
 *
 * No hairline boxes: a soft tinted panel, a feather-blue bar down the start
 * edge when the row is the one in use, the name set large, the endpoint in
 * mono underneath, and the protocol as small pills. The latency sits on the
 * trailing edge as a coloured chip so the eye can scan a column of them.
 */
@Composable
fun ProxyCardContent(
    configuration: ProxyConfiguration,
    isSelected: Boolean,
    latency: LatencyResult?,
    modifier: Modifier = Modifier
) {
    val panel = if (isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.55f)
    else MaterialTheme.colorScheme.surfaceContainerLow

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        color = panel
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // The accent bar: azure only while selected, otherwise a whisper
            // of the panel so the text column keeps its alignment.
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .height(56.dp)
                    .padding(vertical = 6.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(
                        if (isSelected) Brush.verticalGradient(listOf(LightAzure, Azure))
                        else Brush.verticalGradient(listOf(Color.Transparent, Color.Transparent))
                    )
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 12.dp, top = 12.dp, bottom = 12.dp, end = 8.dp)
            ) {
                Text(
                    text = configuration.name,
                    style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                // The provider's serverDescription, under the name as Happ shows it.
                configuration.description?.let { description ->
                    Text(
                        text = description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = configuration.displayEndpoint,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ProtocolPill(configuration.outboundProtocol.displayName)
                    val usesStreamTransport = configuration.outboundProtocol == OutboundProtocol.VLESS ||
                        configuration.outboundProtocol == OutboundProtocol.VMESS ||
                        configuration.outboundProtocol == OutboundProtocol.TROJAN
                    if (usesStreamTransport && configuration.transport != "tcp") {
                        ProtocolPill(configuration.transport.uppercase())
                    }
                    val security = configuration.security.uppercase()
                    if (security != "NONE") ProtocolPill(security)
                    if (configuration.flow?.contains("vision", ignoreCase = true) == true) {
                        ProtocolPill("Vision")
                    }
                    if (configuration.skipsCertificateCheck) InsecurePill()
                }
            }
            Box(modifier = Modifier.padding(end = 14.dp)) {
                LatencyBadge(latency = latency)
            }
        }
    }
}

/** Red on the row of a server whose certificate is not checked ("allow insecure"). */
@Composable
private fun InsecurePill() {
    Text(
        text = stringResource(R.string.insecure_caps),
        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
        color = MaterialTheme.colorScheme.onError,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.error)
            .padding(horizontal = 6.dp, vertical = 2.dp)
    )
}

/** A tiny label pill for protocol facts. */
@Composable
private fun ProtocolPill(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.06f))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    )
}

/**
 * The latency chip. Azure for a good number (the brand's affirmative colour;
 * there is no green in the Wing palette), warning orange for a fair one,
 * error red for a poor one, and quiet slate text for anything that is not a
 * number.
 */
@Composable
fun LatencyBadge(latency: LatencyResult?, modifier: Modifier = Modifier) {
    when (latency) {
        is LatencyResult.Testing -> {
            CircularProgressIndicator(
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = modifier.size(20.dp),
                strokeWidth = 2.dp
            )
        }
        is LatencyResult.Success -> {
            val color = when {
                latency.ms < 300 -> MaterialTheme.colorScheme.primary
                latency.ms < 600 -> if (LocalMythaiaDarkTheme.current) WarningDark else WarningLight
                else -> MaterialTheme.colorScheme.error
            }
            Row(
                modifier = modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(color.copy(alpha = 0.12f))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(RoundedCornerShape(3.dp))
                        .background(color)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = stringResource(R.string.latency_ms, latency.ms),
                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                    color = color
                )
            }
        }
        is LatencyResult.Insecure -> QuietBadge(stringResource(R.string.insecure), modifier)
        is LatencyResult.Failed -> QuietBadge(stringResource(R.string.timeout), modifier)
        null -> {}
    }
}

@Composable
private fun QuietBadge(text: String, modifier: Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.06f))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    )
}

/**
 * A round icon tile on the brand gradient; the settings screens' glyphs.
 * Shared so every list in the app says "Mythaia" the same way.
 */
@Composable
fun WingIconTile(
    modifier: Modifier = Modifier,
    size: androidx.compose.ui.unit.Dp = 34.dp,
    content: @Composable () -> Unit
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(RoundedCornerShape(size / 2))
            .background(Brush.linearGradient(listOf(LightAzure, Azure, AzureDeep))),
        contentAlignment = Alignment.Center
    ) {
        content()
    }
}

/** The Mythaia section header: a small feather mark and a sentence-case title. */
@Composable
fun WingSectionTitle(title: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(start = 6.dp, top = 6.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        WingMark(modifier = Modifier.size(14.dp), color = MaterialTheme.colorScheme.primary)
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

/** A soft panel that groups rows, with no outline. */
@Composable
fun WingPanel(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow
    ) {
        Column { content() }
    }
}
