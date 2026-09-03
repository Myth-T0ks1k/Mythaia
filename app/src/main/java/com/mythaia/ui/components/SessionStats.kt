package com.mythaia.ui.components

import android.text.format.Formatter
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.mythaia.R
import java.util.Locale

/**
 * The live session readout: rate first, total underneath, and how long the
 * tunnel has been up.
 *
 * Rate is the headline because it is the number that changes — a total that
 * only ever grows says little about whether traffic is moving right now.
 */
@Composable
fun SessionStatsRow(
    bytesIn: Long,
    bytesOut: Long,
    downloadSpeed: Long,
    uploadSpeed: Long,
    uptimeSeconds: Long,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            SpeedTile(
                icon = Icons.Filled.KeyboardArrowDown,
                label = stringResource(R.string.download),
                bytesPerSecond = downloadSpeed,
                total = bytesIn,
                valueColor = contentColor,
                modifier = Modifier.weight(1f)
            )
            SpeedTile(
                icon = Icons.Filled.KeyboardArrowUp,
                label = stringResource(R.string.upload),
                bytesPerSecond = uploadSpeed,
                total = bytesOut,
                valueColor = contentColor,
                modifier = Modifier.weight(1f)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surface,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Schedule,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.connected_for),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = formatUptime(uptimeSeconds),
                    style = MaterialTheme.typography.titleSmall
                        .copy(fontFamily = FontFamily.Monospace),
                    color = contentColor
                )
            }
        }
    }
}

@Composable
private fun SpeedTile(
    icon: ImageVector,
    label: String,
    bytesPerSecond: Long,
    total: Long,
    valueColor: Color,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                // Formatter picks the unit, so a busy link reads "1.2 MB/s"
                // rather than seven digits of bytes.
                text = stringResource(
                    R.string.per_second,
                    Formatter.formatShortFileSize(context, bytesPerSecond)
                ),
                style = MaterialTheme.typography.titleMedium
                    .copy(fontFamily = FontFamily.Monospace),
                color = valueColor,
                maxLines = 1
            )
            Text(
                text = Formatter.formatFileSize(context, total),
                style = MaterialTheme.typography.bodySmall
                    .copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1
            )
        }
    }
}

/**
 * `H:MM:SS`, or `MM:SS` under an hour.
 *
 * Root locale so the digits are the ASCII ones the monospaced face aligns, and
 * so the layout does not shift between locales.
 */
private fun formatUptime(seconds: Long): String {
    val safe = seconds.coerceAtLeast(0)
    val hours = safe / 3600
    val minutes = (safe % 3600) / 60
    val secs = safe % 60
    return if (hours > 0) {
        String.format(Locale.ROOT, "%d:%02d:%02d", hours, minutes, secs)
    } else {
        String.format(Locale.ROOT, "%02d:%02d", minutes, secs)
    }
}
