package com.argsment.anywhere.ui.components

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
import com.argsment.anywhere.R

/**
 * Traffic readout as two paper stat tiles (download / upload): slate label
 * over a monospaced numeral. [contentColor] tints the numerals — pass
 * MaterialTheme.colorScheme.onSurface for ink in light mode, bone in dark.
 */
@Composable
fun TrafficStatsRow(
    bytesIn: Long,
    bytesOut: Long,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        TrafficStatTile(
            icon = Icons.Filled.KeyboardArrowDown,
            label = stringResource(R.string.download),
            bytes = bytesIn,
            valueColor = contentColor,
            modifier = Modifier.weight(1f)
        )
        TrafficStatTile(
            icon = Icons.Filled.KeyboardArrowUp,
            label = stringResource(R.string.upload),
            bytes = bytesOut,
            valueColor = contentColor,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun TrafficStatTile(
    icon: ImageVector,
    label: String,
    bytes: Long,
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
                text = Formatter.formatFileSize(context, bytes),
                style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                color = valueColor,
                maxLines = 1
            )
        }
    }
}
