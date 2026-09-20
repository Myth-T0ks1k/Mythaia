package com.mythaia.desktop.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.mythaia.data.network.LatencyResult
import com.mythaia.desktop.tr

/** The Mythaia mark: three feather strokes. */
@Composable
fun WingMark(modifier: Modifier = Modifier, color: Color, strokeScale: Float = 1f) {
    Canvas(modifier = modifier) {
        val s = minOf(size.width, size.height) / 100f
        fun feather(cx: Float, cy: Float, ex: Float, ey: Float, width: Float) {
            val path = Path().apply {
                moveTo(20f * s, 82f * s)
                quadraticTo(cx * s, cy * s, ex * s, ey * s)
            }
            drawPath(path, color, style = Stroke(width = width * s * strokeScale, cap = StrokeCap.Round))
        }
        feather(21f, 32f, 82f, 20f, 8.5f)
        feather(29f, 47f, 69f, 38f, 8.0f)
        feather(36f, 61f, 57f, 55f, 7.5f)
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

/** A round icon tile on the brand gradient. */
@Composable
fun WingIconTile(modifier: Modifier = Modifier, size: Dp = 34.dp, content: @Composable () -> Unit) {
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

/** Latency as a colored chip: azure when fast, orange when fair, red when slow. */
@Composable
fun LatencyBadge(latency: LatencyResult?, modifier: Modifier = Modifier) {
    when (latency) {
        is LatencyResult.Testing -> CircularProgressIndicator(
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = modifier.size(18.dp),
            strokeWidth = 2.dp
        )
        is LatencyResult.Success -> {
            val color = when {
                latency.ms < 300 -> MaterialTheme.colorScheme.primary
                latency.ms < 600 -> if (LocalDarkTheme.current) WarningDark else WarningLight
                else -> MaterialTheme.colorScheme.error
            }
            Row(
                modifier = modifier
                    .clip(RoundedCornerShape(10.dp))
                    .background(color.copy(alpha = 0.12f))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(modifier = Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(color))
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = tr("latency_ms", latency.ms),
                    style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                    color = color
                )
            }
        }
        is LatencyResult.Insecure -> QuietBadge(tr("insecure"), modifier)
        is LatencyResult.Failed -> QuietBadge(tr("timeout"), modifier)
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

/** A settings row with a switch on the right. */
@Composable
fun SwitchRow(title: String, checked: Boolean, subtitle: String? = null, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(horizontal = 18.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f).padding(end = 16.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
fun wingTextFieldColors(): TextFieldColors = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = MaterialTheme.colorScheme.primary,
    unfocusedBorderColor = MaterialTheme.colorScheme.outline,
    focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest
)

val FieldShape = RoundedCornerShape(16.dp)

/** Whether a text field has keyboard focus, so window-level shortcuts stay out of the way of typing. */
object UiFocus {
    val textField = kotlinx.coroutines.flow.MutableStateFlow(false)
}

/** A single-line field in the Wing shape. */
@Composable
fun WingField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier.fillMaxWidth(),
    placeholder: String? = null,
    singleLine: Boolean = true,
    minLines: Int = 1,
    enabled: Boolean = true
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        modifier = modifier.onFocusChanged { UiFocus.textField.value = it.isFocused },
        singleLine = singleLine,
        minLines = minLines,
        enabled = enabled,
        shape = FieldShape,
        colors = wingTextFieldColors()
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DropdownField(
    label: String,
    selectedValue: String,
    options: List<Pair<String, String>>,
    modifier: Modifier = Modifier.fillMaxWidth(),
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val displayText = options.firstOrNull { it.first == selectedValue }?.second ?: selectedValue
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }, modifier = modifier) {
        OutlinedTextField(
            value = displayText,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable),
            shape = FieldShape,
            colors = wingTextFieldColors()
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (value, text) ->
                DropdownMenuItem(text = { Text(text) }, onClick = { onSelect(value); expanded = false })
            }
        }
    }
}

/** Human sizes: 12,3 МБ. */
fun formatBytes(bytes: Long): String {
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024; unit++
    }
    return if (unit == 0) "${bytes} B" else String.format("%.1f %s", value, units[unit])
}

fun formatDuration(ms: Long): String {
    val total = ms / 1000
    val h = total / 3600
    val m = (total % 3600) / 60
    val s = total % 60
    return if (h > 0) String.format("%d:%02d:%02d", h, m, s) else String.format("%02d:%02d", m, s)
}

fun formatDateTime(epochMillis: Long): String {
    val date = java.time.Instant.ofEpochMilli(epochMillis).atZone(java.time.ZoneId.systemDefault())
    return date.format(java.time.format.DateTimeFormatter.ofPattern("dd.MM HH:mm"))
}

fun formatDate(epochMillis: Long): String {
    val date = java.time.Instant.ofEpochMilli(epochMillis).atZone(java.time.ZoneId.systemDefault())
    return date.format(java.time.format.DateTimeFormatter.ofPattern("dd.MM.yyyy"))
}
