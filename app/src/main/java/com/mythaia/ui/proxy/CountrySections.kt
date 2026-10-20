package com.mythaia.ui.proxy

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledIconToggleButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.country.CountryGrouping
import com.mythaia.data.country.CountrySection
import com.mythaia.data.country.ServerCountry
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyResult

/**
 * [configs] in country sections, or null when that would show nothing new:
 * grouping is off, or the list is all one country (or none).
 *
 * With latency sort on, the country with the fastest server comes first;
 * otherwise countries go by name and the unplaced servers last.
 */
@Composable
fun rememberCountrySections(
    configs: List<ProxyConfiguration>,
    enabled: Boolean,
    sortByLatency: Boolean,
    latencies: Map<java.util.UUID, LatencyResult>,
    geoIpGeneration: Int,
    countryOf: (ProxyConfiguration) -> String?
): List<CountrySection<ProxyConfiguration>>? {
    val byName = remember(configs, enabled, geoIpGeneration) {
        if (!enabled) null else CountryGrouping.sections(configs, countryOf).takeIf { it.size >= 2 }
    }
    return remember(byName, sortByLatency, if (sortByLatency) latencies else null) {
        if (byName == null || !sortByLatency) byName
        else byName.map { section ->
            section.copy(
                items = section.items.sortedBy {
                    (latencies[it.id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE
                }
            )
        }.sortedBy { section ->
            (latencies[section.items.first().id] as? LatencyResult.Success)?.ms ?: Int.MAX_VALUE
        }
    }
}

/** "🇩🇪 Germany", or the globe and "Other" for the servers nothing could place. */
@Composable
fun countryLabel(code: String?): String =
    if (code == null) "🌐 " + stringResource(R.string.country_other)
    else "${ServerCountry.flag(code)} ${CountryGrouping.displayName(code)}"

/**
 * A country section's header: flag, name and count, and on the trailing
 * edge a speed test for the country, Auto within it, and the fold arrow.
 * The whole row folds the section.
 */
@Composable
fun CountryHeader(
    code: String?,
    count: Int,
    collapsed: Boolean,
    autoActive: Boolean,
    autoBusy: Boolean,
    onToggle: () -> Unit,
    onPing: () -> Unit,
    onAuto: (() -> Unit)?,
    modifier: Modifier = Modifier
) {
    val label = countryLabel(code)
    val state = stringResource(if (collapsed) R.string.country_collapsed else R.string.country_expanded)
    Surface(
        onClick = onToggle,
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.background,
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                role = Role.Button
                stateDescription = state
            }
    ) {
        Row(
            modifier = Modifier.padding(start = 8.dp, end = 2.dp, top = 2.dp, bottom = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold),
                color = MaterialTheme.colorScheme.onBackground,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = count.toString(),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.weight(1f))
            IconButton(onClick = onPing) {
                Icon(
                    imageVector = Icons.Default.Speed,
                    contentDescription = stringResource(R.string.country_ping, label),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
            }
            if (onAuto != null) {
                FilledIconToggleButton(
                    checked = autoActive,
                    onCheckedChange = { onAuto() },
                    colors = IconButtonDefaults.filledIconToggleButtonColors(
                        containerColor = MaterialTheme.colorScheme.background,
                        contentColor = MaterialTheme.colorScheme.primary,
                        checkedContainerColor = MaterialTheme.colorScheme.primaryContainer,
                        checkedContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                ) {
                    if (autoBusy && autoActive) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    } else {
                        Icon(
                            imageVector = Icons.Default.Bolt,
                            contentDescription = stringResource(R.string.auto_in_country, label),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }
            Icon(
                imageVector = if (collapsed) Icons.Default.ExpandMore else Icons.Default.ExpandLess,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 8.dp).size(22.dp)
            )
        }
    }
}
