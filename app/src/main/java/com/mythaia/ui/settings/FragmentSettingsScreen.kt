package com.mythaia.ui.settings

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import com.mythaia.R
import com.mythaia.data.model.FragmentSettings
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.viewmodel.VpnViewModel

/**
 * Tunnel-wide ClientHello fragmentation: on/off, bytes per record, and the
 * pause between records. A server whose share link carried its own `fragment=`
 * ignores these and uses its own.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FragmentSettingsScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    val stored = remember { viewModel.fragmentSettings }
    var managedBy by remember {
        mutableStateOf(viewModel.managedSettings()[com.mythaia.data.network.ProviderKeys.AppSettings.GROUP_FRAGMENT])
    }

    var enabled by remember { mutableStateOf(stored.isEnabled) }
    var minLength by remember { mutableStateOf(stored.minLength.toString()) }
    var maxLength by remember { mutableStateOf(stored.maxLength.toString()) }
    var minInterval by remember { mutableStateOf(stored.minInterval.toString()) }
    var maxInterval by remember { mutableStateOf(stored.maxInterval.toString()) }

    // Every field writes through immediately, so leaving the screen by any route
    // — back gesture, system back, process death — keeps what was typed. A blank
    // or non-numeric field falls back to the default rather than to zero.
    fun persist() {
        viewModel.fragmentSettings = FragmentSettings(
            isEnabled = enabled,
            minLength = minLength.toIntOrNull() ?: FragmentSettings.DEFAULT_MIN_LENGTH,
            maxLength = maxLength.toIntOrNull() ?: FragmentSettings.DEFAULT_MAX_LENGTH,
            minInterval = minInterval.toIntOrNull() ?: FragmentSettings.DEFAULT_MIN_INTERVAL,
            maxInterval = maxInterval.toIntOrNull() ?: FragmentSettings.DEFAULT_MAX_INTERVAL
        )
        managedBy = null
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.fragment_hello)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            managedBy?.let { providerName ->
                Text(
                    text = stringResource(R.string.settings_managed_by, providerName),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
            GroupCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.fragment_hello_enable),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    Switch(
                        checked = enabled,
                        onCheckedChange = {
                            enabled = it
                            persist()
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
                            checkedTrackColor = MaterialTheme.colorScheme.primary,
                            uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
                            uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
                            uncheckedBorderColor =
                                MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
                        )
                    )
                }
            }

            Text(
                text = stringResource(R.string.fragment_hello_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp)
            )

            GroupCard {
                RangeRow(
                    label = stringResource(R.string.fragment_length),
                    low = minLength,
                    high = maxLength,
                    enabled = enabled,
                    onLowChange = { minLength = it; persist() },
                    onHighChange = { maxLength = it; persist() }
                )
                HorizontalDivider(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    thickness = 1.dp,
                    color = MaterialTheme.colorScheme.outlineVariant
                )
                RangeRow(
                    label = stringResource(R.string.fragment_interval),
                    low = minInterval,
                    high = maxInterval,
                    enabled = enabled,
                    onLowChange = { minInterval = it; persist() },
                    onHighChange = { maxInterval = it; persist() }
                )
            }

            Text(
                text = stringResource(R.string.fragment_range_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp)
            )
        }
    }
}

@Composable
private fun GroupCard(content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column { content() }
    }
}

/** A label and the two ends of a range, laid out so RTL mirrors it correctly. */
@Composable
private fun RangeRow(
    label: String,
    low: String,
    high: String,
    enabled: Boolean,
    onLowChange: (String) -> Unit,
    onHighChange: (String) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = if (enabled) MaterialTheme.colorScheme.onSurface
                    else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        NumberField(value = low, enabled = enabled, onValueChange = onLowChange)
        Text(
            text = "–",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 8.dp)
        )
        NumberField(value = high, enabled = enabled, onValueChange = onHighChange)
    }
}

@Composable
private fun NumberField(
    value: String,
    enabled: Boolean,
    onValueChange: (String) -> Unit
) {
    OutlinedTextField(
        value = value,
        // Digits only: the range is a count of bytes and a count of
        // milliseconds, and a stray sign or separator would silently fall back
        // to the default on save.
        onValueChange = { text -> onValueChange(text.filter { it.isDigit() }.take(5)) },
        enabled = enabled,
        singleLine = true,
        textStyle = MaterialTheme.typography.bodyLarge.copy(textAlign = TextAlign.Center),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        colors = wingTextFieldColors(),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.width(84.dp)
    )
}
