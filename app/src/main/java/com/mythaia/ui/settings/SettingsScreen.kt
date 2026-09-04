package com.mythaia.ui.settings

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.automirrored.filled.CallMerge
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.rules.CountryBypassCatalog
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.ui.components.countryDisplayName
import com.mythaia.data.model.ThemeMode
import androidx.compose.runtime.collectAsState
import androidx.compose.material.icons.filled.BrightnessAuto
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.foundation.layout.width
import com.mythaia.viewmodel.VpnViewModel
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel) {
    val context = LocalContext.current
    var showRoutingRules by remember { mutableStateOf(false) }
    var showAcknowledgements by remember { mutableStateOf(false) }
    var showTrustedCertificates by remember { mutableStateOf(false) }
    var showAdvancedSettings by remember { mutableStateOf(false) }
    var showInsecureAlert by remember { mutableStateOf(false) }

    var globalMode by remember { mutableStateOf(viewModel.proxyMode == "global") }
    var bypassCountryCode by remember { mutableStateOf(viewModel.bypassCountryCode) }
    var allowInsecure by remember { mutableStateOf(viewModel.allowInsecure) }
    val themeMode by viewModel.themeMode.collectAsState()

    val adBlockRuleSet = remember { viewModel.ruleSetRepository.ruleSets.value.find { it.name == "ADBlock" } }
    var adBlockEnabled by remember {
        mutableStateOf(adBlockRuleSet?.assignedConfigurationId == "REJECT")
    }

    // Intercept the device back button when a sub-screen is showing. Without
    // this, the NavHost handles back press by popping the SettingsRoute,
    // sending the user to Home instead of back to the Settings list.
    val activeSubScreen = showRoutingRules || showAcknowledgements ||
            showTrustedCertificates || showAdvancedSettings
    BackHandler(enabled = activeSubScreen) {
        showRoutingRules = false
        showAcknowledgements = false
        showTrustedCertificates = false
        showAdvancedSettings = false
    }

    val currentRoute = when {
        showRoutingRules -> "routing"
        showAcknowledgements -> "acks"
        showTrustedCertificates -> "certs"
        showAdvancedSettings -> "advanced"
        else -> "root"
    }

    SubScreenHost(state = currentRoute, rootKey = "root") { route ->
        when (route) {
            "routing" -> RuleSetListScreen(
                viewModel = viewModel,
                onBack = { showRoutingRules = false }
            )
            "acks" -> AcknowledgementsScreen(onBack = { showAcknowledgements = false })
            "certs" -> TrustedCertificatesScreen(
                viewModel = viewModel,
                onBack = { showTrustedCertificates = false }
            )
            "advanced" -> AdvancedSettingsScreen(
                viewModel = viewModel,
                onBack = { showAdvancedSettings = false }
            )
            else -> SettingsRoot(
                globalMode = globalMode,
                onGlobalModeChange = { globalMode = it; viewModel.proxyMode = if (it) "global" else "rule" },
                bypassCountryCode = bypassCountryCode,
                onBypassCountryChange = {
                    bypassCountryCode = it
                    viewModel.bypassCountryCode = it
                    viewModel.syncRoutingConfigurationToNE()
                },
                adBlockVisible = adBlockRuleSet != null,
                adBlockEnabled = adBlockEnabled,
                onAdBlockChange = { enabled ->
                    adBlockEnabled = enabled
                    if (adBlockRuleSet != null) {
                        viewModel.ruleSetRepository.updateAssignment(
                            adBlockRuleSet,
                            if (enabled) "REJECT" else null
                        )
                        viewModel.syncRoutingConfigurationToNE()
                    }
                },
                allowInsecure = allowInsecure,
                onAllowInsecureChange = { newValue ->
                    if (newValue) {
                        showInsecureAlert = true
                    } else {
                        allowInsecure = false
                        viewModel.allowInsecure = false
                    }
                },
                themeMode = themeMode,
                onThemeModeChange = { viewModel.setThemeMode(it) },
                onOpenTelegram = {
                    com.mythaia.BrandLinks.TELEGRAM_COMMUNITY?.let { link ->
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)))
                    }
                },
                onOpenRoutingRules = { showRoutingRules = true },
                onOpenTrustedCertificates = { showTrustedCertificates = true },
                onOpenAcknowledgements = { showAcknowledgements = true },
                onOpenAdvancedSettings = { showAdvancedSettings = true }
            )
        }
    }

    if (showInsecureAlert) {
        AlertDialog(
            onDismissRequest = { showInsecureAlert = false },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.allow_insecure)) },
            text = { Text(stringResource(R.string.allow_insecure_warning)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        showInsecureAlert = false
                        allowInsecure = true
                        viewModel.allowInsecure = true
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text(stringResource(R.string.allow_anyway))
                }
            },
            dismissButton = {
                TextButton(onClick = { showInsecureAlert = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsRoot(
    globalMode: Boolean,
    onGlobalModeChange: (Boolean) -> Unit,
    bypassCountryCode: String,
    onBypassCountryChange: (String) -> Unit,
    adBlockVisible: Boolean,
    adBlockEnabled: Boolean,
    onAdBlockChange: (Boolean) -> Unit,
    allowInsecure: Boolean,
    onAllowInsecureChange: (Boolean) -> Unit,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    onOpenTelegram: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onOpenTrustedCertificates: () -> Unit,
    onOpenAcknowledgements: () -> Unit,
    onOpenAdvancedSettings: () -> Unit
) {
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            SectionHeader(stringResource(R.string.routing))
            SettingsGroupCard {
                SettingsSwitch(
                    icon = Icons.AutoMirrored.Filled.CallMerge,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.global_mode),
                    checked = globalMode,
                    onCheckedChange = onGlobalModeChange
                )
                if (!globalMode) {
                    SettingsRowDivider()
                    CountryBypassPicker(
                        icon = Icons.Filled.Public,
                        iconTint = MaterialTheme.colorScheme.primary,
                        selectedCode = bypassCountryCode,
                        onSelect = onBypassCountryChange
                    )
                    if (adBlockVisible) {
                        SettingsRowDivider()
                        SettingsSwitch(
                            icon = Icons.Filled.Shield,
                            iconTint = MaterialTheme.colorScheme.primary,
                            label = stringResource(R.string.ad_blocking_title),
                            checked = adBlockEnabled,
                            onCheckedChange = onAdBlockChange
                        )
                    }
                    SettingsRowDivider()
                    SettingsNavRow(
                        icon = Icons.AutoMirrored.Filled.AltRoute,
                        iconTint = MaterialTheme.colorScheme.primary,
                        label = stringResource(R.string.routing_rules),
                        onClick = onOpenRoutingRules
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            SectionHeader(stringResource(R.string.appearance))
            SettingsGroupCard {
                ThemeModeRow(
                    mode = themeMode,
                    onModeChange = onThemeModeChange
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            SectionHeader(stringResource(R.string.security))
            SettingsGroupCard {
                SettingsSwitch(
                    icon = Icons.Filled.Warning,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.allow_insecure),
                    checked = allowInsecure,
                    onCheckedChange = onAllowInsecureChange
                )
                SettingsRowDivider()
                SettingsNavRow(
                    icon = Icons.Filled.VerifiedUser,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.trusted_certificates),
                    onClick = onOpenTrustedCertificates
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            SectionHeader(stringResource(R.string.about))
            SettingsGroupCard {
                // Hidden until a Mythaia community invite is configured — see
                // BrandLinks.TELEGRAM_COMMUNITY. Shipping the row with no link
                // would be a dead tap; pointing it elsewhere would be worse.
                if (com.mythaia.BrandLinks.hasCommunityLink) {
                    SettingsNavRow(
                        painter = painterResource(R.drawable.ic_telegram_symbol),
                        iconTint = MaterialTheme.colorScheme.primary,
                        label = stringResource(R.string.join_telegram_group),
                        onClick = onOpenTelegram
                    )
                    SettingsRowDivider()
                }
                SettingsNavRow(
                    icon = Icons.Filled.Info,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.acknowledgements),
                    onClick = onOpenAcknowledgements
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            SettingsGroupCard {
                SettingsNavRow(
                    icon = Icons.Filled.Tune,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.advanced_settings),
                    onClick = onOpenAdvancedSettings
                )
            }
        }
    }
}

/**
 * Light, dark, or whatever the device is doing.
 *
 * A segmented row rather than a menu: three mutually exclusive choices, and
 * seeing which one is active matters more than saving the width.
 */
@Composable
private fun ThemeModeRow(mode: ThemeMode, onModeChange: (ThemeMode) -> Unit) {
    Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SettingsIcon(
                icon = when (mode) {
                    ThemeMode.SYSTEM -> Icons.Filled.BrightnessAuto
                    ThemeMode.LIGHT -> Icons.Filled.LightMode
                    ThemeMode.DARK -> Icons.Filled.DarkMode
                },
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.width(16.dp))
            Text(
                text = stringResource(R.string.theme),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        val segmentColors = SegmentedButtonDefaults.colors(
            activeContainerColor = MaterialTheme.colorScheme.primaryContainer,
            activeContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            activeBorderColor = MaterialTheme.colorScheme.outline,
            inactiveContainerColor = MaterialTheme.colorScheme.surface,
            inactiveContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            inactiveBorderColor = MaterialTheme.colorScheme.outline
        )
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            val options = listOf(
                ThemeMode.SYSTEM to R.string.theme_system,
                ThemeMode.LIGHT to R.string.theme_light,
                ThemeMode.DARK to R.string.theme_dark
            )
            options.forEachIndexed { index, (value, labelRes) ->
                SegmentedButton(
                    selected = mode == value,
                    onClick = { onModeChange(value) },
                    shape = SegmentedButtonDefaults.itemShape(index, options.size),
                    colors = segmentColors
                ) { Text(stringResource(labelRes)) }
            }
        }
    }
}

/**
 * Slate uppercase caption above a settings group card (Wing editorial style).
 */
@Composable
internal fun SectionHeader(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.sp),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp)
    )
}

/**
 * Wing grouped section card: paper surface, 20dp corners, 1dp hairline outline,
 * no elevation. Rows inside are separated with [SettingsRowDivider].
 */
@Composable
private fun SettingsGroupCard(content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column { content() }
    }
}

/** 1dp inset divider between rows in a [SettingsGroupCard], aligned past the icon tile. */
@Composable
private fun SettingsRowDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(start = 60.dp),
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.outlineVariant
    )
}

// The `tint` / `iconTint` parameters below are retained for signature
// compatibility; the Wing identity renders every settings glyph in azure
// (colorScheme.primary) on a soft azure-tinted squircle, so the value is
// intentionally not used.

@Suppress("UNUSED_PARAMETER")
@Composable
private fun SettingsIcon(
    icon: ImageVector,
    tint: Color,
    modifier: Modifier = Modifier
) {
    SettingsIconContainer(tint = tint, modifier = modifier) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
    }
}

@Suppress("UNUSED_PARAMETER")
@Composable
private fun SettingsIcon(
    painter: Painter,
    tint: Color,
    modifier: Modifier = Modifier
) {
    SettingsIconContainer(tint = tint, modifier = modifier) {
        Icon(
            painter = painter,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
    }
}

@Suppress("UNUSED_PARAMETER")
@Composable
private fun SettingsIconContainer(
    tint: Color,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    Box(
        modifier = modifier
            .size(28.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
        contentAlignment = Alignment.Center
    ) {
        content()
    }
}

@Composable
internal fun SettingsSwitch(
    icon: ImageVector,
    iconTint: Color,
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = settingsSwitchColors()
        )
    }
}

@Composable
private fun settingsSwitchColors() = SwitchDefaults.colors(
    checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
    checkedTrackColor = MaterialTheme.colorScheme.primary,
    uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
    uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
    uncheckedBorderColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
)

@Composable
internal fun SettingsNavRow(
    icon: ImageVector,
    iconTint: Color,
    label: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            modifier = Modifier.size(20.dp)
        )
    }
}

@Composable
internal fun SettingsNavRow(
    painter: Painter,
    iconTint: Color,
    label: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .heightIn(min = 52.dp)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(painter = painter, tint = iconTint)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
            modifier = Modifier.size(20.dp)
        )
    }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CountryBypassPicker(
    icon: ImageVector,
    iconTint: Color,
    selectedCode: String,
    onSelect: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val countryCodes = remember { CountryBypassCatalog.get(context).supportedCountryCodes }

    val displayText = if (selectedCode.isEmpty()) {
        stringResource(R.string.disable)
    } else {
        countryDisplayName(selectedCode)
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SettingsIcon(icon = icon, tint = iconTint)
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = it },
            modifier = Modifier.weight(1f)
        ) {
            OutlinedTextField(
                value = displayText,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.country_bypass)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                shape = RoundedCornerShape(14.dp),
                colors = wingTextFieldColors(),
                modifier = Modifier
                    .fillMaxWidth()
                    .menuAnchor(MenuAnchorType.PrimaryNotEditable)
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false }
            ) {
                DropdownMenuItem(
                    text = { Text(stringResource(R.string.disable)) },
                    onClick = {
                        onSelect("")
                        expanded = false
                    }
                )
                countryCodes.forEach { code ->
                    DropdownMenuItem(
                        text = { Text(countryDisplayName(code)) },
                        onClick = {
                            onSelect(code)
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}
