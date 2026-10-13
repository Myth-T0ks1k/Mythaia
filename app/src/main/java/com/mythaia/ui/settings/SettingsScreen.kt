package com.mythaia.ui.settings

import androidx.core.net.toUri
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
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.IconButton
import com.mythaia.ui.components.WingIconTile
import com.mythaia.ui.components.WingSectionTitle
import androidx.compose.material.icons.automirrored.filled.CallMerge
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Language
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
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
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
import androidx.compose.ui.text.font.FontWeight

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(viewModel: VpnViewModel, onClose: (() -> Unit)? = null) {
    val context = LocalContext.current
    var showRoutingRules by rememberSaveable { mutableStateOf(false) }
    var showAcknowledgements by rememberSaveable { mutableStateOf(false) }
    var showTrustedCertificates by rememberSaveable { mutableStateOf(false) }
    var showAdvancedSettings by rememberSaveable { mutableStateOf(false) }
    var showInsecureAlert by remember { mutableStateOf(false) }

    // Shared with the Home screen's segmented control through the view model.
    val globalMode by viewModel.isGlobalMode.collectAsState()
    var bypassCountryCode by remember { mutableStateOf(viewModel.bypassCountryCode) }
    var allowInsecure by remember { mutableStateOf(viewModel.allowInsecure) }
    val themeMode by viewModel.themeMode.collectAsState()

    // Derived from the live rule-set list rather than read once: the Routing
    // Rules sub-screen can reassign ADBlock, and the switch here has to follow.
    val ruleSets by viewModel.ruleSetRepository.ruleSets.collectAsState()
    val adBlockRuleSet = ruleSets.find { it.id == "ADBlock" && !it.isCustom }
    val adBlockEnabled = adBlockRuleSet?.assignedConfigurationId == "REJECT"

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
    // At the root of a tab, back is the navigation's (to Home); only a host
    // that passes [onClose] takes it over.
    BackHandler(enabled = !activeSubScreen && onClose != null) { onClose?.invoke() }

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
                onGlobalModeChange = { viewModel.proxyMode = if (it) "global" else "rule" },
                bypassCountryCode = bypassCountryCode,
                onBypassCountryChange = {
                    bypassCountryCode = it
                    viewModel.bypassCountryCode = it
                    viewModel.syncRoutingConfigurationToNE()
                },
                adBlockVisible = adBlockRuleSet != null,
                adBlockEnabled = adBlockEnabled,
                onAdBlockChange = { enabled ->
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
                        // A TV box may have nothing that opens a URL.
                        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, link.toUri())) }
                    }
                },
                onOpenRoutingRules = { showRoutingRules = true },
                onOpenTrustedCertificates = { showTrustedCertificates = true },
                onOpenAcknowledgements = { showAcknowledgements = true },
                onOpenAdvancedSettings = { showAdvancedSettings = true },
                onClose = onClose
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
    onOpenAdvancedSettings: () -> Unit,
    onClose: (() -> Unit)?
) {
    // Material 3's settings header: a large title that collapses into the
    // bar as the list scrolls.
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        containerColor = MaterialTheme.colorScheme.background,
        // The bottom bar's inset is the navigation's; the top bar takes the status bar.
        contentWindowInsets = androidx.compose.foundation.layout.WindowInsets(0, 0, 0, 0),
        topBar = {
            LargeTopAppBar(
                title = { Text(stringResource(R.string.settings)) },
                navigationIcon = {
                    if (onClose != null) {
                        IconButton(onClick = onClose) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = stringResource(R.string.close)
                            )
                        }
                    }
                },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.largeTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.surfaceContainer,
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
                    iconTint = if (allowInsecure) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.allow_insecure),
                    checked = allowInsecure,
                    onCheckedChange = onAllowInsecureChange
                )
                // The same warning the per-server switch carries, louder: this
                // one turns the check off for every server at once.
                Column(modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp)) {
                    Text(
                        text = stringResource(R.string.insecure_caps),
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        ),
                        color = MaterialTheme.colorScheme.error
                    )
                    Text(
                        text = stringResource(R.string.insecure_global_explained),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (allowInsecure) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SettingsRowDivider()
                SettingsNavRow(
                    icon = Icons.Filled.VerifiedUser,
                    iconTint = MaterialTheme.colorScheme.primary,
                    label = stringResource(R.string.trusted_certificates),
                    onClick = onOpenTrustedCertificates
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            SectionHeader(stringResource(R.string.system_section))
            SystemSettingsCard()

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
    WingSectionTitle(title = title)
}

/**
 * Wing grouped section card: paper surface, 20dp corners, 1dp hairline outline,
 * no elevation. Rows inside are separated with [SettingsRowDivider].
 */
@Composable
private fun SettingsGroupCard(content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow
    ) {
        Column { content() }
    }
}

/** 1dp inset divider between rows in a [SettingsGroupCard], aligned past the icon tile. */
@Composable
private fun SettingsRowDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(start = 66.dp, end = 16.dp),
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f)
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
            tint = Color.White,
            modifier = Modifier.size(18.dp)
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
            tint = Color.White,
            modifier = Modifier.size(18.dp)
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
    WingIconTile(modifier = modifier, size = 34.dp) { content() }
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

/**
 * Rows that open Android's own screens: the kill switch (Always-on VPN and
 * "Block connections without VPN" are enforced by the OS, so the app can only
 * point at them), the app language, notifications — plus a diagnostics copy
 * for support.
 */
@Composable
private fun SystemSettingsCard() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val copied = stringResource(R.string.diagnostics_copied)
    SettingsGroupCard {
        SettingsNavRow(
            icon = Icons.Filled.Shield,
            iconTint = MaterialTheme.colorScheme.primary,
            label = stringResource(R.string.always_on_vpn),
            onClick = { SystemShortcuts.openVpnSettings(context) }
        )
        if (SystemShortcuts.supportsAppLanguage) {
            SettingsRowDivider()
            SettingsNavRow(
                icon = Icons.Filled.Language,
                iconTint = MaterialTheme.colorScheme.primary,
                label = stringResource(R.string.app_language),
                onClick = { SystemShortcuts.openAppLanguage(context) }
            )
        }
        SettingsRowDivider()
        SettingsNavRow(
            icon = Icons.Filled.Notifications,
            iconTint = MaterialTheme.colorScheme.primary,
            label = stringResource(R.string.notification_settings),
            onClick = { SystemShortcuts.openNotificationSettings(context) }
        )
        SettingsRowDivider()
        SettingsNavRow(
            icon = Icons.Filled.ContentCopy,
            iconTint = MaterialTheme.colorScheme.primary,
            label = stringResource(R.string.copy_diagnostics),
            onClick = {
                val protocol = com.mythaia.vpn.MythaiaVpnService.activeConfigId
                    ?.let { com.mythaia.data.repository.ConfigRepository.get(context).get(it) }
                    ?.let { com.mythaia.data.network.ProtocolProbe.describe(it) }
                SystemShortcuts.copyToClipboard(context, "Mythaia diagnostics", SystemShortcuts.diagnosticsReport(context, protocol))
                android.widget.Toast.makeText(context, copied, android.widget.Toast.LENGTH_SHORT).show()
            }
        )
    }
}
