package com.mythaia.ui.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.automirrored.filled.Rule
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.repository.RuleSetRepository
import com.mythaia.ui.components.AppIconView
import com.mythaia.ui.components.RouteTargetField
import com.mythaia.ui.components.RouteTargets
import com.mythaia.ui.components.rememberRouteTargets
import com.mythaia.ui.components.routeTargetLabel
import com.mythaia.ui.components.wingTextFieldColors
import com.mythaia.viewmodel.VpnViewModel

/**
 * Shows built-in service rule sets (Direct + ADBlock are excluded: Direct is
 * always-direct, ADBlock is toggled from the root Settings screen). Below the
 * built-ins, lists user-created custom rule sets and navigates into
 * [CustomRuleSetDetailScreen] on tap. Adding new custom rule sets is gated
 * behind [VpnViewModel.experimentalEnabled].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetListScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    var openCustomId by rememberSaveable { mutableStateOf<String?>(null) }
    BackHandler(enabled = openCustomId != null) { openCustomId = null }

    val route = openCustomId
    SubScreenHost(state = route, rootKey = null) { current ->
        if (current == null) {
            RuleSetListRoot(
                viewModel = viewModel,
                onBack = onBack,
                onOpenCustom = { id -> openCustomId = id }
            )
        } else {
            CustomRuleSetDetailScreen(
                viewModel = viewModel,
                customRuleSetId = current,
                onBack = { openCustomId = null }
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RuleSetListRoot(
    viewModel: VpnViewModel,
    onBack: () -> Unit,
    onOpenCustom: (String) -> Unit
) {
    val ruleSets by viewModel.ruleSetRepository.ruleSets.collectAsState()
    val customRuleSets by viewModel.ruleSetRepository.customRuleSets.collectAsState()
    val configurations by viewModel.configRepository.configurations.collectAsState()
    val subscriptions by viewModel.subscriptionRepository.subscriptions.collectAsState()
    val routingProfiles by viewModel.routingProfiles.collectAsState()
    val fetchingProfile by viewModel.routingFilesFetching.collectAsState()

    val builtInServiceRuleSets = remember(ruleSets) {
        ruleSets.filter { !it.isCustom && it.name != "ADBlock" && it.id != "Direct" }
    }

    val routeTargets = rememberRouteTargets(configurations, subscriptions)

    val experimentalEnabled = remember { viewModel.experimentalEnabled }
    var menuOpen by remember { mutableStateOf(false) }
    var showNewDialog by remember { mutableStateOf(false) }
    var pendingDeleteId by remember { mutableStateOf<String?>(null) }
    var showResetConfirm by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.routing_rules)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground,
                    navigationIconContentColor = MaterialTheme.colorScheme.onBackground,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurfaceVariant
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                },
                actions = {
                    Box {
                        IconButton(onClick = { menuOpen = true }) {
                            Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.more))
                        }
                        DropdownMenu(
                            expanded = menuOpen,
                            onDismissRequest = { menuOpen = false }
                        ) {
                            if (experimentalEnabled) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.new_rule_set)) },
                                    leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null) },
                                    onClick = {
                                        menuOpen = false
                                        showNewDialog = true
                                    }
                                )
                            }
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.reset)) },
                                leadingIcon = { Icon(Icons.Filled.Refresh, contentDescription = null) },
                                onClick = {
                                    menuOpen = false
                                    showResetConfirm = true
                                }
                            )
                        }
                    }
                }
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            contentPadding = PaddingValues(top = 8.dp)
        ) {
            if (routingProfiles.entries.isNotEmpty()) {
                item(key = "profiles-header") {
                    Text(
                        text = stringResource(R.string.routing_profiles),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 16.dp, top = 4.dp, bottom = 8.dp)
                    )
                }
                item(key = "profiles-card") {
                    PaperCard {
                        routingProfiles.entries.forEachIndexed { index, entry ->
                            key(entry.name) {
                                val active = routingProfiles.active.equals(entry.name, ignoreCase = true)
                                val pending = routingProfiles.pending.equals(entry.name, ignoreCase = true)
                                val fetching = fetchingProfile.equals(entry.name, ignoreCase = true)
                                val subtitle = when {
                                    entry.filesError != null -> entry.filesError
                                    fetching || pending -> stringResource(R.string.routing_profile_fetching)
                                    !entry.subscriptionName.isNullOrBlank() -> entry.subscriptionName
                                    else -> null
                                }
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 16.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    RuleSetIconTile(Icons.AutoMirrored.Filled.Rule)
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = entry.name,
                                            style = MaterialTheme.typography.bodyLarge,
                                            color = MaterialTheme.colorScheme.onSurface,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis
                                        )
                                        if (subtitle != null) {
                                            Text(
                                                text = subtitle,
                                                style = MaterialTheme.typography.bodySmall,
                                                color = if (entry.filesError != null) MaterialTheme.colorScheme.error
                                                else MaterialTheme.colorScheme.onSurfaceVariant,
                                                maxLines = 2,
                                                overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                    if (entry.filesError != null) {
                                        IconButton(onClick = { viewModel.retryRoutingFiles(entry.name) }) {
                                            Icon(
                                                Icons.Filled.Refresh,
                                                contentDescription = stringResource(R.string.reset),
                                                tint = MaterialTheme.colorScheme.primary
                                            )
                                        }
                                    }
                                    Switch(
                                        checked = active || pending,
                                        onCheckedChange = { on ->
                                            if (on) viewModel.activateRoutingProfile(entry.name)
                                            else viewModel.routingProfilesOff()
                                        }
                                    )
                                    IconButton(onClick = { viewModel.removeRoutingProfile(entry.name) }) {
                                        Icon(
                                            Icons.Filled.Delete,
                                            contentDescription = stringResource(R.string.delete),
                                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                            if (index < routingProfiles.entries.lastIndex) {
                                HorizontalDivider(
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    modifier = Modifier.padding(horizontal = 16.dp)
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                }
            }

            item(key = "built-in-card") {
                PaperCard {
                    builtInServiceRuleSets.forEachIndexed { index, ruleSet ->
                        key(ruleSet.id) {
                            RuleSetRow(
                                ruleSet = ruleSet,
                                routeTargets = routeTargets,
                                onAssign = { configId ->
                                    viewModel.ruleSetRepository.updateAssignment(ruleSet, configId)
                                    viewModel.syncRoutingConfigurationToNE()
                                }
                            )
                        }
                        if (index < builtInServiceRuleSets.lastIndex) {
                            HorizontalDivider(
                                color = MaterialTheme.colorScheme.outlineVariant,
                                modifier = Modifier.padding(horizontal = 16.dp)
                            )
                        }
                    }
                }
            }

            if (customRuleSets.isNotEmpty()) {
                item(key = "custom-header") {
                    Text(
                        text = stringResource(R.string.custom),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 16.dp, top = 20.dp, bottom = 8.dp)
                    )
                }
                item(key = "custom-card") {
                    PaperCard {
                        customRuleSets.forEachIndexed { index, custom ->
                            key(custom.id) {
                                val assignment =
                                    ruleSets.firstOrNull { it.id == custom.id }?.assignedConfigurationId
                                CustomRuleSetRow(
                                    name = custom.name,
                                    ruleCount = custom.rules.size,
                                    assignmentLabel = routeTargetLabel(assignment, routeTargets),
                                    onOpen = { onOpenCustom(custom.id) },
                                    onDelete = { pendingDeleteId = custom.id }
                                )
                            }
                            if (index < customRuleSets.lastIndex) {
                                HorizontalDivider(
                                    color = MaterialTheme.colorScheme.outlineVariant,
                                    modifier = Modifier.padding(horizontal = 16.dp)
                                )
                            }
                        }
                    }
                }
            }

            item(key = "bottom-spacer") {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }

    if (showNewDialog) {
        NewRuleSetDialog(
            onDismiss = { showNewDialog = false },
            onCreate = { name ->
                val created = viewModel.ruleSetRepository.addCustomRuleSet(name)
                showNewDialog = false
                onOpenCustom(created.id)
            }
        )
    }

    if (showResetConfirm) {
        AlertDialog(
            onDismissRequest = { showResetConfirm = false },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.reset_assignments_title)) },
            text = { Text(stringResource(R.string.reset_assignments_message)) },
            confirmButton = {
                TextButton(onClick = {
                    showResetConfirm = false
                    viewModel.ruleSetRepository.resetAssignments()
                    viewModel.syncRoutingConfigurationToNE()
                }) { Text(stringResource(R.string.reset), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showResetConfirm = false }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }

    pendingDeleteId?.let { id ->
        val name = customRuleSets.firstOrNull { it.id == id }?.name.orEmpty()
        AlertDialog(
            onDismissRequest = { pendingDeleteId = null },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.delete)) },
            text = { Text(name) },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.ruleSetRepository.removeCustomRuleSet(id)
                    viewModel.syncRoutingConfigurationToNE()
                    pendingDeleteId = null
                }) { Text(stringResource(R.string.delete), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteId = null }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }
}

/** Grouped "paper" card: surface fill, 20dp radius, 1dp hairline outline, no shadow. */
@Composable
private fun PaperCard(content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .border(
                width = 1.dp,
                color = MaterialTheme.colorScheme.outline,
                shape = RoundedCornerShape(20.dp)
            )
            .clip(RoundedCornerShape(20.dp))
            .background(MaterialTheme.colorScheme.surface)
    ) {
        content()
    }
}

/** Soft azure pill badge for metadata (current assignment). */
@Composable
private fun AssignmentBadge(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier
            .widthIn(max = 140.dp)
            .clip(RoundedCornerShape(percent = 50))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f))
            .padding(horizontal = 8.dp, vertical = 3.dp)
    )
}

/** 28dp rounded tile with a soft azure wash behind an azure glyph. */
@Composable
private fun RuleSetIconTile(icon: ImageVector) {
    Box(
        modifier = Modifier
            .size(28.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(16.dp)
        )
    }
}

@Composable
private fun CustomRuleSetRow(
    name: String,
    ruleCount: Int,
    assignmentLabel: String,
    onOpen: () -> Unit,
    onDelete: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RuleSetIconTile(Icons.AutoMirrored.Filled.Rule)
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = name,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = pluralStringResource(R.plurals.rules_count, ruleCount, ruleCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        AssignmentBadge(assignmentLabel)
        IconButton(onClick = onDelete) {
            Icon(
                Icons.Filled.Delete,
                contentDescription = stringResource(R.string.delete),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun NewRuleSetDialog(
    onDismiss: () -> Unit,
    onCreate: (String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(28.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.onSurface,
        textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        title = { Text(stringResource(R.string.new_rule_set)) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.name_label)) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                colors = wingTextFieldColors()
            )
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val trimmed = name.trim()
                    if (trimmed.isNotEmpty()) onCreate(trimmed)
                },
                enabled = name.trim().isNotEmpty()
            ) { Text(stringResource(R.string.add)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
        }
    )
}

@Composable
private fun RuleSetRow(
    ruleSet: RuleSetRepository.RuleSet,
    routeTargets: RouteTargets,
    onAssign: (String?) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        AppIconView(name = ruleSet.name, modifier = Modifier.size(40.dp))
        Spacer(modifier = Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = ruleSet.name,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(4.dp))

            RouteTargetField(
                assignedId = ruleSet.assignedConfigurationId,
                targets = routeTargets,
                onAssign = onAssign,
                ruleSetName = ruleSet.name,
                textStyle = MaterialTheme.typography.bodySmall,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}
