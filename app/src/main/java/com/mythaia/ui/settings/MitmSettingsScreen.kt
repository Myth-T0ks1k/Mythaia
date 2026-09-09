package com.mythaia.ui.settings

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.security.KeyChain
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mythaia.R
import com.mythaia.data.repository.MitmRuleSetInfo
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Configures HTTPS interception: the root certificate every intercepted leaf
 * chains to, and the imported `.amrs` rule sets that decide which hosts are
 * intercepted.
 *
 * Reads its state straight off [com.mythaia.data.repository.MitmRepository]'s
 * flows and drives it through the same repository, so a change lands in
 * [com.mythaia.vpn.mitm.MitmRuleStore] the moment it is persisted. Nothing here
 * runs on a fresh install: with no CA and no rule sets the store stays empty and
 * the tunnel stays inert, exactly as it does for a user who never opens this
 * screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MitmSettingsScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val repo = viewModel.mitmRepository

    val caInstalled by repo.caInstalled.collectAsState()
    val ruleSets by repo.ruleSets.collectAsState()

    var pendingDelete by remember { mutableStateOf<MitmRuleSetInfo?>(null) }

    val caGeneratedMessage = stringResource(R.string.mitm_ca_generated)
    val caGenerateFailedMessage = stringResource(R.string.mitm_ca_generate_failed)
    val exportFailedMessage = stringResource(R.string.mitm_export_failed)
    val importFailedMessage = stringResource(R.string.mitm_import_failed)
    val defaultRuleSetName = stringResource(R.string.mitm_rule_set_default_name)
    val exportFileName = stringResource(R.string.mitm_export_filename)

    // application/x-pem-file so a certificate manager offers to open the export;
    // the launch below suggests a filename the picker pre-fills.
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-pem-file")
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    val pem = repo.caCertificatePem() ?: return@runCatching false
                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(pem.toByteArray())
                    } ?: return@runCatching false
                    true
                }.getOrDefault(false)
            }
            if (!ok) snackbarHostState.showSnackbar(exportFailedMessage)
        }
    }

    // Not "application/x-amrs": file providers rarely know that type, and a
    // narrow filter would hide the file the user is looking for (as GeoIP does).
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching {
                    val text = context.contentResolver.openInputStream(uri)?.use { stream ->
                        stream.bufferedReader().readText()
                    } ?: return@runCatching false
                    val name = deriveRuleSetName(context, uri, defaultRuleSetName)
                    repo.importRuleSet(name, text)
                }.getOrDefault(false)
            }
            if (!ok) snackbarHostState.showSnackbar(importFailedMessage)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.mitm_title)) },
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
            // MARK: - Certificate authority
            WingSectionLabel(stringResource(R.string.mitm_ca_section))
            WingCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.mitm_root_certificate),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        text = stringResource(
                            if (caInstalled) R.string.mitm_ca_installed else R.string.mitm_ca_none
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        color = if (caInstalled) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Button(
                onClick = {
                    scope.launch {
                        val ok = runCatching { repo.generateCa() }.isSuccess
                        snackbarHostState.showSnackbar(
                            if (ok) caGeneratedMessage else caGenerateFailedMessage
                        )
                    }
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text(stringResource(R.string.mitm_generate_ca))
            }

            if (caInstalled) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(
                        onClick = { exportLauncher.launch(exportFileName) },
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Text(stringResource(R.string.mitm_export_certificate))
                    }
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                val der = repo.caCertificateDer() ?: return@launch
                                val intent = KeyChain.createInstallIntent().apply {
                                    putExtra(KeyChain.EXTRA_CERTIFICATE, der)
                                    putExtra(KeyChain.EXTRA_NAME, MitmCertificateAuthority.COMMON_NAME)
                                }
                                runCatching { context.startActivity(intent) }
                            }
                        },
                        shape = RoundedCornerShape(14.dp)
                    ) {
                        Text(stringResource(R.string.mitm_install_certificate))
                    }
                }
            }

            Text(
                text = stringResource(R.string.mitm_ca_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 4.dp)
            )

            // MARK: - Rule sets
            WingSectionLabel(stringResource(R.string.mitm_rule_sets_section))
            WingCard {
                if (ruleSets.isEmpty()) {
                    Text(
                        text = stringResource(R.string.mitm_no_rule_sets),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 16.dp)
                    )
                } else {
                    ruleSets.forEachIndexed { index, info ->
                        if (index > 0) WingRowDivider()
                        RuleSetRow(
                            info = info,
                            onToggle = { enabled ->
                                scope.launch { repo.setEnabled(info.name, enabled) }
                            },
                            onDelete = { pendingDelete = info }
                        )
                    }
                }
            }

            Button(
                onClick = { importLauncher.launch(arrayOf("*/*")) },
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ),
                shape = RoundedCornerShape(14.dp)
            ) {
                Text(stringResource(R.string.mitm_import_rules))
            }
        }
    }

    pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            shape = RoundedCornerShape(28.dp),
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface,
            textContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            title = { Text(stringResource(R.string.mitm_delete_rule_set_title)) },
            text = { Text(stringResource(R.string.mitm_delete_rule_set_message, target.name)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingDelete = null
                        scope.launch { repo.removeRuleSet(target.name) }
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text(stringResource(R.string.delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }
}

/** One persisted rule set: its name and rule count, an enable toggle, and a delete affordance. */
@Composable
private fun RuleSetRow(
    info: MitmRuleSetInfo,
    onToggle: (Boolean) -> Unit,
    onDelete: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .padding(start = 16.dp, top = 8.dp, bottom = 8.dp, end = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = info.name,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = pluralStringResource(R.plurals.rules_count, info.ruleCount, info.ruleCount),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = info.enabled,
            onCheckedChange = onToggle,
            colors = wingSwitchColors()
        )
        IconButton(onClick = onDelete) {
            Icon(
                imageVector = Icons.Filled.Delete,
                contentDescription = stringResource(R.string.delete),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
            )
        }
    }
}

/** Slate uppercase caption above a Wing group card, matching the other settings screens. */
@Composable
private fun WingSectionLabel(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.sp),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 16.dp, bottom = 8.dp)
    )
}

/** Wing grouped section card: paper surface, 20dp corners, 1dp hairline outline, no elevation. */
@Composable
private fun WingCard(content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column { content() }
    }
}

/** 1dp inset divider between rows in a [WingCard], aligned past the row's left padding. */
@Composable
private fun WingRowDivider() {
    HorizontalDivider(
        modifier = Modifier.padding(start = 16.dp),
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.outlineVariant
    )
}

@Composable
private fun wingSwitchColors() = SwitchDefaults.colors(
    checkedThumbColor = MaterialTheme.colorScheme.onPrimary,
    checkedTrackColor = MaterialTheme.colorScheme.primary,
    uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
    uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
    uncheckedBorderColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
)

/**
 * A stable name for an imported set, taken from the picked file's display name
 * with the `.amrs` extension dropped. The repository keys the store by this
 * name, so re-importing the same file replaces the set in place. Falls back to
 * [fallback] when the provider exposes no readable name.
 */
private fun deriveRuleSetName(context: Context, uri: Uri, fallback: String): String {
    var displayName: String? = null
    runCatching {
        context.contentResolver.query(
            uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
        )?.use { cursor ->
            if (cursor.moveToFirst()) {
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0) displayName = cursor.getString(index)
            }
        }
    }
    val raw = (displayName ?: uri.lastPathSegment)?.substringAfterLast('/') ?: return fallback
    return raw.removeSuffix(".amrs").trim().ifEmpty { fallback }
}
