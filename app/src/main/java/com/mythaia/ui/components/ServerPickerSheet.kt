package com.mythaia.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import kotlinx.coroutines.launch

/** The values a rule set stores in place of a server id (see RuleSetRepository). */
private const val ROUTE_DIRECT = "DIRECT"
private const val ROUTE_REJECT = "REJECT"

/** Above this many servers the sheet opens tall, so filtering does not resize it. */
private const val TALL_SHEET_SERVERS = 6

/**
 * Every server a routing rule can be sent to, grouped the way the proxy list
 * groups them: the servers added by hand, then one group per subscription in
 * the subscriptions' order. Built once per change of the data, so a row asks
 * for a server by id through a map instead of joining and scanning the lists.
 *
 * A server whose subscription is gone is left out, and an id met twice is
 * kept only the first time: the picker's lazy list needs unique keys, and
 * both copies would store the same value anyway.
 */
@Immutable
class RouteTargets private constructor(
    val standalone: List<ProxyConfiguration>,
    val groups: List<Pair<Subscription, List<ProxyConfiguration>>>,
    private val byId: Map<String, ProxyConfiguration>
) {
    /** How many servers can be picked. */
    val size: Int get() = byId.size

    /** The server an assignment points at, or null for DIRECT, REJECT or a stale id. */
    operator fun get(id: String): ProxyConfiguration? = byId[id]

    /**
     * The sections that have a server matching [query] by name, address or
     * protocol; all of them, unfiltered, when the query is blank.
     */
    fun sections(query: String): List<ServerSection> {
        val q = query.trim()
        fun keep(servers: List<ProxyConfiguration>) =
            if (q.isEmpty()) servers else servers.filter { it.matches(q) }

        val result = ArrayList<ServerSection>(groups.size + 1)
        keep(standalone).takeIf { it.isNotEmpty() }?.let { result += ServerSection(null, it) }
        for ((subscription, servers) in groups) {
            keep(servers).takeIf { it.isNotEmpty() }?.let { result += ServerSection(subscription, it) }
        }
        return result
    }

    companion object {
        fun of(configurations: List<ProxyConfiguration>, subscriptions: List<Subscription>): RouteTargets {
            val byId = HashMap<String, ProxyConfiguration>(configurations.size * 2)
            fun firstSeen(servers: List<ProxyConfiguration>) = servers.filter { config ->
                val key = config.id.toString()
                if (byId.containsKey(key)) false else { byId[key] = config; true }
            }

            val bySubscription = configurations.groupBy { it.subscriptionId }
            val standalone = firstSeen(bySubscription[null].orEmpty())
            val groups = subscriptions.mapNotNull { subscription ->
                val servers = firstSeen(bySubscription[subscription.id].orEmpty())
                if (servers.isEmpty()) null else subscription to servers
            }
            return RouteTargets(standalone, groups, byId)
        }
    }
}

/** One block of the picker: the hand-added servers ([subscription] null) or a subscription's. */
@Immutable
class ServerSection(val subscription: Subscription?, val servers: List<ProxyConfiguration>)

private fun ProxyConfiguration.matches(query: String): Boolean =
    name.contains(query, ignoreCase = true) ||
        serverAddress.contains(query, ignoreCase = true) ||
        outboundProtocol.displayName.contains(query, ignoreCase = true)

@Composable
fun rememberRouteTargets(
    configurations: List<ProxyConfiguration>,
    subscriptions: List<Subscription>
): RouteTargets = remember(configurations, subscriptions) {
    RouteTargets.of(configurations, subscriptions)
}

/** What an assignment reads as: Default, DIRECT, REJECT or the server's name. */
@Composable
fun routeTargetLabel(assignedId: String?, targets: RouteTargets): String = when (assignedId) {
    null -> stringResource(R.string.default_value)
    ROUTE_DIRECT -> stringResource(R.string.direct)
    ROUTE_REJECT -> stringResource(R.string.reject)
    else -> targets[assignedId]?.name ?: stringResource(R.string.default_value)
}

/**
 * The "route to" field of a rule set. It looks like the read-only dropdown
 * field it replaces, but a tap opens [ServerPickerSheet]: a dropdown menu
 * composes every one of its items at once, and a subscription can bring
 * ten thousand servers.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RouteTargetField(
    assignedId: String?,
    targets: RouteTargets,
    onAssign: (String?) -> Unit,
    modifier: Modifier = Modifier,
    label: String? = null,
    ruleSetName: String? = null,
    textStyle: TextStyle = LocalTextStyle.current
) {
    var picking by rememberSaveable { mutableStateOf(false) }
    val value = routeTargetLabel(assignedId, targets)
    val routeTo = stringResource(R.string.route_to)
    val shape = RoundedCornerShape(14.dp)

    Box(modifier = modifier) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = if (label != null) {
                { Text(label) }
            } else null,
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = picking) },
            shape = shape,
            colors = wingTextFieldColors(),
            textStyle = textStyle,
            // Only the face of the control: the layer above takes the touch,
            // the keyboard focus and the screen reader.
            modifier = Modifier
                .fillMaxWidth()
                .focusProperties { canFocus = false }
                .clearAndSetSemantics {}
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                // An outlined field with a label sits 8dp below its top edge.
                .padding(top = if (label != null) 8.dp else 0.dp)
                .clip(shape)
                .semantics {
                    contentDescription = label ?: routeTo
                    stateDescription = value
                }
                .clickable(role = Role.DropdownList) { picking = true }
        )
    }

    if (picking) {
        ServerPickerSheet(
            title = routeTo,
            subtitle = ruleSetName,
            selectedId = assignedId,
            targets = targets,
            onSelect = onAssign,
            onDismiss = { picking = false }
        )
    }
}

private class RouteOption(val value: String?, val label: String, val icon: ImageVector)

/**
 * Picks where a rule sends its traffic: Default, DIRECT, REJECT, or one
 * server, found by search and listed lazily under a header per
 * subscription. [onSelect] receives the value to store: null for Default,
 * "DIRECT", "REJECT" or the server's id.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ServerPickerSheet(
    title: String,
    subtitle: String?,
    selectedId: String?,
    targets: RouteTargets,
    onSelect: (String?) -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    var query by rememberSaveable { mutableStateOf("") }
    val trimmed = query.trim()

    val options = listOf(
        RouteOption(null, stringResource(R.string.default_value), Icons.Filled.Shield),
        RouteOption(ROUTE_DIRECT, stringResource(R.string.direct), Icons.Filled.Language),
        RouteOption(ROUTE_REJECT, stringResource(R.string.reject), Icons.Filled.Block)
    )
    val visibleOptions = if (trimmed.isEmpty()) options
    else options.filter { it.label.contains(trimmed, ignoreCase = true) }
    val sections = remember(targets, trimmed) { targets.sections(trimmed) }

    // A stale id reads as Default on the field, so Default is what is ticked.
    val selectedServer = selectedId?.let { targets[it] }
    val selectedOption = selectedId?.takeIf { it == ROUTE_DIRECT || it == ROUTE_REJECT }
    val standaloneTitle = stringResource(R.string.standalone)
    // The hand-added servers get a header only when subscriptions follow them.
    val headed = { section: ServerSection -> section.subscription != null || targets.groups.isNotEmpty() }

    // Open on the server in use rather than on the top of a long list.
    val listState = rememberLazyListState(
        initialFirstVisibleItemIndex = remember {
            val server = selectedServer ?: return@remember 0
            var index = options.size
            for (section in targets.sections("")) {
                if (headed(section)) index++
                val at = section.servers.indexOfFirst { it === server }
                if (at >= 0) return@remember (index + at - 1).coerceAtLeast(0)
                index += section.servers.size
            }
            0
        }
    )

    fun choose(value: String?) {
        keyboard?.hide()
        onSelect(value)
        scope.launch { sheetState.hide() }.invokeOnCompletion { onDismiss() }
    }

    fun search(text: String) {
        query = text
        scope.launch { listState.scrollToItem(0) }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        containerColor = MaterialTheme.colorScheme.surface
    ) {
        Column(
            modifier = if (targets.size > TALL_SHEET_SERVERS) Modifier.fillMaxHeight(0.85f) else Modifier
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 24.dp, end = 24.dp, bottom = 12.dp)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.semantics { heading() }
                )
                if (subtitle != null) {
                    Text(
                        text = subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            if (targets.size > 0) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { search(it) },
                    placeholder = { Text(stringResource(R.string.search_proxies)) },
                    leadingIcon = {
                        Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                    },
                    trailingIcon = if (query.isNotEmpty()) {
                        {
                            IconButton(onClick = { search("") }) {
                                Icon(
                                    Icons.Filled.Close,
                                    contentDescription = stringResource(R.string.clear),
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    } else null,
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { keyboard?.hide() }),
                    shape = RoundedCornerShape(14.dp),
                    colors = wingTextFieldColors(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            LazyColumn(
                state = listState,
                contentPadding = PaddingValues(bottom = 24.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f, fill = false)
                    .selectableGroup()
            ) {
                items(visibleOptions, key = { "option:${it.value}" }, contentType = { "option" }) { option ->
                    OptionRow(
                        option = option,
                        selected = selectedServer == null && option.value == selectedOption,
                        onClick = { choose(option.value) }
                    )
                }

                for (section in sections) {
                    if (headed(section)) {
                        val subscription = section.subscription
                        stickyHeader(
                            key = "header:${subscription?.id ?: "standalone"}",
                            contentType = "header"
                        ) {
                            ServerSectionHeader(
                                title = subscription?.name ?: standaloneTitle,
                                count = section.servers.size
                            )
                        }
                    }
                    items(section.servers, key = { it.id }, contentType = { "server" }) { config ->
                        ServerRow(
                            config = config,
                            selected = config === selectedServer,
                            onClick = { choose(config.id.toString()) }
                        )
                    }
                }

                if (trimmed.isNotEmpty() && visibleOptions.isEmpty() && sections.isEmpty()) {
                    item(key = "no-match") {
                        Text(
                            text = stringResource(R.string.no_matching_proxies),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
                        )
                    }
                }
            }
        }
    }
}

/** A tappable picker row: soft azure wash while selected, a tick at the end. */
@Composable
private fun PickerRow(
    selected: Boolean,
    onClick: () -> Unit,
    content: @Composable androidx.compose.foundation.layout.RowScope.() -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
            .background(
                if (selected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.6f)
                else Color.Transparent
            )
            .padding(horizontal = 24.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        content()
        Spacer(modifier = Modifier.width(8.dp))
        Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) {
            if (selected) {
                Icon(
                    imageVector = Icons.Filled.Check,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@Composable
private fun OptionRow(option: RouteOption, selected: Boolean, onClick: () -> Unit) {
    PickerRow(selected = selected, onClick = onClick) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = option.icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(16.dp)
            )
        }
        Spacer(modifier = Modifier.width(14.dp))
        Text(
            text = option.label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
    }
}

/** A server as the proxy list shows it: the name, then protocol and endpoint. */
@Composable
private fun ServerRow(config: ProxyConfiguration, selected: Boolean, onClick: () -> Unit) {
    PickerRow(selected = selected, onClick = onClick) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = config.name,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = config.outboundProtocol.displayName,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.06f))
                        .padding(horizontal = 6.dp, vertical = 2.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = config.displayEndpoint,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

/** A subscription's name over its servers; it stays pinned while they scroll. */
@Composable
private fun ServerSectionHeader(title: String, count: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(start = 24.dp, end = 24.dp, top = 14.dp, bottom = 6.dp)
            .semantics(mergeDescendants = true) { heading() },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.SemiBold),
            color = MaterialTheme.colorScheme.primary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = count.toString(),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
