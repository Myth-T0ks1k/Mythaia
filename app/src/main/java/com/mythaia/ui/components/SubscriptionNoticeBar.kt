package com.mythaia.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalResources
import com.mythaia.R
import com.mythaia.viewmodel.SubscriptionNotice
import com.mythaia.viewmodel.VpnViewModel

/**
 * The bar at the bottom of every screen that says a subscription did not
 * update, with the way out beside it: fetch it again through a server that
 * works. It goes away on its own after a while, like any snackbar.
 */
@Composable
fun SubscriptionNoticeBar(viewModel: VpnViewModel) {
    val notice by viewModel.subscriptionNotice.collectAsState()
    val hostState = remember { SnackbarHostState() }
    val resources = LocalResources.current

    LaunchedEffect(notice) {
        val shown = notice ?: return@LaunchedEffect
        val result = when (shown) {
            is SubscriptionNotice.Failed -> hostState.showSnackbar(
                message = resources.getString(R.string.subscription_update_failed_named, shown.name, shown.message),
                actionLabel = if (shown.canRetry) resources.getString(R.string.subscription_through_working_server) else null,
                withDismissAction = true,
                duration = SnackbarDuration.Long
            )
            // Replaced by the outcome when the attempt ends.
            is SubscriptionNotice.Retrying -> hostState.showSnackbar(
                message = resources.getString(R.string.subscription_retrying_through_server, shown.name),
                withDismissAction = true,
                duration = SnackbarDuration.Indefinite
            )
            is SubscriptionNotice.UpdatedThrough -> hostState.showSnackbar(
                message = resources.getString(R.string.subscription_updated_through, shown.name, shown.server),
                duration = SnackbarDuration.Short
            )
        }
        when {
            result == SnackbarResult.ActionPerformed && shown is SubscriptionNotice.Failed ->
                viewModel.refreshSubscriptionThroughServer(shown.subscriptionId)
            // Timed out or closed: gone for good, unless something newer took its place.
            viewModel.subscriptionNotice.value == shown -> viewModel.dismissSubscriptionNotice()
        }
    }

    SnackbarHost(hostState) { data ->
        Snackbar(
            snackbarData = data,
            // The action is a phrase, not a word; under the text it fits.
            actionOnNewLine = data.visuals.actionLabel != null,
            containerColor = MaterialTheme.colorScheme.inverseSurface,
            contentColor = MaterialTheme.colorScheme.inverseOnSurface,
            actionColor = MaterialTheme.colorScheme.inversePrimary
        )
    }
}
