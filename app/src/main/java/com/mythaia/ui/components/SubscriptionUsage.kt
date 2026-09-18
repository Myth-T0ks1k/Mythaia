package com.mythaia.ui.components

import android.text.format.DateUtils
import android.text.format.Formatter
import androidx.compose.foundation.BorderStroke
import com.mythaia.ui.theme.LocalMythaiaDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.data.model.Subscription
import com.mythaia.ui.theme.WarningDark
import com.mythaia.ui.theme.WarningLight

/**
 * What a subscription has left: traffic used against the quota, and how long
 * until it expires.
 *
 * The panel reports both in the `subscription-userinfo` header, and until now
 * the app stored them without ever showing them. Renders nothing when the panel
 * sent neither, which is common for unmetered subscriptions.
 */
@Composable
fun SubscriptionUsageCard(
    subscription: Subscription,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    val used = (subscription.upload ?: 0L) + (subscription.download ?: 0L)
    val total = subscription.total?.takeIf { it > 0 }
    val expire = subscription.expire?.takeIf { it > 0 }

    // Nothing to say: no quota and no expiry.
    if (total == null && expire == null) return

    val fraction = if (total != null) (used.toFloat() / total).coerceIn(0f, 1f) else 0f
    val now = System.currentTimeMillis()
    val expired = expire != null && expire <= now

    val warningColor = if (LocalMythaiaDarkTheme.current) WarningDark else WarningLight
    val accent: Color = when {
        expired -> MaterialTheme.colorScheme.error
        total != null && fraction >= 0.95f -> MaterialTheme.colorScheme.error
        total != null && fraction >= 0.8f -> warningColor
        // Under a week left reads as a warning even with quota to spare.
        expire != null && expire - now < WEEK_MS -> warningColor
        else -> MaterialTheme.colorScheme.primary
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = subscription.name,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (expire != null) {
                    Text(
                        text = if (expired) {
                            stringResource(R.string.subscription_expired)
                        } else {
                            stringResource(
                                R.string.subscription_expires,
                                DateUtils.getRelativeTimeSpanString(
                                    expire, now, DateUtils.MINUTE_IN_MILLIS
                                ).toString()
                            )
                        },
                        style = MaterialTheme.typography.labelMedium,
                        color = accent,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            if (total != null) {
                Spacer(modifier = Modifier.height(10.dp))
                LinearProgressIndicator(
                    progress = { fraction },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(6.dp),
                    color = accent,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                    // The default gap and stop indicator read as clutter at
                    // this size; the bar is the whole point.
                    strokeCap = androidx.compose.ui.graphics.StrokeCap.Round,
                    gapSize = 0.dp,
                    drawStopIndicator = {}
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = stringResource(
                            R.string.subscription_used,
                            Formatter.formatShortFileSize(context, used),
                            Formatter.formatShortFileSize(context, total)
                        ),
                        style = MaterialTheme.typography.bodySmall
                            .copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Text(
                        text = "${(fraction * 100).toInt()}%",
                        style = MaterialTheme.typography.bodySmall
                            .copy(fontFamily = FontFamily.Monospace),
                        color = accent
                    )
                }
            }
        }
    }
}

private const val WEEK_MS = 7L * 24 * 60 * 60 * 1000
