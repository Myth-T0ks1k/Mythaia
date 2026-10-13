package com.mythaia.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.mythaia.R
import com.mythaia.ui.theme.Azure
import com.mythaia.ui.theme.Bone

/**
 * The hero connect control, carrying the WingMark at its heart.
 *
 * Idle: paper circle with a hairline outline and an azure mark.
 * Connected: solid azure fill with bone feather strokes and a soft bone
 * border so the circle reads against the connected gradient.
 * All state changes crossfade over 600ms, in step with the background.
 */
@Composable
fun PowerButton(
    isConnected: Boolean,
    isTransitioning: Boolean,
    enabled: Boolean,
    /** What the tunnel is doing, in words, for a screen reader. */
    statusText: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val containerColor by animateColorAsState(
        targetValue = if (isConnected) Azure else MaterialTheme.colorScheme.surface,
        animationSpec = tween(600),
        label = "powerContainer"
    )
    val markColor by animateColorAsState(
        targetValue = if (isConnected) Bone else MaterialTheme.colorScheme.primary,
        animationSpec = tween(600),
        label = "powerMark"
    )
    val borderColor by animateColorAsState(
        targetValue = if (isConnected) Bone.copy(alpha = 0.35f) else MaterialTheme.colorScheme.outline,
        animationSpec = tween(600),
        label = "powerBorder"
    )
    val label = stringResource(R.string.power_button)

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier.size(160.dp)
    ) {
        Surface(
            shape = CircleShape,
            color = containerColor,
            border = BorderStroke(1.dp, borderColor),
            modifier = Modifier
                .size(140.dp)
                // The state is told by colour alone, so without this
                // TalkBack announced nothing but "Button".
                .semantics {
                    contentDescription = label
                    stateDescription = statusText
                    role = Role.Switch
                },
            onClick = onClick,
            enabled = enabled
        ) {
            Box(contentAlignment = Alignment.Center) {
                if (isTransitioning) {
                    CircularProgressIndicator(
                        color = markColor,
                        modifier = Modifier.size(44.dp),
                        strokeWidth = 3.dp
                    )
                } else {
                    WingMark(
                        modifier = Modifier.size(68.dp),
                        color = markColor
                    )
                }
            }
        }
    }
}
