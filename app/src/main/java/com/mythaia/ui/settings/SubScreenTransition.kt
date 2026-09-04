package com.mythaia.ui.settings

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.IntOffset

/**
 * Horizontal push/pop transition used for in-screen drill-down navigation.
 *
 * The root destination is always represented by [rootKey]; anything else is
 * treated as a child route. Going root → child eases the child in from the end
 * of the reading direction; going child → root eases it back out the same way.
 * That is the right in a left-to-right locale and the left in Arabic or Farsi,
 * where sliding the other way reads as going backwards.
 *
 * Motion follows the Wing direction — a gentle 250ms fade-through with a
 * short slide (about a quarter of the width) instead of a hard full-width
 * push; no scaling, no overshoot.
 */
@Composable
internal fun <T> SubScreenHost(
    state: T,
    rootKey: T,
    content: @Composable (T) -> Unit
) {
    // Drilling in moves toward the end of the reading direction, which is left
    // in Arabic and Farsi. Read here, in a composable, because the transition
    // spec below is not one.
    val rightToLeft = LocalLayoutDirection.current == LayoutDirection.Rtl
    AnimatedContent(
        targetState = state,
        transitionSpec = { slideTransition(rootKey, rightToLeft) },
        label = "sub-screen"
    ) { current ->
        content(current)
    }
}

private fun <T> AnimatedContentTransitionScope<T>.slideTransition(
    rootKey: T,
    rightToLeft: Boolean
): ContentTransform {
    val goingBack = targetState == rootKey
    // Mirroring the offsets is enough: the two directions are exact opposites.
    val sign = if (rightToLeft) -1 else 1
    val enterSpec = tween<Float>(durationMillis = 250, easing = FastOutSlowInEasing)
    val exitSpec = tween<Float>(durationMillis = 200, easing = FastOutSlowInEasing)
    val slideInSpec = tween<IntOffset>(durationMillis = 250, easing = FastOutSlowInEasing)
    val slideOutSpec = tween<IntOffset>(durationMillis = 250, easing = FastOutSlowInEasing)
    return if (goingBack) {
        (slideInHorizontally(animationSpec = slideInSpec) { sign * -it / 8 } + fadeIn(animationSpec = enterSpec)) togetherWith
            (slideOutHorizontally(animationSpec = slideOutSpec) { sign * it / 4 } + fadeOut(animationSpec = exitSpec))
    } else {
        (slideInHorizontally(animationSpec = slideInSpec) { sign * it / 4 } + fadeIn(animationSpec = enterSpec)) togetherWith
            (slideOutHorizontally(animationSpec = slideOutSpec) { sign * -it / 8 } + fadeOut(animationSpec = exitSpec))
    }
}
