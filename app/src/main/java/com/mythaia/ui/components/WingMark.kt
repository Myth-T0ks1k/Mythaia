package com.mythaia.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke

/**
 * The Mythaia "WingMark": three feather strokes fanning up-right from a single
 * origin at bottom-left. Drawn as strokes only (no fill) with round caps, in a
 * 100x100 design space scaled uniformly to the smaller canvas dimension.
 *
 * The caller must give the canvas a size (e.g. Modifier.size(30.dp)).
 *
 * @param color stroke color — azure on light chrome, bone inside azure/ink fills.
 * @param strokeScale multiplies all three stroke widths (1f = reference weights
 *   8.5 / 8.0 / 7.5 in design-space units).
 */
@Composable
fun WingMark(
    modifier: Modifier = Modifier,
    color: Color,
    strokeScale: Float = 1f
) {
    Canvas(modifier = modifier) {
        val s = minOf(size.width, size.height) / 100f

        fun feather(cx: Float, cy: Float, ex: Float, ey: Float, width: Float) {
            val path = Path().apply {
                moveTo(20f * s, 82f * s)
                quadraticTo(cx * s, cy * s, ex * s, ey * s)
            }
            drawPath(
                path = path,
                color = color,
                style = Stroke(width = width * s * strokeScale, cap = StrokeCap.Round)
            )
        }

        feather(21f, 32f, 82f, 20f, 8.5f)
        feather(29f, 47f, 69f, 38f, 8.0f)
        feather(36f, 61f, 57f, 55f, 7.5f)
    }
}
