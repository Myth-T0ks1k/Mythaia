package com.mythaia.ui.home

import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import java.time.LocalDate
import java.time.temporal.ChronoUnit
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

/**
 * The little drawings that line the edges of the home screen while the
 * tunnel is up.
 *
 * Every one is drawn in code, in the same hand as the WingMark: round-capped
 * strokes, no fills to speak of, one colour. That keeps them light (no
 * bitmaps in the APK) and lets them take the theme's colour on either ground.
 */
enum class Sticker {
    SUN, MOON, STAR, CLOUD, FEATHER, LEAF, BOLT, HEART, FLOWER, SNOWFLAKE,
    GIFT, BALLOON, PUMPKIN, FIREWORK, TULIP, CONFETTI,

    /** Shown instead of the set when a connection has just failed. */
    RED_X
}

/**
 * Which stickers today gets.
 *
 * A holiday owns the day before, the day itself and the day after; outside
 * those windows each weekday has its own quiet set, so the edges change a
 * little through the week without ever shouting.
 */
object StickerCalendar {

    private data class Holiday(val month: Int, val day: Int, val stickers: List<Sticker>)

    // International days, with Nowruz for the spring: the app's home market
    // keeps it, and the tulip and sun read as spring anywhere.
    private val holidays = listOf(
        Holiday(1, 1, listOf(Sticker.FIREWORK, Sticker.STAR, Sticker.SNOWFLAKE, Sticker.GIFT)),
        Holiday(2, 14, listOf(Sticker.HEART, Sticker.FLOWER, Sticker.HEART, Sticker.STAR)),
        Holiday(3, 8, listOf(Sticker.FLOWER, Sticker.TULIP, Sticker.HEART, Sticker.SUN)),
        Holiday(3, 21, listOf(Sticker.TULIP, Sticker.SUN, Sticker.LEAF, Sticker.FLOWER)),
        Holiday(4, 1, listOf(Sticker.CONFETTI, Sticker.BALLOON, Sticker.STAR, Sticker.SUN)),
        Holiday(5, 1, listOf(Sticker.LEAF, Sticker.FLOWER, Sticker.SUN, Sticker.TULIP)),
        Holiday(6, 1, listOf(Sticker.BALLOON, Sticker.CONFETTI, Sticker.SUN, Sticker.STAR)),
        Holiday(10, 31, listOf(Sticker.PUMPKIN, Sticker.MOON, Sticker.STAR, Sticker.CLOUD)),
        Holiday(12, 25, listOf(Sticker.GIFT, Sticker.SNOWFLAKE, Sticker.STAR, Sticker.MOON)),
        Holiday(12, 31, listOf(Sticker.FIREWORK, Sticker.CONFETTI, Sticker.STAR, Sticker.GIFT))
    )

    private val weekdays = listOf(
        listOf(Sticker.SUN, Sticker.CLOUD, Sticker.FEATHER, Sticker.LEAF),      // Monday
        listOf(Sticker.MOON, Sticker.STAR, Sticker.FEATHER, Sticker.CLOUD),
        listOf(Sticker.BOLT, Sticker.FEATHER, Sticker.SUN, Sticker.STAR),
        listOf(Sticker.LEAF, Sticker.FLOWER, Sticker.FEATHER, Sticker.SUN),
        listOf(Sticker.STAR, Sticker.CLOUD, Sticker.MOON, Sticker.FEATHER),
        listOf(Sticker.FEATHER, Sticker.BOLT, Sticker.LEAF, Sticker.CLOUD),
        listOf(Sticker.SUN, Sticker.HEART, Sticker.FEATHER, Sticker.STAR)       // Sunday
    )

    fun forDate(date: LocalDate = LocalDate.now()): List<Sticker> {
        for (holiday in holidays) {
            // Checked in the neighbouring years too, so 31 December's
            // "day after" and 1 January's "day before" cross the year line.
            for (year in date.year - 1..date.year + 1) {
                val on = runCatching { LocalDate.of(year, holiday.month, holiday.day) }.getOrNull() ?: continue
                if (abs(ChronoUnit.DAYS.between(on, date)) <= 1) return holiday.stickers
            }
        }
        return weekdays[date.dayOfWeek.value - 1]
    }
}

/** One sticker, drawn to fill the modifier's size. */
@Composable
fun StickerGlyph(
    sticker: Sticker,
    color: Color,
    modifier: Modifier = Modifier,
    strokeScale: Float = 1f
) {
    Canvas(modifier = modifier) {
        val s = minOf(size.width, size.height) / 100f
        val stroke = Stroke(width = 7f * s * strokeScale, cap = StrokeCap.Round, join = StrokeJoin.Round)
        when (sticker) {
            Sticker.SUN -> drawSun(s, color, stroke)
            Sticker.MOON -> drawMoon(s, color, stroke)
            Sticker.STAR -> drawStar(s, color, stroke)
            Sticker.CLOUD -> drawCloud(s, color, stroke)
            Sticker.FEATHER -> drawFeather(s, color, strokeScale)
            Sticker.LEAF -> drawLeaf(s, color, stroke)
            Sticker.BOLT -> drawBolt(s, color, stroke)
            Sticker.HEART -> drawHeart(s, color, stroke)
            Sticker.FLOWER -> drawFlower(s, color, stroke)
            Sticker.SNOWFLAKE -> drawSnowflake(s, color, stroke)
            Sticker.GIFT -> drawGift(s, color, stroke)
            Sticker.BALLOON -> drawBalloon(s, color, stroke)
            Sticker.PUMPKIN -> drawPumpkin(s, color, stroke)
            Sticker.FIREWORK -> drawFirework(s, color, stroke)
            Sticker.TULIP -> drawTulip(s, color, stroke)
            Sticker.CONFETTI -> drawConfetti(s, color)
            Sticker.RED_X -> drawRedX(s, color, stroke)
        }
    }
}

private fun DrawScope.p(x: Float, y: Float, s: Float) = Offset(x * s, y * s)

private fun DrawScope.drawSun(s: Float, color: Color, stroke: Stroke) {
    drawCircle(color, radius = 18f * s, center = p(50f, 50f, s), style = stroke)
    for (i in 0 until 8) {
        val a = i * PI / 4
        val from = p(50f + 28f * cos(a).toFloat(), 50f + 28f * sin(a).toFloat(), s)
        val to = p(50f + 40f * cos(a).toFloat(), 50f + 40f * sin(a).toFloat(), s)
        drawLine(color, from, to, strokeWidth = stroke.width, cap = StrokeCap.Round)
    }
}

private fun DrawScope.drawMoon(s: Float, color: Color, stroke: Stroke) {
    val path = Path().apply {
        moveTo(62f * s, 14f * s)
        cubicTo(30f * s, 20f * s, 22f * s, 68f * s, 58f * s, 86f * s)
        cubicTo(38f * s, 72f * s, 40f * s, 30f * s, 62f * s, 14f * s)
        close()
    }
    drawPath(path, color, style = stroke)
    drawCircle(color, radius = 3f * s, center = p(78f, 30f, s))
}

private fun DrawScope.drawStar(s: Float, color: Color, stroke: Stroke) {
    val path = Path()
    for (i in 0 until 10) {
        val r = if (i % 2 == 0) 38f else 16f
        val a = -PI / 2 + i * PI / 5
        val pt = p(50f + r * cos(a).toFloat(), 52f + r * sin(a).toFloat(), s)
        if (i == 0) path.moveTo(pt.x, pt.y) else path.lineTo(pt.x, pt.y)
    }
    path.close()
    drawPath(path, color, style = stroke)
}

private fun DrawScope.drawCloud(s: Float, color: Color, stroke: Stroke) {
    val path = Path().apply {
        moveTo(26f * s, 70f * s)
        cubicTo(8f * s, 70f * s, 10f * s, 44f * s, 30f * s, 46f * s)
        cubicTo(32f * s, 26f * s, 60f * s, 24f * s, 64f * s, 42f * s)
        cubicTo(84f * s, 38f * s, 92f * s, 66f * s, 72f * s, 70f * s)
        close()
    }
    drawPath(path, color, style = stroke)
}

private fun DrawScope.drawFeather(s: Float, color: Color, strokeScale: Float) {
    fun feather(cx: Float, cy: Float, ex: Float, ey: Float, width: Float) {
        val path = Path().apply {
            moveTo(20f * s, 82f * s)
            quadraticTo(cx * s, cy * s, ex * s, ey * s)
        }
        drawPath(path, color, style = Stroke(width = width * s * strokeScale, cap = StrokeCap.Round))
    }
    feather(21f, 32f, 82f, 20f, 8.5f)
    feather(29f, 47f, 69f, 38f, 8.0f)
    feather(36f, 61f, 57f, 55f, 7.5f)
}

private fun DrawScope.drawLeaf(s: Float, color: Color, stroke: Stroke) {
    val path = Path().apply {
        moveTo(22f * s, 80f * s)
        cubicTo(20f * s, 40f * s, 50f * s, 18f * s, 82f * s, 20f * s)
        cubicTo(84f * s, 54f * s, 60f * s, 82f * s, 22f * s, 80f * s)
        close()
    }
    drawPath(path, color, style = stroke)
    drawLine(color, p(24f, 78f, s), p(74f, 28f, s), strokeWidth = stroke.width * 0.7f, cap = StrokeCap.Round)
}

private fun DrawScope.drawBolt(s: Float, color: Color, stroke: Stroke) {
    val path = Path().apply {
        moveTo(58f * s, 10f * s)
        lineTo(30f * s, 56f * s)
        lineTo(50f * s, 56f * s)
        lineTo(42f * s, 90f * s)
        lineTo(72f * s, 42f * s)
        lineTo(52f * s, 42f * s)
        close()
    }
    drawPath(path, color, style = stroke)
}

private fun DrawScope.drawHeart(s: Float, color: Color, stroke: Stroke) {
    val path = Path().apply {
        moveTo(50f * s, 84f * s)
        cubicTo(14f * s, 58f * s, 14f * s, 24f * s, 36f * s, 22f * s)
        cubicTo(44f * s, 22f * s, 48f * s, 28f * s, 50f * s, 34f * s)
        cubicTo(52f * s, 28f * s, 56f * s, 22f * s, 64f * s, 22f * s)
        cubicTo(86f * s, 24f * s, 86f * s, 58f * s, 50f * s, 84f * s)
        close()
    }
    drawPath(path, color, style = stroke)
}

private fun DrawScope.drawFlower(s: Float, color: Color, stroke: Stroke) {
    for (i in 0 until 5) {
        val a = -PI / 2 + i * 2 * PI / 5
        drawCircle(color, radius = 13f * s, center = p(50f + 22f * cos(a).toFloat(), 50f + 22f * sin(a).toFloat(), s), style = stroke)
    }
    drawCircle(color, radius = 8f * s, center = p(50f, 50f, s))
}

private fun DrawScope.drawSnowflake(s: Float, color: Color, stroke: Stroke) {
    for (i in 0 until 6) {
        rotate(degrees = i * 60f, pivot = p(50f, 50f, s)) {
            drawLine(color, p(50f, 50f, s), p(50f, 12f, s), strokeWidth = stroke.width, cap = StrokeCap.Round)
            drawLine(color, p(50f, 24f, s), p(40f, 16f, s), strokeWidth = stroke.width * 0.8f, cap = StrokeCap.Round)
            drawLine(color, p(50f, 24f, s), p(60f, 16f, s), strokeWidth = stroke.width * 0.8f, cap = StrokeCap.Round)
        }
    }
}

private fun DrawScope.drawGift(s: Float, color: Color, stroke: Stroke) {
    drawRoundRect(color, topLeft = p(18f, 40f, s), size = Size(64f * s, 46f * s),
        cornerRadius = androidx.compose.ui.geometry.CornerRadius(6f * s), style = stroke)
    drawLine(color, p(50f, 40f, s), p(50f, 86f, s), strokeWidth = stroke.width, cap = StrokeCap.Round)
    drawLine(color, p(18f, 56f, s), p(82f, 56f, s), strokeWidth = stroke.width * 0.8f, cap = StrokeCap.Round)
    val bow = Path().apply {
        moveTo(50f * s, 40f * s)
        cubicTo(30f * s, 40f * s, 26f * s, 16f * s, 50f * s, 30f * s)
        cubicTo(74f * s, 16f * s, 70f * s, 40f * s, 50f * s, 40f * s)
    }
    drawPath(bow, color, style = stroke)
}

private fun DrawScope.drawBalloon(s: Float, color: Color, stroke: Stroke) {
    drawOval(color, topLeft = p(26f, 10f, s), size = Size(48f * s, 58f * s), style = stroke)
    val string = Path().apply {
        moveTo(50f * s, 70f * s)
        cubicTo(60f * s, 78f * s, 40f * s, 86f * s, 52f * s, 96f * s)
    }
    drawPath(string, color, style = Stroke(width = stroke.width * 0.6f, cap = StrokeCap.Round))
}

private fun DrawScope.drawPumpkin(s: Float, color: Color, stroke: Stroke) {
    drawOval(color, topLeft = p(14f, 34f, s), size = Size(72f * s, 54f * s), style = stroke)
    drawOval(color, topLeft = p(32f, 34f, s), size = Size(36f * s, 54f * s), style = Stroke(stroke.width * 0.6f, cap = StrokeCap.Round))
    val stem = Path().apply {
        moveTo(50f * s, 34f * s)
        cubicTo(50f * s, 22f * s, 56f * s, 18f * s, 62f * s, 14f * s)
    }
    drawPath(stem, color, style = stroke)
}

private fun DrawScope.drawFirework(s: Float, color: Color, stroke: Stroke) {
    for (i in 0 until 8) {
        val a = i * PI / 4 + PI / 8
        val inner = p(50f + 12f * cos(a).toFloat(), 50f + 12f * sin(a).toFloat(), s)
        val outer = p(50f + 36f * cos(a).toFloat(), 50f + 36f * sin(a).toFloat(), s)
        drawLine(color, inner, outer, strokeWidth = stroke.width * 0.8f, cap = StrokeCap.Round)
        drawCircle(color, radius = 4f * s, center = p(50f + 44f * cos(a).toFloat(), 50f + 44f * sin(a).toFloat(), s))
    }
}

private fun DrawScope.drawTulip(s: Float, color: Color, stroke: Stroke) {
    val cup = Path().apply {
        moveTo(30f * s, 22f * s)
        lineTo(30f * s, 44f * s)
        cubicTo(30f * s, 58f * s, 70f * s, 58f * s, 70f * s, 44f * s)
        lineTo(70f * s, 22f * s)
        lineTo(60f * s, 34f * s)
        lineTo(50f * s, 20f * s)
        lineTo(40f * s, 34f * s)
        close()
    }
    drawPath(cup, color, style = stroke)
    drawLine(color, p(50f, 58f, s), p(50f, 92f, s), strokeWidth = stroke.width, cap = StrokeCap.Round)
    val leaf = Path().apply {
        moveTo(50f * s, 84f * s)
        cubicTo(36f * s, 82f * s, 26f * s, 70f * s, 24f * s, 60f * s)
        cubicTo(38f * s, 62f * s, 48f * s, 72f * s, 50f * s, 84f * s)
    }
    drawPath(leaf, color, style = Stroke(stroke.width * 0.8f, cap = StrokeCap.Round))
}

private fun DrawScope.drawConfetti(s: Float, color: Color) {
    val pieces = listOf(
        Triple(20f, 22f, 20f), Triple(70f, 16f, -30f), Triple(44f, 46f, 45f),
        Triple(82f, 56f, 10f), Triple(28f, 70f, -15f), Triple(62f, 82f, 35f)
    )
    for ((x, y, deg) in pieces) {
        rotate(deg, pivot = p(x, y, s)) {
            drawRoundRect(color, topLeft = p(x - 7f, y - 4f, s), size = Size(14f * s, 8f * s),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(2f * s))
        }
    }
    drawCircle(color, radius = 4f * s, center = p(50f, 20f, s))
    drawCircle(color, radius = 3f * s, center = p(14f, 50f, s))
    drawCircle(color, radius = 3f * s, center = p(86f, 30f, s))
}

private fun DrawScope.drawRedX(s: Float, color: Color, stroke: Stroke) {
    drawCircle(color, radius = 40f * s, center = p(50f, 50f, s), style = Stroke(stroke.width * 0.8f))
    val w = stroke.width * 1.3f
    drawLine(color, p(32f, 32f, s), p(68f, 68f, s), strokeWidth = w, cap = StrokeCap.Round)
    drawLine(color, p(68f, 32f, s), p(32f, 68f, s), strokeWidth = w, cap = StrokeCap.Round)
}
