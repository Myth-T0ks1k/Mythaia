package com.mythaia.ui.scanner

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The scanner's frame decoding without a camera: a QR code drawn into a
 * luminance plane the way CameraX hands one over — padded rows, any
 * rotation, light on dark.
 */
class QrFrameDecoderTest {
    private val link = "vless://00000000-0000-0000-0000-000000000000@example.com:443" +
        "?security=reality&sni=www.example.org&fp=chrome#Сервер · Frankfurt"

    /** A [width]x[height] frame, rows [stride] bytes apart, with the code at [left],[top]. */
    private fun frame(
        text: String, width: Int, height: Int, stride: Int,
        left: Int, top: Int, size: Int, rotate: Int = 0, inverted: Boolean = false
    ): ByteArray {
        val matrix = QRCodeWriter().encode(
            text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8")
        )
        val light = if (inverted) 30 else 220
        val dark = if (inverted) 220 else 30
        val data = ByteArray(stride * height) { light.toByte() }
        for (y in 0 until size) for (x in 0 until size) {
            val (mx, my) = when (rotate) {
                90 -> y to size - 1 - x
                180 -> size - 1 - x to size - 1 - y
                270 -> size - 1 - y to x
                else -> x to y
            }
            if (matrix[mx, my]) data[(top + y) * stride + left + x] = dark.toByte()
        }
        return data
    }

    @Test
    fun `reads a share link from a padded camera frame`() {
        val data = frame(link, width = 1280, height = 720, stride = 1344, left = 420, top = 120, size = 440)
        assertEquals(link, QrFrameDecoder().decode(data, 1280, 720, 1344))
    }

    @Test
    fun `reads a code whatever the sensor rotation`() {
        val decoder = QrFrameDecoder()
        for (rotate in listOf(90, 180, 270)) {
            val data = frame(link, 640, 480, 640, 100, 40, 400, rotate = rotate)
            assertEquals("rotation $rotate", link, decoder.decode(data, 640, 480))
        }
    }

    @Test
    fun `reads a light code on a dark screen`() {
        val data = frame(link, 640, 480, 640, 100, 40, 400, inverted = true)
        assertEquals(link, QrFrameDecoder().decode(data, 640, 480))
    }

    @Test
    fun `an empty frame has no code`() {
        assertNull(QrFrameDecoder().decode(ByteArray(640 * 480) { 128.toByte() }, 640, 480))
    }
}
