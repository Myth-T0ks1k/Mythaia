package com.mythaia.desktop.util

import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.client.j2se.BufferedImageLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.multi.qrcode.QRCodeMultiReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.awt.GraphicsEnvironment
import java.awt.Rectangle
import java.awt.Robot
import java.awt.image.BufferedImage

/** QR codes: one for sharing a server, and reading whatever is on the screens. */
object Qr {

    /** A QR image of [text], [size] pixels square, black on white. */
    fun encode(text: String, size: Int = 512): ImageBitmap? = runCatching {
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1)
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
        for (y in 0 until size) for (x in 0 until size) {
            image.setRGB(x, y, if (matrix.get(x, y)) 0x000000 else 0xFFFFFF)
        }
        image.toComposeImageBitmap()
    }.getOrNull()

    /** Every QR code visible on every screen right now, as text. */
    fun scanScreens(): List<String> {
        val found = LinkedHashSet<String>()
        val screens = GraphicsEnvironment.getLocalGraphicsEnvironment().screenDevices
        for (screen in screens) {
            val bounds: Rectangle = screen.defaultConfiguration.bounds
            val shot = runCatching { Robot(screen).createScreenCapture(Rectangle(0, 0, bounds.width, bounds.height)) }.getOrNull()
                ?: continue
            found += decodeAll(shot)
        }
        return found.toList()
    }

    private fun decodeAll(image: BufferedImage): List<String> {
        val bitmap = BinaryBitmap(HybridBinarizer(BufferedImageLuminanceSource(image)))
        val hints = mapOf(DecodeHintType.TRY_HARDER to true, DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
        runCatching { QRCodeMultiReader().decodeMultiple(bitmap, hints) }.getOrNull()
            ?.mapNotNull { it.text }?.takeIf { it.isNotEmpty() }?.let { return it }
        return runCatching { listOf(MultiFormatReader().decode(bitmap, hints).text) }.getOrDefault(emptyList())
    }
}
