package com.mythaia.desktop.util

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.awt.Color
import java.awt.RenderingHints
import java.awt.image.BaseMultiResolutionImage
import java.awt.image.BufferedImage

/** Reading a code off a screen capture taken at a display scale above 100 %. */
class QrTest {

    /** [text] as a QR code of [module] pixels per module, at [x],[y] on a white [width]×[height] screen. */
    private fun screen(text: String, module: Int, width: Int, height: Int, x: Int, y: Int): BufferedImage {
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 0))
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
        val g = image.createGraphics()
        g.color = Color.WHITE
        g.fillRect(0, 0, width, height)
        g.color = Color.BLACK
        for (my in 0 until matrix.height) for (mx in 0 until matrix.width) {
            if (matrix.get(mx, my)) g.fillRect(x + mx * module, y + my * module, module, module)
        }
        g.dispose()
        return image
    }

    /** What Robot makes of a capture at a display scale: bilinear, down to the logical size. */
    private fun scaledDown(image: BufferedImage, scale: Double): BufferedImage {
        val width = (image.width / scale).toInt()
        val height = (image.height / scale).toInt()
        val out = BufferedImage(width, height, image.type)
        val g = out.createGraphics()
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR)
        g.drawImage(image, 0, 0, width, height, 0, 0, image.width, image.height, null)
        g.dispose()
        return out
    }

    @Test
    fun `a code too small for the scaled capture is read from the full one`() {
        val link = "vless://0b2c7c4e-8d4e-4a8a-9d4f-1b2c3d4e5f60@203.0.113.7:443?security=reality&sni=www.example.com" +
            "&pbk=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde&sid=6ba85179&fp=chrome&type=tcp#Server%20one"
        val full = screen(link, module = 2, width = 1800, height = 1200, x = 1100, y = 700)
        val scaled = scaledDown(full, 2.5)
        assertTrue("the scaled capture must be unreadable for this test to mean anything", Qr.decodeAll(scaled).isEmpty())
        assertEquals(listOf(link), Qr.decodeBest(BaseMultiResolutionImage(scaled, full)))
    }

    @Test
    fun `a capture at 100 percent has one variant and is read as it is`() {
        val image = screen("ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.4:8388#plain", module = 4, width = 800, height = 600, x = 300, y = 200)
        assertEquals(listOf("ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.4:8388#plain"), Qr.decodeBest(BaseMultiResolutionImage(image)))
    }
}
