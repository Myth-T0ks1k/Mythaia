package com.mythaia.ui.scanner

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer

/**
 * Finds a QR code in a camera frame: the luminance (Y) plane of a
 * YUV_420_888 image, rows [rowStride] bytes apart.
 *
 * ZXing rather than ML Kit: it is free software, works offline and needs no
 * Google Play services, so scanning works on every phone — and the F-Droid
 * build can carry it. A QR code's finder patterns make it readable at any
 * rotation, so the frame is decoded as the sensor gives it.
 *
 * Not thread-safe: one instance per analyzer thread.
 */
internal class QrFrameDecoder {
    private val reader = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
                // Share links are UTF-8; without this ZXing guesses, and a
                // Cyrillic server name can come out as Shift_JIS.
                DecodeHintType.CHARACTER_SET to "UTF-8"
            )
        )
    }

    /** The text of the QR code in the frame, or null when there is none. */
    fun decode(luminance: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
        val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)
        // Light-on-dark codes (a dark theme's QR screen) read only inverted.
        return decode(source) ?: decode(source.invert())
    }

    private fun decode(source: LuminanceSource): String? = try {
        reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
    } catch (_: ReaderException) {
        null
    } finally {
        reader.reset()
    }
}
