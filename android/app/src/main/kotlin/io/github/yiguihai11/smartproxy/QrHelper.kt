package io.github.yiguihai11.smartproxy

import android.graphics.Bitmap
import android.graphics.Color
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/**
 * 面板 URL 二维码(M2,§4.4)。直接调 QRCodeWriter,不走 MultiFormatWriter 的反射,
 * R8 裁剪安全;内容过大/异常返回 null。
 */
object QrHelper {

    fun generate(content: String, size: Int = 256): Bitmap? = try {
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
        val px = IntArray(size * size)
        for (y in 0 until size) {
            for (x in 0 until size) {
                px[y * size + x] = if (matrix[x, y]) Color.BLACK else Color.WHITE
            }
        }
        Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            .apply { setPixels(px, 0, size, 0, 0, size, size) }
    } catch (e: Exception) {
        null
    }
}
