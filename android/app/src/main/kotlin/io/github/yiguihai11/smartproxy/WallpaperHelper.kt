package io.github.yiguihai11.smartproxy

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

object WallpaperHelper {

    private const val TAG = "WallpaperHelper"

    /**
     * 读取已保存的自定义壁纸 Bitmap。未启用或文件不存在时返回 null。
     */
    fun loadWallpaperBitmap(context: Context): Bitmap? {
        if (!AppPrefs.isCustomWallpaperEnabled(context)) return null
        val file = AppPrefs.customWallpaperFile(context)
        if (!file.exists() || file.length() == 0L) return null
        return runCatching {
            BitmapFactory.decodeFile(file.absolutePath)
        }.onFailure { Log.e(TAG, "Failed to decode saved wallpaper", it) }.getOrNull()
    }

    /**
     * 将用户选中的图片保存为自定义壁纸。
     * 单次消费 InputStream 复制到应用缓存临时文件，再做 bounds/decode/exif 计算，
     * 彻底解决 PhotoPicker/MediaStore Uri 多次 openInputStream 权限失效或无法 seek 的问题。
     */
    fun saveWallpaper(context: Context, uri: Uri, initialStream: InputStream? = null): Boolean {
        val tempRawFile = File(context.cacheDir, "picked_raw_wallpaper.tmp")
        val destFile = AppPrefs.customWallpaperFile(context)
        val tempDestFile = File(context.filesDir, "custom_wallpaper_tmp.jpg")

        try {
            // 1. 单次读取输入流至私有缓存文件
            val inStream = initialStream ?: context.contentResolver.openInputStream(uri)
            if (inStream == null) {
                Log.e(TAG, "Could not open InputStream for uri: $uri")
                return false
            }

            val bytesCopied = inStream.use { input ->
                FileOutputStream(tempRawFile).use { output ->
                    input.copyTo(output)
                }
            }

            if (bytesCopied <= 0L || !tempRawFile.exists()) {
                Log.e(TAG, "Empty file copied: $bytesCopied bytes")
                tempRawFile.delete()
                return false
            }

            // 2. 读取图片宽高做等比采样
            val boundsOptions = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeFile(tempRawFile.absolutePath, boundsOptions)

            val origWidth = boundsOptions.outWidth
            val origHeight = boundsOptions.outHeight
            if (origWidth <= 0 || origHeight <= 0) {
                Log.e(TAG, "Invalid image dimensions: ${origWidth}x${origHeight}")
                tempRawFile.delete()
                return false
            }

            val dm = context.resources.displayMetrics
            val maxScreenDim = maxOf(dm.widthPixels, dm.heightPixels).coerceAtLeast(2160)

            var sampleSize = 1
            while (origWidth / (sampleSize * 2) >= maxScreenDim || origHeight / (sampleSize * 2) >= maxScreenDim) {
                sampleSize *= 2
            }

            // 3. 解码采样后的原图
            val decodeOptions = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
                inPreferredConfig = Bitmap.Config.ARGB_8888
            }
            val decodedBitmap = BitmapFactory.decodeFile(tempRawFile.absolutePath, decodeOptions)
            if (decodedBitmap == null) {
                Log.e(TAG, "Failed to decode bitmap from ${tempRawFile.absolutePath}")
                tempRawFile.delete()
                return false
            }

            // 4. 读取 EXIF 并矫正方向 (直接基于本地缓存临时文件，无流重开与 seek 风险)
            val matrix = Matrix()
            runCatching {
                val exif = ExifInterface(tempRawFile.absolutePath)
                when (exif.getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)) {
                    ExifInterface.ORIENTATION_ROTATE_90 -> matrix.postRotate(90f)
                    ExifInterface.ORIENTATION_ROTATE_180 -> matrix.postRotate(180f)
                    ExifInterface.ORIENTATION_ROTATE_270 -> matrix.postRotate(270f)
                    ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> matrix.postScale(-1f, 1f)
                    ExifInterface.ORIENTATION_FLIP_VERTICAL -> matrix.postScale(1f, -1f)
                }
            }.onFailure { Log.w(TAG, "ExifInterface read failed", it) }

            // 缓存的原始临时文件用完立即清理
            tempRawFile.delete()

            val finalBitmap = if (!matrix.isIdentity) {
                val transformed = Bitmap.createBitmap(
                    decodedBitmap,
                    0,
                    0,
                    decodedBitmap.width,
                    decodedBitmap.height,
                    matrix,
                    true
                )
                if (transformed != decodedBitmap) {
                    decodedBitmap.recycle()
                }
                transformed
            } else {
                decodedBitmap
            }

            // 5. 压缩并原子重命名存储
            FileOutputStream(tempDestFile).use { out ->
                finalBitmap.compress(Bitmap.CompressFormat.JPEG, 90, out)
            }
            finalBitmap.recycle()

            if (tempDestFile.exists() && tempDestFile.length() > 0L) {
                if (destFile.exists()) {
                    destFile.delete()
                }
                tempDestFile.renameTo(destFile)
            } else {
                Log.e(TAG, "Failed to write compressed file")
                return false
            }

            AppPrefs.setCustomWallpaperEnabled(context, true)
            Log.i(TAG, "Wallpaper successfully saved (${destFile.length()} bytes)")
            return true
        } catch (e: Throwable) {
            Log.e(TAG, "saveWallpaper failed", e)
            tempRawFile.delete()
            tempDestFile.delete()
            return false
        }
    }

    fun saveWallpaperFromUri(context: Context, uri: Uri): Boolean =
        saveWallpaper(context, uri, null)

    /**
     * 清理自定义壁纸并重置回默认极光
     */
    fun clearWallpaper(context: Context) {
        AppPrefs.setCustomWallpaperEnabled(context, false)
        val file = AppPrefs.customWallpaperFile(context)
        if (file.exists()) {
            file.delete()
        }
    }
}
