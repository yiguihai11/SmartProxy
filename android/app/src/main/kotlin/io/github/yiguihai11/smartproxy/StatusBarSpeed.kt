package io.github.yiguihai11.smartproxy

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.Icon
import androidx.core.content.ContextCompat

/**
 * 状态栏网速(TrafficIndicator 式):把每秒网速文字画成 Bitmap 塞进常驻通知的 smallIcon,
 * 系统状态栏会把通知小图标画在状态栏那一行(图标按 alpha 通道被系统着色——深色状态栏→白字、
 * 浅色状态栏→黑字,所以这里统一画白字,字形靠 alpha 保留)。
 *
 * 普通 App 无法把自定义 View 嵌进 SystemUI 状态栏内部(要系统签名),这是唯一能在状态栏
 * 那一行显示自定义文字的公开路子:只要 POST_NOTIFICATIONS,不需要 SYSTEM_ALERT_WINDOW。
 *
 * 局限(系统行为,非 bug):部分 ROM 状态栏不显示通知小图标,或把非方形图标按方形矩阵缩放,
 * 宽文字可能被压小;下拉通知面板里显示的是普通通知条目(标题+正文)。
 */
object StatusBarSpeed {

    private const val CHANNEL_ID = "speed_status_bar"
    private const val NOTIFICATION_ID = 1003

    @Volatile
    private var active = false
    private var lastText: String? = null

    private fun nm(app: Context) =
        app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun canNotify(app: Context): Boolean =
        ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun ensureChannel(app: Context) {
        val ch = NotificationChannel(
            CHANNEL_ID,
            app.getString(R.string.status_speed_channel),
            NotificationManager.IMPORTANCE_LOW // LOW:无声音不弹横幅、但状态栏仍显示小图标(MIN 不显示)
        ).apply {
            setShowBadge(false)
            setSound(null, null)
            description = app.getString(R.string.status_speed_channel_desc)
        }
        nm(app).createNotificationChannel(ch)
    }

    /** 后台线程每秒调:显示「谁网速大显示谁」那个 App 的上下行(与胶囊同源);label 非空时
     *  下拉面板标题带 App 名。文字没变就不重发(避免 notify 抖动);权限缺失或异常时隐藏,不崩。 */
    fun update(app: Context, upBps: Long, downBps: Long, label: String? = null) {
        runCatching {
            if (!canNotify(app)) {
                if (active) hide(app)
                return
            }
            val up = fmt(upBps)
            val down = fmt(downBps)
            // 状态栏空间极窄,固定用 ↑/↓ 紧凑拼接(忽略设置里的自定义长标签,那是给胶囊用的)。
            val text = "↑$up ↓$down"
            if (text == lastText && active) return
            ensureChannel(app)
            val bmp = renderText(app, text)
            val n = Notification.Builder(app, CHANNEL_ID)
                .setSmallIcon(Icon.createWithBitmap(bmp))
                .setContentTitle(label ?: app.getString(R.string.app_name))
                .setContentText("↑ $up/s   ↓ $down/s")
                .setOngoing(true)
                .setShowWhen(false)
                .setOnlyAlertOnce(true)
                .build()
            nm(app).notify(NOTIFICATION_ID, n)
            lastText = text
            active = true
        }
    }

    /** 关掉/断开时撤通知。幂等。任意线程。 */
    fun hide(app: Context) {
        runCatching {
            if (!active && lastText == null) return
            nm(app).cancel(NOTIFICATION_ID)
            lastText = null
            active = false
        }
    }

    /** 把网速文字画成透明底白字 Bitmap(高度按密度取,宽度随文字测量)。 */
    private fun renderText(app: Context, text: String): Bitmap {
        val density = app.resources.displayMetrics.density
        val h = (22f * density).toInt().coerceAtLeast(1)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = h * 0.84f
            typeface = Typeface.DEFAULT_BOLD
            textAlign = Paint.Align.LEFT
        }
        val pad = (2f * density).toInt()
        val w = (paint.measureText(text) + pad * 2).toInt().coerceAtLeast(h)
        val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        val fm = paint.fontMetrics
        val baseline = h / 2f - (fm.ascent + fm.descent) / 2f
        canvas.drawText(text, pad.toFloat(), baseline, paint)
        return bmp
    }

    /** 状态栏紧凑单位:≥1M 一位小数,≥1K 取整 K,其余裸字节数(0 显示 "0")。 */
    private fun fmt(bps: Long): String {
        val f = bps.toDouble()
        return when {
            f >= 1_048_576.0 -> String.format("%.1fM", f / 1_048_576.0)
            f >= 1024.0 -> "${(f / 1024.0).toInt()}K"
            else -> "$bps"
        }
    }
}
