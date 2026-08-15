package io.github.yiguihai11.smartproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import androidx.core.app.ServiceCompat

/**
 * 保活通知(§4.3):极简,只显示"正在运行" + 一个停止按钮。
 * setOngoing(true) 不可滑动清除、无清除按钮;渠道 IMPORTANCE_LOW 不打扰。
 */
object NotificationHelper {

    const val CHANNEL_ID = "vpn_service"
    const val NOTIFICATION_ID = 1001
    const val NOTIFICATION_ID_DISCONNECTED = 1002

    const val ACTION_STOP = "io.github.yiguihai11.smartproxy.STOP_VPN"

    fun ensureChannel(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.notification_channel_vpn),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            setShowBadge(false)
            setSound(null, null)
        }
        nm.createNotificationChannel(channel)
    }

    fun build(context: Context): Notification {
        // 停止按钮:用户主动停止 → 服务静默停(§4.5 userInitiatedStop)。
        val stopIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            context, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val content = android.app.Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notification_running))
            .setOngoing(true)
            .setShowWhen(false)
            .addAction(
                Notification.Action.Builder(
                    null,
                    context.getString(R.string.notification_stop),
                    stopPending
                ).build()
            )
        return content.build()
    }

    fun isStopAction(intent: Intent?): Boolean =
        intent?.action == ACTION_STOP

    /** §4.5 被动断连提示:一次性(auto-cancel)通知,非 ongoing,点掉即消失。 */
    fun notifyDisconnected(context: Context) {
        ensureChannel(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val n = android.app.Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.notification_disconnected))
            .setAutoCancel(true)
            .setShowWhen(false)
            .build()
        nm.notify(NOTIFICATION_ID_DISCONNECTED, n)
    }

    /** 启动前台并带 specialUse 类型(API 34+ 必需;manifest 已声明,这里显式传参双保险)。 */
    fun startForeground(service: Service) {
        ensureChannel(service)
        ServiceCompat.startForeground(
            service,
            NOTIFICATION_ID,
            build(service),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )
    }
}
