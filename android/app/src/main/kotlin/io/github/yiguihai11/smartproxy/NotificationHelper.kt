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
import org.json.JSONObject

/**
 * 保活通知(§4.3):显示当前选路策略、活跃节点及延迟，提供切换策略、刷新测速和停止按钮。
 * setOngoing(true) 不可滑动清除、无清除按钮;渠道 IMPORTANCE_LOW 不打扰。
 */
object NotificationHelper {

    const val CHANNEL_ID = "vpn_service"
    const val NOTIFICATION_ID = 1001
    const val NOTIFICATION_ID_DISCONNECTED = 1002

    const val ACTION_STOP = "io.github.yiguihai11.smartproxy.STOP_VPN"

    /** 循环切换选路策略 (latency -> failover -> round_robin)。 */
    const val ACTION_CYCLE_STRATEGY = "io.github.yiguihai11.smartproxy.CYCLE_STRATEGY"

    /** 触发上游节点并发对冲测速与重新选路。 */
    const val ACTION_REFRESH_NODES = "io.github.yiguihai11.smartproxy.REFRESH_NODES"

    /** 悬浮网速计(流量条)位置锁定/解锁切换(兼容保留)。 */
    const val ACTION_TOGGLE_SPEED_METER_LOCK = "io.github.yiguihai11.smartproxy.TOGGLE_SPEED_METER_LOCK"

    /** 通知授权补发(§4.3):startForeground 先于 POST_NOTIFICATIONS 授权执行时,系统压住
     *  通知;授权落定后重发本 action,让 FGS 只重刷通知、不动引擎。 */
    const val ACTION_REFRESH_FOREGROUND = "io.github.yiguihai11.smartproxy.REFRESH_FOREGROUND"

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

    fun getStrategyDisplayName(context: Context, strategy: String): String {
        return when (strategy.lowercase()) {
            "latency" -> context.getString(R.string.notification_strategy_latency)
            "round_robin" -> context.getString(R.string.notification_strategy_round_robin)
            "random" -> context.getString(R.string.notification_strategy_random)
            else -> context.getString(R.string.notification_strategy_failover)
        }
    }

    fun build(context: Context): Notification {
        // 点通知正文 → 打开主界面(CLEAR_TOP+SINGLE_TOP:已存在则复用同一实例,
        // 不清任务栈;requestCode=1 与下方各 action 区分,避免 PendingIntent 互撞)。
        val openIntent = Intent(context, MainActivity::class.java)
            .setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val openPending = PendingIntent.getActivity(
            context, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // 策略切换按钮:循环切换 latency / failover / round_robin
        val cycleIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(ACTION_CYCLE_STRATEGY)
        val cyclePending = PendingIntent.getService(
            context, 2, cycleIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // 刷新测速按钮:重新并发探测节点延迟并选路
        val refreshIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(ACTION_REFRESH_NODES)
        val refreshPending = PendingIntent.getService(
            context, 3, refreshIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // 停止按钮:用户主动停止 → 服务静默停(§4.5 userInitiatedStop)。
        val stopIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            context, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // 解析 Go 引擎当前的选路与活跃节点状态
        val status = runCatching {
            JSONObject(smartproxy.mobile.Mobile.getActiveNodeStatus())
        }.getOrNull()

        val rawStrategy = status?.optString("strategy").orEmpty().ifBlank {
            ConfigProvider.upstreamStrategy(context)
        }
        val strategyDisplayName = getStrategyDisplayName(context, rawStrategy)
        val title = context.getString(R.string.notification_title_with_strategy, strategyDisplayName)

        val v4Node = status?.optString("v4_node").orEmpty()
        val v4Latency = status?.optLong("v4_latency_ms", 0L) ?: 0L
        val v6Node = status?.optString("v6_node").orEmpty()
        val v6Latency = status?.optLong("v6_latency_ms", 0L) ?: 0L
        val isDualStackNode = status?.optBoolean("dual_stack_node", false) ?: false

        val fmtLatencySuffix = { ms: Long -> if (ms > 0) " · ${ms}ms" else "" }
        val fmtLatencyParens = { ms: Long -> if (ms > 0) " (${ms}ms)" else "" }

        val hasConfiguredNodes = ConfigProvider.hasUpstreamProxy(context)
        val contentText: String
        val bigDetailLines = mutableListOf<String>()
        bigDetailLines.add(context.getString(R.string.notification_detail_strategy, strategyDisplayName))

        if (v4Node.isBlank() && v6Node.isBlank()) {
            contentText = if (!hasConfiguredNodes) {
                context.getString(R.string.notification_node_unconfigured)
            } else {
                context.getString(R.string.notification_node_none)
            }
            bigDetailLines.add(contentText)
        } else if (isDualStackNode && v4Node.isNotBlank()) {
            val latSuffix = fmtLatencySuffix(v4Latency)
            contentText = context.getString(R.string.notification_node_dual, v4Node, latSuffix)
            bigDetailLines.add(contentText)
        } else if (v4Node.isNotBlank() && v6Node.isNotBlank()) {
            val v4Suffix = fmtLatencyParens(v4Latency)
            val v6Suffix = fmtLatencyParens(v6Latency)
            contentText = context.getString(R.string.notification_node_separate, v4Node, v4Suffix, v6Node, v6Suffix)
            bigDetailLines.add("IPv4: $v4Node$v4Suffix")
            bigDetailLines.add("IPv6: $v6Node$v6Suffix")
        } else if (v4Node.isNotBlank()) {
            val v4Suffix = fmtLatencyParens(v4Latency)
            contentText = context.getString(R.string.notification_node_v4_only, v4Node, v4Suffix)
            bigDetailLines.add("IPv4: $v4Node$v4Suffix")
        } else {
            val v6Suffix = fmtLatencyParens(v6Latency)
            contentText = context.getString(R.string.notification_node_v6_only, v6Node, v6Suffix)
            bigDetailLines.add("IPv6: $v6Node$v6Suffix")
        }

        val content = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(title)
            .setContentText(contentText)
            .setStyle(Notification.BigTextStyle().bigText(bigDetailLines.joinToString("\n")))
            .setContentIntent(openPending)
            .setOngoing(true)
            .setShowWhen(false)

        // Action 1: 切换调度策略 [切换调度策略]
        content.addAction(
            Notification.Action.Builder(
                null,
                context.getString(R.string.notification_action_strategy),
                cyclePending
            ).build()
        )

        // Action 2: 重新测速与选路 [刷新]
        content.addAction(
            Notification.Action.Builder(
                null,
                context.getString(R.string.notification_action_refresh),
                refreshPending
            ).build()
        )

        // Action 3: 停止服务 [停止]
        content.addAction(
            Notification.Action.Builder(
                null,
                context.getString(R.string.notification_stop),
                stopPending
            ).build()
        )
        return content.build()
    }

    /** 原地更新前台保活通知(不重启服务)。 */
    fun refresh(context: Context) {
        ensureChannel(context)
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, build(context))
    }

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

    /** 启动前台并带 specialUse 类型。注意 `vpn` 不是合法的 manifest 属性 flag
     *  (AOSP foregroundServiceType 全版本都没有它,FOREGROUND_SERVICE_TYPE_VPN 只是
     *  运行期常量),v2rayNG 等 VPN 应用一律声明 specialUse + PROPERTY_SPECIAL_USE
     *  subtype;运行期类型必须与 manifest 声明一致,否则 Android 14+ 抛异常。 */
    fun startForeground(service: Service) {
        ensureChannel(service)
        ServiceCompat.startForeground(
            service,
            NOTIFICATION_ID,
            build(service),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        )
    }

    /**
     * 保活通知当前是否还在通知栏里。
     *
     * 用途:Android 14+ 允许用户划掉 specialUse 类型的前台服务通知。用户划掉后服务可能仍
     * 在跑(也可能已被系统收掉,但 VPN 引擎状态由 SmartProxyVpnService._isRunning 单独反映)。
     * MainActivity.onResume() 用它判断"隧道在跑但通知不在了",再补挂一次 startForeground
     * (方案 A:不立即重发,只在用户回到 App 时补,尊重用户当时划除意图)。
     *
     * 注意:activeNotifications 在 Android 13+ 需要 POST_NOTIFICATIONS 权限,未授权时返回
     * 空列表——此时通知本就被系统压住,补挂也无意义,由授权回调里的 refreshForeground 负责。
     */
    fun isForegroundNotificationVisible(context: Context): Boolean {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        return nm.activeNotifications?.any { it.id == NOTIFICATION_ID } == true
    }
}
