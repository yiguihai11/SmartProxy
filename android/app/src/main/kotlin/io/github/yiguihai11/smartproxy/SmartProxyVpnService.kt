package io.github.yiguihai11.smartproxy

import android.content.Intent
import android.net.VpnService
import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * VPN 入口服务(§4 / §4.5 / §4.6):
 *  - 读 config.json 的 tun 段(§4.6)建 VpnService.Builder → establish → fd → StartRouter
 *  - 前台服务保活通知(§4.3)
 *  - onRevoke 断连检测:被其它 VPN 抢占 / 系统设置断开 → 停引擎、停服务、状态落 false
 *
 * 生命周期 = Go 引擎生命周期(§4.6 启停联动),无独立开关。
 */
class SmartProxyVpnService : VpnService() {

    companion object {
        /** 唯一真实状态源(§4.5):Compose 首页 collect 它。 */
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning

        private const val ACTION_START = "io.github.yiguihai11.smartproxy.START_VPN"

        /** 启动 VPN(外部调用,如 MainActivity 的启动按钮)。 */
        fun start(context: android.content.Context) {
            context.startForegroundService(
                Intent(context, SmartProxyVpnService::class.java).setAction(ACTION_START)
            )
        }

        /** 用户主动停止(§4.5 userInitiatedStop 语义:M1 直接停,后续区分通知提示)。 */
        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, SmartProxyVpnService::class.java)
                    .setAction(NotificationHelper.ACTION_STOP)
            )
        }
    }

    private var startedEngine = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == NotificationHelper.ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }

        // 启动流程:M1 家族开关默认全开;M2 从 AppPrefs 读取。
        NotificationHelper.startForeground(this)
        if (establishVpn()) {
            startedEngine = true
            _isRunning.value = true
            return START_STICKY
        }
        // establish/StartRouter 失败:前台服务已起,立即收掉避免空转。
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        return START_NOT_STICKY
    }

    /** 按 §4.6 从 config.json tun 段建 Builder → establish → StartRouter。 */
    private fun establishVpn(): Boolean {
        return try {
            ConfigProvider.ensureRuntimeFiles(this)
            val configJson = ConfigProvider.loadConfig(this)
            val tun = TunConfig.parse(org.json.JSONObject(configJson))

            val builder = VpnService.Builder().setMtu(tun.mtu)

            val ipv4 = AppPrefs.ipv4(this)   // M1 默认 true,M2 接首页开关
            val ipv6 = AppPrefs.ipv6(this)

            if (ipv4 && tun.inet4 != null) {
                builder.addAddress(tun.inet4.ip, tun.inet4.prefix)   // "172.19.0.1/30" → addAddress(172.19.0.1, 30)
                    .addRoute("0.0.0.0", 0)                          // §4.1:族开才加该族默认路由
                    .addDnsServer(tun.dnsV4)                         // 默认 223.5.5.5
            }
            if (ipv6 && tun.inet6 != null) {
                builder.addAddress(tun.inet6.ip, tun.inet6.prefix)
                    .addRoute("::", 0)
                    .addDnsServer(tun.dnsV6)                         // 默认 2400:3200::1
            }

            // 流量模式(§4):M1 默认"仅绕过(global)",M2/M5 从 AppPrefs 喂选中列表。
            if (AppPrefs.globalMode(this)) {
                AppPrefs.selectedApps(this).forEach { builder.addDisallowedApplication(it) }
            } else {
                AppPrefs.selectedApps(this).forEach { builder.addAllowedApplication(it) }
            }
            // 放行自身:无条件强制,防回环(§4)。
            builder.addDisallowedApplication(packageName)

            val fd = builder.establish()?.fd ?: return false
            // Go engine AAR:gomobile bind(mobile 包)→ smartproxy.mobile.Mobile。
            // 注意 gomobile 导出方法首字母小写(lowerFirst),StartRouter → startRouter。
            smartproxy.mobile.Mobile.startRouter(configJson, fd)
            true
        } catch (e: Exception) {
            // config 解析 / Builder 参数 / establish / StartRouter 任一失败都走这。
            android.util.Log.e("SmartProxyVpn", "establishVpn failed", e)
            false
        }
    }

    /** 停引擎 + 收前台服务 + 状态落 false(§4.5)。 */
    private fun shutdown() {
        if (startedEngine) {
            try {
                smartproxy.mobile.Mobile.stopRouter()
            } catch (e: Exception) {
                android.util.Log.e("SmartProxyVpn", "stopRouter failed", e)
            }
            startedEngine = false
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        _isRunning.value = false
    }

    /** 被其它 VPN 抢占 / 系统设置断开:系统调此,隧道即刻失效(§4.5 主信号)。 */
    override fun onRevoke() {
        super.onRevoke()
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
