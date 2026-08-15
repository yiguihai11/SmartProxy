package io.github.yiguihai11.smartproxy

import android.content.Intent
import android.net.VpnService
import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * VPN 入口服务(§4 / §4.5 / §4.6):
 *  - ConfigGenerator 产出 config.json(§4.6 单一真源),其 tun 段建 VpnService.Builder
 *    → establish → fd → StartRouter
 *  - 前台服务保活通知(§4.3)
 *  - onRevoke 断连检测:被其它 VPN 抢占 / 系统设置断开 → 停引擎、停服务、状态落 false;
 *    被动断开弹一次性通知(§4.5),用户主动停止则静默。
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

        /** 用户主动停止(§4.5 userInitiatedStop:静默,不弹"已被断开")。 */
        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, SmartProxyVpnService::class.java)
                    .setAction(NotificationHelper.ACTION_STOP)
            )
        }
    }

    private var startedEngine = false

    /** §4.5 区分主动/被动停止:ACTION_STOP 置 true;正常启动置 false。主线程回调间切换。 */
    private var userInitiatedStop = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == NotificationHelper.ACTION_STOP) {
            // 通知栏"停止"按钮 / 首页停止按钮:用户主动 → 静默停,后续 onRevoke 不误报被动。
            userInitiatedStop = true
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }

        // 正常启动:之后的 onRevoke 一律视为被动断连(被抢占 / 系统设置断开)。
        userInitiatedStop = false
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

    /** 按 §4.6 用同一份 config.json 建 Builder → establish → StartRouter(单一真源)。 */
    private fun establishVpn(): Boolean {
        return try {
            ConfigProvider.ensureRuntimeFiles(this)
            val configJson = ConfigGenerator.build(this)
            val tun = TunConfig.parse(org.json.JSONObject(configJson))

            // VpnService.Builder 是 VpnService 的内部类,不能写成 VpnService.Builder():
            // 本类继承 VpnService,裸 Builder() 会用 this 当外部接收者。
            val builder = Builder().setMtu(tun.mtu)

            val ipv4 = AppPrefs.ipv4(this)   // M1 默认 true,M2 接首页开关
            val ipv6 = AppPrefs.ipv6(this)

            if (ipv4 && tun.inet4 != null) {
                builder.addAddress(tun.inet4.ip, tun.inet4.prefix)   // "172.19.0.1/30" → addAddress(172.19.0.1, 30)
                    .addRoute("0.0.0.0", 0)                          // §4.1:族开才加该族默认路由
                    .addDnsServer(AppPrefs.dnsV4(this))              // §4.2 默认 223.5.5.5
            }
            if (ipv6 && tun.inet6 != null) {
                builder.addAddress(tun.inet6.ip, tun.inet6.prefix)
                    .addRoute("::", 0)
                    .addDnsServer(AppPrefs.dnsV6(this))              // §4.2 默认 2400:3200::1
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
            // 注意 gomobile 导出方法首字母小写(lowerFirst),StartRouter → startRouter;
            // Go 的 int 参数在 Java 侧是 long,fd(Int)要转 Long。
            smartproxy.mobile.Mobile.startRouter(configJson, fd.toLong())
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
        val passive = !userInitiatedStop   // 用户主动停止流程不会触发 onRevoke,此处必为被动
        shutdown()
        stopSelf()
        // §4.5:被动断开弹一次性通知(仅提示,不违背保活通知极简原则);主动停止则静默。
        if (passive) NotificationHelper.notifyDisconnected(this)
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }
}
