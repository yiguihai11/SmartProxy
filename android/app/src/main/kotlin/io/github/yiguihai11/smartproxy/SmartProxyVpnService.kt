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
            // config 落 filesDir 持久文件,引擎按路径加载(StartRouter(configPath, fd),
            // 与桌面 config.Load 同路);configJson 仍喂 Builder 保证两侧同源。
            val configPath = ConfigProvider.persistConfig(this, configJson)
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
                // 仅绕过(黑名单):全接管,唯独放行选中 + 自身。
                AppPrefs.selectedApps(this).forEach { builder.addDisallowedApplication(it) }
                // 自身 uid 无条件排除,防回环:引擎的出站直连/上游连接出自本进程 uid,
                // 不排除就会灌回 TUN → gvisor 处理自己的出站包 → 死循环。
                builder.addDisallowedApplication(packageName)
            } else {
                // 仅代理(白名单):只放行选中。自身 uid 天然不在白名单里(面板枚举已滤掉
                // 自己),且 Android 不允许白名单/黑名单混用(混加抛 UnsupportedOperationException),
                // 所以这里既不能也不需加 addDisallowedApplication(self)。防御性滤掉自身,
                // 防陈旧偏好里残留本包名导致回环。
                AppPrefs.selectedApps(this)
                    .filter { it != packageName }
                    .forEach { builder.addAllowedApplication(it) }
            }

            // fd 所有权契约(单所有者,杜绝泄漏/误关):
            //  - establish() 返回的 PFD 是隧道 fd 的 Java 侧唯一所有者。
            //  - startRouter 成功 = Go 引擎已 os.NewFile 接管 → detachFd() 交出 Java
            //    所有权,防 GC 回收 PFD 时把 fd 一起关掉(隧道中途 EBADF 死亡)。
            //  - startRouter 抛错 = 引擎没接管(错误在 NewTUN 之前,如 netlink monitor
            //    失败)→ PFD 仍持所有权,close() 归还。若不关,OS 以为隧道还活着 →
            //    状态栏 VPN 图标常驻(真机实测 ErrNetlinkBanned 后图标仍在),且无人
            //    读包,成僵尸隧道。注:NewTUN 之后失败(如 gvisor 栈)Go 会自己 t.Close(),
            //    PFD.close 对其幂等,异常同步回抛的窗口内无并发 fd 复用,安全。
            val pfd = builder.establish() ?: return false
            try {
                // Go 的 int 参数在 Java 侧是 long,getFd()(Int)要转 Long。
                smartproxy.mobile.Mobile.startRouter(configPath, pfd.getFd().toLong())
                pfd.detachFd()
            } catch (e: Exception) {
                pfd.close()
                throw e
            }
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
