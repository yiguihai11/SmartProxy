package io.github.yiguihai11.smartproxy

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * VPN 入口服务(§4 / §4.5 / §4.6):
 *  - VPN 模式(默认):读 filesDir/config.json(§4.6 单一真源,Go 面板与首页开关共写)建
 *    VpnService.Builder → establish → fd → StartRouter
 *  - 仅代理模式(§8 服务模式):不建 VpnService,直接 StartRouter(fd=0, tunEnabled=false),
 *    只跑引擎 SOCKS5(:1080,全接口双栈)
 *  - 前台服务保活通知(§4.3)
 *  - onRevoke 断连检测:被其它 VPN 抢占 / 系统设置断开 → 停引擎、停服务、状态落 false;
 *    被动断开弹一次性通知(§4.5),用户主动停止则静默。
 *
 * 生命周期 = Go 引擎生命周期(§4.6 启停联动),无独立开关。
 */
class SmartProxyVpnService : VpnService() {

    companion object {
        private const val TAG = "SmartProxyVpn"

        /** 唯一真实状态源(§4.5):Compose 首页 collect 它。 */
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning

        /** DNS 硬编码默认(§6 用户要求应用内不提供 DNS UI):AppPrefs 自定义留空时回退。 */
        private const val DEFAULT_DNS_V4 = "223.5.5.5"
        private const val DEFAULT_DNS_V6 = "2400:3200::1"

        private const val ACTION_START = "io.github.yiguihai11.smartproxy.START_VPN"

        /** VpnControl 重启循环的内部 stop 标记:这类 stop 不算用户停止,不递增重启世代。 */
        const val EXTRA_INTERNAL_STOP = "io.github.yiguihai11.smartproxy.INTERNAL_STOP"

        /** 启动 VPN(外部调用,如 MainActivity 的启动按钮)。 */
        fun start(context: android.content.Context) {
            Log.i(TAG, "[Companion] start() requested by caller")
            context.startForegroundService(
                Intent(context, SmartProxyVpnService::class.java).setAction(ACTION_START)
            )
        }

        /** 用户主动停止(§4.5 userInitiatedStop:静默,不弹"已被断开")。 */
        fun stop(context: android.content.Context) {
            Log.i(TAG, "[Companion] stop() requested by caller (User initiate stop)")
            context.startService(
                Intent(context, SmartProxyVpnService::class.java)
                    .setAction(NotificationHelper.ACTION_STOP)
            )
        }

        /** 重启循环内部 stop(过渡性,随后立即 start):带 EXTRA_INTERNAL_STOP 标记,
         *  ACTION_STOP 处理时不算用户停止,不递增重启世代(否则会取消重启自己)。 */
        fun stopInternal(context: android.content.Context) {
            Log.i(TAG, "[Companion] stopInternal() requested by caller (Internal restart stop)")
            context.startService(
                Intent(context, SmartProxyVpnService::class.java)
                    .setAction(NotificationHelper.ACTION_STOP)
                    .putExtra(EXTRA_INTERNAL_STOP, true)
            )
        }
    }

    private var startedEngine = false

    /** §4.6 establish 保留的原始 PFD:shutdown 时显式 close() 通知系统拆 VPN(状态栏图标
     *  即刻消失)。传给 Go 的 fd 是它 dup + detachFd 出的独立拷贝(见 establishVpn),Go
     *  引擎独占那份;原始 PFD 从不过手,close 它就是系统拆 VPN 的唯一干净信号。不可
     *  detach 原始 PFD——fd 所有权转给 Go 后系统收不到关闭回调,实测图标赖到 onDestroy
     *  (~20s+)才清(系统不拆 VPN 就拖着服务不销毁)。 */
    private var tunPfd: ParcelFileDescriptor? = null

    /** §4.5 区分主动/被动停止:ACTION_STOP 置 true;正常启动置 false。主线程回调间切换。 */
    private var userInitiatedStop = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        val isInternalStop = intent?.getBooleanExtra(EXTRA_INTERNAL_STOP, false) == true
        Log.i(TAG, "[onStartCommand] Called. action=$action, isInternalStop=$isInternalStop, startId=$startId")

        if (action == NotificationHelper.ACTION_STOP) {
            // 圆球 / 通知停止 = 用户显式停止 → 递增 VpnControl 重启世代,使在途/挂起的
            // 重启在 delayed start 时取消(否则关掉后隧道又被拉起,状态栏图标不消失)。
            // VpnControl 重启循环的内部 stop 带 EXTRA_INTERNAL_STOP,不算用户停止。
            if (!isInternalStop) {
                Log.i(TAG, "[onStartCommand] ACTION_STOP is user stop. Calling VpnControl.noteUserStop().")
                VpnControl.noteUserStop()
            } else {
                Log.i(TAG, "[onStartCommand] ACTION_STOP is internal stop (restart flow).")
            }
            // 通知栏"停止"按钮 / 首页停止按钮:用户主动 → 静默停,后续 onRevoke 不误报被动。
            userInitiatedStop = true
            Log.i(TAG, "[onStartCommand] Step 1/2: Executing shutdown()...")
            shutdown()
            Log.i(TAG, "[onStartCommand] Step 2/2: Executing stopSelf()...")
            stopSelf()
            Log.i(TAG, "[onStartCommand] ACTION_STOP handling completed. Returning START_NOT_STICKY.")
            return START_NOT_STICKY
        }

        // 正常启动:之后的 onRevoke 一律视为被动断连(被抢占 / 系统设置断开)。
        Log.i(TAG, "[onStartCommand] Normal start path. Setting userInitiatedStop=false.")
        userInitiatedStop = false
        Log.i(TAG, "[onStartCommand] Calling NotificationHelper.startForeground()...")
        NotificationHelper.startForeground(this)
        // 服务模式(§8):仅代理(SOCKS5)不建 VpnService,直接起引擎 SOCKS5;VPN 模式走 establishVpn。
        val socksOnly = AppPrefs.serviceMode(this) == AppPrefs.MODE_SOCKS5
        Log.i(TAG, "[onStartCommand] serviceMode=${AppPrefs.serviceMode(this)}, socksOnly=$socksOnly. Calling ${if (socksOnly) "startSocksOnly()" else "establishVpn()"}...")
        val started = if (socksOnly) startSocksOnly() else establishVpn()
        if (started) {
            startedEngine = true
            _isRunning.value = true
            Log.i(TAG, "[onStartCommand] Start SUCCESS (socks=$socksOnly)! startedEngine=true, _isRunning=true. Returning START_STICKY.")
            return START_STICKY
        }
        // start 失败:前台服务已起,立即收掉避免空转。
        Log.e(TAG, "[onStartCommand] Start FAILED (socks=$socksOnly)! Stopping foreground notification and service.")
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
        return START_NOT_STICKY
    }

    /** 按 §4.6 用同一份 filesDir/config.json 建 Builder → establish → StartRouter(单一真源)。 */
    private fun establishVpn(): Boolean {
        return try {
            Log.i(TAG, "[establishVpn] Step 1: Ensuring config files & reading config...")
            ConfigProvider.ensureRuntimeFiles(this)
            ConfigProvider.ensureConfig(this)
            // config.json 是唯一真源(Go 面板经 /config 写它、首页开关写它、引擎 watcher
            // 监控它):不再由 AppPrefs 重新合成。Builder 与 StartRouter 读同一份。
            val configJson = ConfigProvider.readConfig(this)
            val configPath = ConfigProvider.configPath(this)
            val tun = TunConfig.parse(configJson)
            Log.i(TAG, "[establishVpn] Parsed TUN config: mtu=${tun.mtu}, inet4=${tun.inet4}, inet6=${tun.inet6}")

            // VpnService.Builder 是 VpnService 的内部类,不能写成 VpnService.Builder():
            // 本类继承 VpnService,裸 Builder() 会用 this 当外部接收者。
            val builder = Builder().setMtu(tun.mtu)

            // IPv4/IPv6 拦截 = tun.inet4/6_address 存在(首页开关读写同一字段);
            // DNS 只走 AppPrefs(§6 应用内设置):tun.dns_servers 引擎不消费、config.json
            // 无此字段,缺省回退硬编码默认。
            val inet4 = tun.inet4
            val customDnsV4 = AppPrefs.dnsV4(this)
            val effectiveDnsV4 = if (customDnsV4.isNotBlank()) customDnsV4 else DEFAULT_DNS_V4
            if (inet4 != null) {
                builder.addAddress(inet4.ip, inet4.prefix)   // "172.19.0.1/30" → addAddress(172.19.0.1, 30)
                    .addRoute("0.0.0.0", 0)                  // §4.1:族开才加该族默认路由
                    .addDnsServer(effectiveDnsV4)
                Log.i(TAG, "[establishVpn] IPv4 address=${inet4.ip}/${inet4.prefix}, route=0.0.0.0/0, DNS=$effectiveDnsV4")
            }
            val inet6 = tun.inet6
            val customDnsV6 = AppPrefs.dnsV6(this)
            val effectiveDnsV6 = if (customDnsV6.isNotBlank()) customDnsV6 else DEFAULT_DNS_V6
            if (inet6 != null) {
                builder.addAddress(inet6.ip, inet6.prefix)
                    .addRoute("::", 0)
                    .addDnsServer(effectiveDnsV6)
                Log.i(TAG, "[establishVpn] IPv6 address=${inet6.ip}/${inet6.prefix}, route=::/0, DNS=$effectiveDnsV6")
            }

            // 排除路由 (excludeRoute, 仅限 Android 13+ / API 33+ 特性)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val excluded = AppPrefs.excludedRoutes(this)
                if (excluded.isNotEmpty()) {
                    Log.i(TAG, "[establishVpn] Applying ${excluded.size} excludeRoute rules (API 33+)...")
                    excluded.forEach { cidrStr ->
                        if (cidrStr.isNotBlank()) {
                            try {
                                val cidr = TunConfig.parseCidr(cidrStr.trim())
                                val inetAddr = java.net.InetAddress.getByName(cidr.ip)
                                builder.excludeRoute(android.net.IpPrefix(inetAddr, cidr.prefix))
                                Log.i(TAG, "[establishVpn] Excluded route: ${cidr.ip}/${cidr.prefix}")
                            } catch (e: Exception) {
                                Log.w(TAG, "[establishVpn] Failed to parse excludeRoute '$cidrStr': ${e.message}")
                            }
                        }
                    }
                }
            } else {
                Log.i(TAG, "[establishVpn] Current SDK ${Build.VERSION.SDK_INT} < 33, excludeRoute skipped.")
            }

            // 流量模式(§4):M1 默认"仅绕过(global)",M2/M5 从 AppPrefs 喂选中列表。
            if (AppPrefs.globalMode(this)) {
                Log.i(TAG, "[establishVpn] Mode: Global (Bypass selected apps + self)")
                // 仅绕过(黑名单):全接管,唯独放行选中 + 自身。
                AppPrefs.selectedApps(this).forEach { builder.addDisallowedApplication(it) }
                // 自身 uid 无条件排除,防回环:引擎的出站直连/上游连接出自本进程 uid,
                // 不排除就会灌回 TUN → gvisor 处理自己的出站包 → 死循环。
                builder.addDisallowedApplication(packageName)
            } else {
                Log.i(TAG, "[establishVpn] Mode: Bypass (Proxy selected apps only)")
                // 仅代理(白名单):只放行选中。自身 uid 天然不在白名单里(面板枚举已滤掉
                // 自己),且 Android 不允许白名单/黑名单混用(混加抛 UnsupportedOperationException),
                // 所以这里既不能也不需加 addDisallowedApplication(self)。防御性滤掉自身,
                // 防陈旧偏好里残留本包名导致回环。
                AppPrefs.selectedApps(this)
                    .filter { it != packageName }
                    .forEach { builder.addAllowedApplication(it) }
            }

            Log.i(TAG, "[establishVpn] Step 2: Executing Builder.establish()...")
            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "[establishVpn] Builder.establish() returned NULL! (VPN permission revoked or system rejected)")
                return false
            }
            Log.i(TAG, "[establishVpn] Builder.establish() SUCCESS. PFD fd=${pfd.fd}")

            try {
                Log.i(TAG, "[establishVpn] Step 3: Calling Go Mobile.startRouter(configPath, fd=${pfd.fd}, tunEnabled=true)...")
                val t0 = System.currentTimeMillis()
                // Go 侧 sing-tun 用 os.NewFile(uintptr(fd)) 直接包传入的 fd 号(不 dup)。
                // 直接把 PFD 的 fd 号交给 Go,两边就共享同一 fd:shutdown 时 pfd.close() 的
                // 系统拆 VPN 信号会被这份共享所有权搅浑(实测停止后状态栏图标赖 42s+ 才清,
                // stopSelf→onDestroy 间隔 42s)。改为 dup → detachFd 把独立 fd 交给 Go 独占;
                // 原始 PFD 留在 Kotlin(系统关闭回调挂在它身上),shutdown 对它的 close 就是
                // 拆 VPN 的唯一干净信号,图标即刻消失。
                val dupPfd = pfd.dup()
                val goFd = dupPfd.detachFd()
                smartproxy.mobile.Mobile.startRouter(configPath, goFd.toLong(), true)
                Log.i(TAG, "[establishVpn] Mobile.startRouter() returned successfully in ${System.currentTimeMillis() - t0} ms. (goFd=$goFd, kotlinPfd=${pfd.fd})")
                tunPfd = pfd
                Log.i(TAG, "[establishVpn] Step 4: VPN established. tunPfd retained for shutdown close.")
            } catch (e: Exception) {
                Log.e(TAG, "[establishVpn] Mobile.startRouter threw exception! Closing PFD...", e)
                pfd.close()
                tunPfd = null
                // goFd 所有权已交 Go:若其已 os.NewFile 包装,Go 的失败清理会关它;此处不关,
                // 避免与 Go 清理路径 double-close(EBADF 或 fd 号被复用后误关)。
                throw e
            }
            true
        } catch (e: Exception) {
            // config 解析 / Builder 参数 / establish / StartRouter 任一失败都走这。
            Log.e(TAG, "[establishVpn] establishVpn failed with exception: ${e.message}", e)
            false
        }
    }

    /** 仅代理(SOCKS5)模式(§8 服务模式):不建 VpnService / 不 establish,直接 StartRouter
     *  (fd=0, tunEnabled=false)。bridge 侧补缺省端口 1080、host 沿用 config(默认 :: 全接口)。
     *  startedEngine 语义不变:shutdown 里 stopRouter 统一收尾。 */
    private fun startSocksOnly(): Boolean {
        return try {
            Log.i(TAG, "[startSocksOnly] Step 1: Ensuring config files...")
            ConfigProvider.ensureRuntimeFiles(this)
            ConfigProvider.ensureConfig(this)
            val configPath = ConfigProvider.configPath(this)
            Log.i(TAG, "[startSocksOnly] Step 2: Calling Go Mobile.startRouter(configPath, fd=0, tunEnabled=false)...")
            val t0 = System.currentTimeMillis()
            smartproxy.mobile.Mobile.startRouter(configPath, 0L, false)
            Log.i(TAG, "[startSocksOnly] Mobile.startRouter() returned successfully in ${System.currentTimeMillis() - t0} ms.")
            true
        } catch (e: Exception) {
            Log.e(TAG, "[startSocksOnly] Mobile.startRouter() threw exception", e)
            false
        }
    }

    /** 停引擎 + 收前台服务 + 状态落 false(§4.5)。
     *  先关 tunPfd:close() 通知系统拆 VPN → 状态栏图标即刻消失。Go 引擎持有的是
     *  establishVpn 里 dup + detach 出的独立 fd,不受此 close 影响,由随后的
     *  stopRouter 收尾。shutdown 幂等(重复进入 tunPfd 已置 null)。 */
    private fun shutdown() {
        Log.i(TAG, "[shutdown] Step 0: Enter shutdown(). startedEngine=$startedEngine, _isRunning=${_isRunning.value}")
        tunPfd?.let { pfd ->
            try {
                Log.i(TAG, "[shutdown] Step 1/4: Closing tun PFD (tear down VPN)...")
                pfd.close()
                Log.i(TAG, "[shutdown] Step 1/4: tun PFD closed.")
            } catch (e: Exception) {
                Log.e(TAG, "[shutdown] Step 1/4: tun PFD close failed", e)
            }
            tunPfd = null
        }
        if (startedEngine) {
            try {
                Log.i(TAG, "[shutdown] Step 2/4: Invoking Go Mobile.stopRouter()...")
                val t0 = System.currentTimeMillis()
                smartproxy.mobile.Mobile.stopRouter()
                val duration = System.currentTimeMillis() - t0
                Log.i(TAG, "[shutdown] Step 2/4: Mobile.stopRouter() completed in ${duration} ms.")
            } catch (e: Exception) {
                Log.e(TAG, "[shutdown] Step 2/4: Mobile.stopRouter() threw exception", e)
            }
            startedEngine = false
        } else {
            Log.i(TAG, "[shutdown] Step 2/4: startedEngine is false, skipping Mobile.stopRouter().")
        }

        Log.i(TAG, "[shutdown] Step 3/4: Calling ServiceCompat.stopForeground(STOP_FOREGROUND_REMOVE)...")
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "[shutdown] Step 3/4: stopForeground completed.")

        Log.i(TAG, "[shutdown] Step 4/4: Updating state _isRunning.value = false...")
        _isRunning.value = false
        Log.i(TAG, "[shutdown] Step 5/4: shutdown() completed. _isRunning is now false.")
    }

    /** 被其它 VPN 抢占 / 系统设置断开:系统调此,隧道即刻失效(§4.5 主信号)。 */
    override fun onRevoke() {
        super.onRevoke()
        val passive = !userInitiatedStop
        Log.w(TAG, "[onRevoke] Triggered by system! userInitiatedStop=$userInitiatedStop, passive=$passive")
        Log.i(TAG, "[onRevoke] Executing shutdown()...")
        shutdown()
        Log.i(TAG, "[onRevoke] Executing stopSelf()...")
        stopSelf()
        // §4.5:被动断开弹一次性通知(仅提示,不违背保活通知极简原则);主动停止则静默。
        if (passive) {
            Log.i(TAG, "[onRevoke] Passive disconnect. Displaying notification...")
            NotificationHelper.notifyDisconnected(this)
        }
        Log.i(TAG, "[onRevoke] Completed.")
    }

    override fun onDestroy() {
        Log.i(TAG, "[onDestroy] Service onDestroy() entered.")
        shutdown()
        super.onDestroy()
        Log.i(TAG, "[onDestroy] Service onDestroy() completed.")
    }
}

