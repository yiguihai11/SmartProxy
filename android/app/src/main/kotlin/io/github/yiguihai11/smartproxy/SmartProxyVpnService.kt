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

        /** 本次连接会话的启动时刻(ms),首页圆环连接时长数据源;0 = 未连接。
         *  启动成功(含 sticky 重启)时赋值,完整拆机(fullTeardown)时清零;
         *  重建(fullTeardown=false)不重置,时长连续不计入重启间隙。 */
        @Volatile
        var startedAt: Long = 0L

        /** DNS 缺省值(§6 抽屉 DNS 设置存 AppPrefs,自定义留空时回退这里)。 */
        private const val DEFAULT_DNS_V4 = "223.5.5.5"
        private const val DEFAULT_DNS_V6 = "2400:3200::1"

        /** 停止时 stopSelf() 之后、关 tun fd 之前的留白(ms),等系统异步拆 VPN 网络
         *  (注销 NetworkAgent / 移除路由 → 应用活跃连接的 dst 引用释放)。对齐 v2rayNG
         *  stopAllService 的 Thread.sleep(100),防止"先关 fd 网络还挂着 → 图标赖着不掉"。
         *  留白太小或 vivo 拆网更慢时调大。 */
        private const val TEARDOWN_SETTLE_MS = 100L

        private const val ACTION_START = "io.github.yiguihai11.smartproxy.START_VPN"

        /** 设置变更重建(§6 应用层设置 / 首页 IPv4 / IPv6 开关):停旧会话 → 立即按新配置
         *  重建 VpnService。onStartCommand 主线程单一回调内原子执行,只由 App 侧显式
         *  调用——不会再像旧的 VpnControl 异步重启循环那样,在用户停止后被 delayed start
         *  把隧道重新拉起(状态栏图标赖着不掉,2026-08 已删除该机制)。 */
        const val ACTION_RESTART = "io.github.yiguihai11.smartproxy.RESTART_VPN"

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

        /** 设置变更重建入口:仅 VPN 在跑时才有意义(未在跑只落盘,下次启动自然生效)。
         *  重启是主线程原子的 stop→build,不异步、无竞态窗口。 */
        fun restart(context: android.content.Context) {
            if (!isRunning.value) {
                Log.i(TAG, "[Companion] restart() requested but VPN not running, skipping.")
                return
            }
            Log.i(TAG, "[Companion] restart() requested by caller (settings change)")
            context.startService(
                Intent(context, SmartProxyVpnService::class.java).setAction(ACTION_RESTART)
            )
        }

        /** 通知授权补发(§4.3):仅重刷前台通知,不碰引擎。首次安装时 POST_NOTIFICATIONS
         *  授权可能晚于 startForeground,系统压住通知;授权落定后由 MainActivity 调本方法。 */
        fun refreshForeground(context: android.content.Context) {
            Log.i(TAG, "[Companion] refreshForeground() requested (notification permission granted late)")
            context.startService(
                Intent(context, SmartProxyVpnService::class.java)
                    .setAction(NotificationHelper.ACTION_REFRESH_FOREGROUND)
            )
        }

        private var appContextRef: java.lang.ref.WeakReference<android.content.Context>? = null
        fun getAppContext(): android.content.Context? = appContextRef?.get()
    }

    private var startedEngine = false

    /** P1#6 守卫:完整拆机(fullTeardown=true)只执行一次。ACTION_STOP 的 shutdown 之后
     *  onDestroy 会再调一次 shutdown,没有这个守卫就会再 sleep 100ms + 再 stopForeground;
     *  onRevoke 与 onDestroy 并发/先后到达同理。startInternal 成功建隧道时复位。 */
    private var tornDown = false

    /** §4.6 establish 保留的原始 PFD:shutdown 时显式 close() 通知系统拆 VPN(状态栏图标
     *  即刻消失)。传给 Go 的 fd 是 dup + detachFd 出的独立拷贝(见 establishVpn),Go 引擎
     *  独占那份;原始 PFD 从不过手,close 它就是系统拆 VPN 的唯一干净信号。不可 detach 原始
     *  PFD——fd 所有权转给 Go 后系统收不到关闭回调,实测图标赖到 onDestroy(~20s+)才清
     *  (系统不拆 VPN 就拖着服务不销毁)。 */
    private var tunPfd: ParcelFileDescriptor? = null

    /** §4.5 区分主动/被动停止:ACTION_STOP 置 true;正常启动置 false。主线程回调间切换。 */
    private var userInitiatedStop = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        Log.i(TAG, "[onStartCommand] Called. action=$action, startId=$startId")

        if (action == NotificationHelper.ACTION_STOP) {
            // 圆球 / 通知停止 = 用户显式停止:静默停,后续 onRevoke 不误报被动。
            // stopSelf() 在 shutdown(fullTeardown=true) 内部先于关 fd 调用(v2rayNG 顺序)。
            userInitiatedStop = true
            Log.i(TAG, "[onStartCommand] ACTION_STOP is user stop. shutdown() will call stopSelf() BEFORE closing tun fd...")
            shutdown()
            Log.i(TAG, "[onStartCommand] ACTION_STOP handling completed. Returning START_NOT_STICKY.")
            return START_NOT_STICKY
        }

        // 设置变更重建(§6 / 首页 IPv4 / IPv6 开关):停旧会话 → 立即按新配置重建。
        // shutdown + startInternal 在同一主线程回调内顺序执行,原子完成——不会再像旧的
        // 异步重启循环那样,在用户停止后靠 delayed start 把隧道重新拉起。
        if (action == ACTION_RESTART) {
            // 重建(§6 设置变更 / 首页 IPv4 / IPv6 开关):服务需存活,不能 stopSelf。
            // fullTeardown=false → 跳过"stopSelf + 留白",停引擎 + 关 fd 后立即重建。
            Log.i(TAG, "[onStartCommand] ACTION_RESTART: shutting down (fullTeardown=false, keep service alive) then rebuilding VPN...")
            shutdown(fullTeardown = false)
            Log.i(TAG, "[onStartCommand] ACTION_RESTART: re-establishing with new settings...")
            return startInternal()
        }

        // 通知授权补发:只重刷前台通知,不动引擎。已在跑保持,没在跑不拉起。
        if (action == NotificationHelper.ACTION_REFRESH_FOREGROUND) {
            Log.i(TAG, "[onStartCommand] REFRESH_FOREGROUND: re-calling startForeground() (engine running=$startedEngine)")
            if (startedEngine) {
                NotificationHelper.startForeground(this)
                return START_STICKY
            }
            return START_NOT_STICKY
        }

        // 正常启动:之后的 onRevoke 一律视为被动断连(被抢占 / 系统设置断开)。
        Log.i(TAG, "[onStartCommand] Normal start path. Setting userInitiatedStop=false.")
        userInitiatedStop = false
        return startInternal()
    }

    /** 建前台通知并按服务模式启动引擎 / 隧道(§8):START 与 RESTART 分支共用。
     *  成功返回 START_STICKY;失败立即收掉前台服务避免空转,返回 START_NOT_STICKY。 */
    private fun startInternal(): Int {
        // P0#6 守卫:重复/重投的 START intent 在引擎已跑时直接忽略。没有这个守卫,
        // 已运行状态下再走 establishVpn → StartRouter 报 "router is already running"
        // → establishVpn 返回 false → 走到下方失败分支把正在跑的 VPN 拆掉。
        if (startedEngine) {
            Log.i(TAG, "[startInternal] Engine already running; ignoring duplicate start (P0#6).")
            return START_STICKY
        }
        // 新的隧道会话开始:tornDown 复位,允许下次完整拆机再走一遍停服流程。
        tornDown = false
        Log.i(TAG, "[startInternal] Calling NotificationHelper.startForeground()...")
        NotificationHelper.startForeground(this)
        // 服务模式(§8):仅代理(SOCKS5)不建 VpnService,直接起引擎 SOCKS5;VPN 模式走 establishVpn。
        val socksOnly = AppPrefs.serviceMode(this) == AppPrefs.MODE_SOCKS5
        Log.i(TAG, "[startInternal] serviceMode=${AppPrefs.serviceMode(this)}, socksOnly=$socksOnly. Calling ${if (socksOnly) "startSocksOnly()" else "establishVpn()"}...")
        appContextRef = java.lang.ref.WeakReference(applicationContext)
        val started = if (socksOnly) startSocksOnly() else establishVpn()
        if (started) {
            startedEngine = true
            _isRunning.value = true
            startedAt = System.currentTimeMillis()
            io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync.onStarted(this, ConfigProvider.readConfig(this).toString())
            Log.i(TAG, "[startInternal] Start SUCCESS (socks=$socksOnly)! startedEngine=true, _isRunning=true. Returning START_STICKY.")
            return START_STICKY
        }
        // start 失败:前台服务已起,立即收掉避免空转。状态落 false——正常启动路径本就
        // 是 false;重建(ACTION_RESTART)路径 shutdown(fullTeardown=false)为无感保留了
        // isRunning=true,重建失败必须落 false,否则首页圆球卡在"已连接"但隧道已没了。
        Log.e(TAG, "[startInternal] Start FAILED (socks=$socksOnly)! Stopping foreground notification and service.")
        io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync.onStartFailed(this, "Start failed")
        _isRunning.value = false
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

            // 兜底:至少一个 IP 族启用。VpnService.Builder 没调过 addAddress 就 establish()
            // 会抛 IllegalArgumentException;首页开关层已阻止双关,但 Go 面板或直接编辑
            // config.json 仍可能把 inet4/6_address 都写成空,这里明确判失败而非让异常冒泡。
            if (tun.inet4 == null && tun.inet6 == null) {
                Log.e(TAG, "[establishVpn] Neither IPv4 nor IPv6 enabled in config (tun.inet4/6_address both empty); cannot establish VPN.")
                return false
            }

            // VpnService.Builder 是 VpnService 的内部类,不能写成 VpnService.Builder():
            // 本类继承 VpnService,裸 Builder() 会用 this 当外部接收者。
            val builder = Builder().setMtu(tun.mtu)

            // IPv4/IPv6 拦截 = tun.inet4/6_address 存在(首页开关读写同一字段);
            // DNS 只走 AppPrefs(§6 应用内设置):config.json 已无 tun.dns_servers
            // (2026-08 删死配置),缺省回退硬编码默认。
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
            //
            // 逐项包名必须独立兜底 NameNotFoundException:addDisallowed/AllowedApplication
            // 对已卸载/多用户下不可见的包会抛此异常,若用一个 forEach 不兜,外层 try/catch
            // 会让整个 establishVpn 返回 false → 前台服务被收掉、VPN 静默起不来(只在 logcat
            // 留异常)。陈旧偏好里残留已卸载包是常态(用户卸 app 不会同步改我们的选择),
            // 所以这里跳过并告警,绝不因一个包名拖垮整次启动。
            val selected = AppPrefs.selectedApps(this)
            if (AppPrefs.globalMode(this)) {
                Log.i(TAG, "[establishVpn] Mode: Global (Bypass selected apps + self)")
                // 仅绕过(黑名单):全接管,唯独放行选中 + 自身。selected 里滤掉本包名,
                // 自身只由下面显式加一次(避免重复 addDisallowed)。
                selected.filter { it != packageName }
                    .forEach { pkg -> applyDisallowedApp(builder, pkg, isSelf = false) }
                // 自身 uid 无条件排除,防回环:引擎的出站直连/上游连接出自本进程 uid,
                // 不排除就会灌回 TUN → gvisor 处理自己的出站包 → 死循环。
                applyDisallowedApp(builder, packageName, isSelf = true)
            } else {
                Log.i(TAG, "[establishVpn] Mode: Bypass (Proxy selected apps only)")
                // 仅代理(白名单):只放行选中。自身 uid 天然不在白名单里(面板枚举已滤掉
                // 自己),且 Android 不允许白名单/黑名单混用(混加抛 UnsupportedOperationException),
                // 所以这里既不能也不需加 addDisallowedApplication(self)。防御性滤掉自身,
                // 防陈旧偏好里残留本包名导致回环。
                var allowedCount = 0
                selected.filter { it != packageName }.forEach { pkg ->
                    if (applyAllowedApp(builder, pkg)) allowedCount++
                }
                // 白名单一个有效包都没有(全卸载 / 空选 / 全不可见)时,Builder 没调过任何
                // addAllowed/DisallowedApplication → Android 默认接管全部流量,含本引擎
                // 自身出站 → TUN 回环死循环。直接判失败,不 establish。
                if (allowedCount == 0) {
                    Log.e(TAG, "[establishVpn] Whitelist mode but 0 valid apps to proxy (all uninstalled?); aborting to avoid TUN loopback.")
                    return false
                }
                Log.i(TAG, "[establishVpn] Whitelist: $allowedCount app(s) will be proxied.")
            }

            // 「禁止联网」(per-app block,§5 第一期仅在仅绕过/黑名单模式提供):被拦应用
            // 不进 addDisallowed(仍进 TUN),由 Go 侧按连接反查 UID 丢弃;UID 集合写
            // config.json tun.blocked_uids(引擎 StartRouter 读同一份)。白名单模式不启用
            // (UI 已禁用拦截),显式清空避免陈旧偏好残留拦截规则。
            val blockedPkgs = AppPrefs.blockedApps(this)
            if (AppPrefs.globalMode(this)) {
                val blockedUids = resolveBlockedUids(blockedPkgs)
                ConfigProvider.setBlockedUids(this, blockedUids)
                Log.i(TAG, "[establishVpn] Blocked apps written to tun.blocked_uids: ${blockedUids.size} uid(s) $blockedUids")
            } else {
                ConfigProvider.setBlockedUids(this, emptyList())
                if (blockedPkgs.isNotEmpty()) {
                    Log.w(TAG, "[establishVpn] Whitelist mode: ignoring ${blockedPkgs.size} blocked app(s) (block disabled).")
                }
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
                // stopSelf→onDestroy 间隔 42s)。改为 dup 出独立 fd 交给 Go 独占;必须 detachFd
                // 把 PFD 的 fdsan 所有权也一并交出去——否则 PFD 仍登记为 fd 主人,Go 用裸
                // close() 关掉后该 fd 号被复用会触发 fdsan 所有权冲突直接 SIGABRT(实测闪退)。
                // 原始 PFD 留在 Kotlin(系统关闭回调挂在它身上),shutdown 对它的 close 就是
                // 拆 VPN 的唯一干净信号,图标即刻消失。
                val dupPfd = pfd.dup()
                val goFd = dupPfd.detachFd()
                // 注册 UID 反查回调(per-app「禁止联网」):Go TUN 路径按连接回问 Android
                // 连接所属 UID,命中 tun.blocked_uids 即丢弃。必须在 startRouter 前注册,
                // 引擎启动时注入 TUN handler。
                smartproxy.mobile.Mobile.setUIDResolver(UIDResolver(this))
                smartproxy.mobile.Mobile.startRouter(configPath, goFd.toLong(), true)
                Log.i(TAG, "[establishVpn] Mobile.startRouter() returned successfully in ${System.currentTimeMillis() - t0} ms. (goFd=$goFd, kotlinPfd=${pfd.fd}, tunFds=${tunFdCount()})")
                tunPfd = pfd
                Log.i(TAG, "[establishVpn] Step 4: VPN established. tunPfd retained for shutdown close.")
            } catch (e: Exception) {
                Log.e(TAG, "[establishVpn] Mobile.startRouter threw exception! Closing PFD...", e)
                pfd.close()
                tunPfd = null
                // goFd 所有权已交 Go(detachFd):若其已 os.NewFile 包装,Go 的失败清理会关它;
                // 此处不关,避免与 Go 清理路径 double-close(fdsan 也会因所有权挂错而 abort)。
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

    /** 把 [pkg] 加进黑名单(bypass)。已卸载/不可见的包抛 NameNotFoundException → 跳过并
     *  告警,不让一个陈旧包名拖垮 establish(见 establishVpn 调用处)。isSelf=true 仅用于
     *  日志标注(自身 uid 排除是防回环的关键项,缺失要留痕)。返回是否成功加入。 */
    private fun applyDisallowedApp(builder: Builder, pkg: String, isSelf: Boolean): Boolean {
        return try {
            builder.addDisallowedApplication(pkg)
            true
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            val tag = if (isSelf) " (self — unexpected! TUN loopback protection lost)" else ""
            Log.w(TAG, "[establishVpn] Skipping disallowed '$pkg': not installed$tag")
            false
        }
    }

    /** 把 [pkg] 加进白名单(仅代理)。已卸载/不可见的包跳过并告警(同上)。返回是否成功加入。 */
    private fun applyAllowedApp(builder: Builder, pkg: String): Boolean {
        return try {
            builder.addAllowedApplication(pkg)
            true
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            Log.w(TAG, "[establishVpn] Skipping allowed '$pkg': not installed")
            false
        }
    }

    /** 把「禁止联网」包名解析成 uid(建立时快照);已卸载/不可见的包跳过并告警,
     *  不让一个陈旧包名拖垮 establish(与 applyDisallowedApp 同策略)。 */
    private fun resolveBlockedUids(pkgs: Set<String>): List<Int> {
        return pkgs.mapNotNull { pkg ->
            try {
                packageManager.getApplicationInfo(pkg, 0).uid
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(TAG, "[establishVpn] Skipping blocked '$pkg': not installed")
                null
            }
        }
    }

    /** 统计本进程当前持有的 tun 设备 fd 数(/proc/self/fd 符号链接指向 /dev/tun)。
     *  诊断用:stop 后若仍 >0,说明 Go 或 PFD 没真正释放,内核不会删 tun0,状态栏图标
     *  就赖到服务/进程销毁。失败返回 -1。 */
    private fun tunFdCount(): Int = try {
        java.io.File("/proc/self/fd").listFiles()?.count { f ->
            try { android.system.Os.readlink(f.absolutePath).contains("tun") } catch (e: Exception) { false }
        } ?: 0
    } catch (e: Exception) {
        -1
    }

    /** 停引擎 + 收前台服务 + 状态落 false(§4.5)。
     *
     *  ## 停止顺序:对齐 v2rayNG stopAllService(2026-08 图标赖着不掉排查)
     *
     *  关 tun fd 之前,必须**先让系统拆掉 VPN 网络**,再关最后一个 fd:
     *
     *  ```
     *  1. stopRouter()     停 Go 引擎,关掉 establishVpn 里 dup 出的那份独立 fd(goFd)
     *  2. stopSelf()       触发系统拆 VPN 网络:注销 NetworkAgent / 移除路由
     *  3. sleep(100ms)     等异步拆网完成(应用活跃连接拿到 NetworkLost,释放 dst 引用)
     *  4. tunPfd.close()   关原始 PFD —— tun 设备的最后一次引用,此时已无外部引用,秒删
     *  ```
     *
     *  **为什么不能先关 fd**:tun 设备的两个 fd(goFd + PFD)都关掉、内核开始删 tun0 时,
     *  若 VPN 网络还挂着(路由仍指向 tun0),曾经走过流量的应用 TCP 连接会 hold 住 tun0 的
     *  dev refcount(连接 socket 的 dst 持有 dev 引用),内核 `netdev_wait_allrefs` 会一直等
     *  到这些连接自然超时关闭(实测数十秒)才真正删掉 tun0;`interfaceRemoved` 事件不触发,
     *  状态栏钥匙图标就赖着不掉。**没流量 = 没有活跃连接 = 没有 dst 引用 = 秒删**——正是
     *  用户观察到的现象。v2rayNG 用"stopSelf 先行 + 100ms 留白再关 fd"解决同一问题
     *  (CoreVpnService.stopAllService:"a race condition that can leave the VPN icon in
     *  the status bar")。先关 goFd 保留 PFD 的含义不变:PFD 是系统追踪的唯一 fd,close 它
     *  就是拆 VPN 的唯一干净信号;先关 PFD 而 goFd 还开着时,系统按 fd-close 查设备状态
     *  看到"还在"即跳过、不再复查(实测 stopSelf→onDestroy 间歇性拖到 128s)。
     *
     *  ## fullTeardown 参数
     *
     *  - `true`(默认):用户停止 / onRevoke / onDestroy,完整拆机,内含 stopSelf + 留白。
     *  - `false`:仅 ACTION_RESTART 重建——服务需存活,不能 stopSelf,停引擎 + 关 fd 后
     *    立即按新配置重建,旧 tun0 残留等连接关闭即可(不影响新会话图标)。
     *
     *  幂等:重复进入 startedEngine=false、tunPfd 已置 null;stopSelf() 本身也是幂等的。
     */
    private fun shutdown(fullTeardown: Boolean = true) {
        // P1#6:完整拆机只执行一次。ACTION_STOP 的 shutdown 之后 onDestroy 会再调一次,
        // 没有这个守卫会重复 sleep(100ms)+stopForeground,停止累计睡 ~200ms;onRevoke 与
        // onDestroy 先后到达同理。重建(fullTeardown=false)不置位,可反复执行。
        if (tornDown) {
            Log.i(TAG, "[shutdown] Already torn down (tornDown=true), skipping.")
            return
        }
        io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync.onStopping(this)
        Log.i(TAG, "[shutdown] Step 0: Enter shutdown(). startedEngine=$startedEngine, _isRunning=${_isRunning.value}, tunFds=${tunFdCount()}, fullTeardown=$fullTeardown")
        if (startedEngine) {
            try {
                Log.i(TAG, "[shutdown] Step 1/6: Invoking Go Mobile.stopRouter()... (tunFds before=${tunFdCount()})")
                val t0 = System.currentTimeMillis()
                smartproxy.mobile.Mobile.stopRouter()
                val duration = System.currentTimeMillis() - t0
                Log.i(TAG, "[shutdown] Step 1/6: Mobile.stopRouter() completed in ${duration} ms. tunFds after=${tunFdCount()}")
            } catch (e: Exception) {
                Log.e(TAG, "[shutdown] Step 1/6: Mobile.stopRouter() threw exception", e)
            }
            startedEngine = false
        } else {
            Log.i(TAG, "[shutdown] Step 1/6: startedEngine is false, skipping Mobile.stopRouter().")
        }

        if (fullTeardown) {
            // v2rayNG 顺序:先 stopSelf 拆网络,再关最后一个 fd。留白给系统异步拆网
            // (注销 NetworkAgent / 移除路由 → 活跃连接的 dst 引用释放),否则关 fd 时
            // 网络还挂着,活跃连接 hold 住 tun0 → netdev_wait_allrefs 等连接超时,图标赖着。
            Log.i(TAG, "[shutdown] Step 2/6: Calling stopSelf() to tear down VPN network BEFORE closing tun fd...")
            stopSelf()
            try {
                Thread.sleep(TEARDOWN_SETTLE_MS)
            } catch (e: InterruptedException) {
                Log.w(TAG, "[shutdown] Step 2/6: Sleep interrupted", e)
            }
            Log.i(TAG, "[shutdown] Step 2/6: stopSelf() settle delay done. tunFds=${tunFdCount()}")
        } else {
            Log.i(TAG, "[shutdown] Step 2/6: fullTeardown=false (restart rebuild), skipping stopSelf()/settle.")
        }

        // 注意:不对 Go 那份 fd 做 Java 侧兜底强关——它已 detach 归 Go 独占,从 Java 抢关
        // (或让该 fd 号被复用)会触发 fdsan 所有权冲突 SIGABRT(实测闪退)。stopRouter 后是否
        // 真关干净,由下面各步 tunFds 判定:若仍 >0,说明 Go 引擎没关掉它的 fd,修复应放在
        // Go 侧(StopRouter 关 fd),而不是 Java 侧。
        tunPfd?.let { pfd ->
            try {
                Log.i(TAG, "[shutdown] Step 3/6: Closing tun PFD (last fd to tun device, tear down VPN)...")
                pfd.close()
                Log.i(TAG, "[shutdown] Step 3/6: tun PFD closed. tunFds=${tunFdCount()}")
            } catch (e: Exception) {
                Log.e(TAG, "[shutdown] Step 3/6: tun PFD close failed", e)
            }
            tunPfd = null
        }

        if (fullTeardown) {
            // 完整拆机(用户停止 / onRevoke / onDestroy):拆保活通知 + 状态落 false。
            // 重建(fullTeardown=false)时不拆——通知保留避免闪烁,_isRunning 保持 true,
            // 隧道重建对用户无感;若重建失败,由 startInternal 失败分支负责落 false。
            Log.i(TAG, "[shutdown] Step 4/6: Calling ServiceCompat.stopForeground(STOP_FOREGROUND_REMOVE)...")
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            Log.i(TAG, "[shutdown] Step 4/6: stopForeground completed.")

            Log.i(TAG, "[shutdown] Step 5/6: Updating state _isRunning.value = false...")
            _isRunning.value = false
            startedAt = 0L
            // 完整拆机完成,后续(如 onDestroy)的 shutdown 直接跳过。
            tornDown = true
        } else {
            Log.i(TAG, "[shutdown] Step 4/6: fullTeardown=false, keeping foreground notification + isRunning=true for rebuild.")
        }
        Log.i(TAG, "[shutdown] Step 6/6: shutdown() completed. _isRunning=${_isRunning.value}. tunFds=${tunFdCount()}")
    }

    /** 被其它 VPN 抢占 / 系统设置断开:系统调此,隧道即刻失效(§4.5 主信号)。
     *  shutdown(fullTeardown=true) 内部已含 stopSelf(),不再单独调。 */
    override fun onRevoke() {
        super.onRevoke()
        val passive = !userInitiatedStop
        Log.w(TAG, "[onRevoke] Triggered by system! userInitiatedStop=$userInitiatedStop, passive=$passive")
        Log.i(TAG, "[onRevoke] Executing shutdown()...")
        shutdown()
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

