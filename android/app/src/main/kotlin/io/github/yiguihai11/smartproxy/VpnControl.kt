package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log

/**
 * M5:面板启停控制。Go admin 的 HTTP goroutine 回调 bridge 时,当前线程没有 Looper
 * (JNI attach 的纯 Go 线程),直接调 start/stop 会崩——这里统一 post 到主线程执行。
 *
 * 启停只在安卓端(§4.4);面板对 VPN 的唯一交互是保存后 restart,start/stop 仅供
 * 完整性(也走同一通道)。返回值约定:空串 = 已受理,非空 = 错误描述(返给面板 400)。
 *
 * restart 串行化(§4.6 watcher 自动重启,App 侧不再手动重启):
 *  - fsnotify 对一次写入会多发事件(open(O_TRUNC) 的 truncate + write 各一个 IN_MODIFY),
 *    加上首页开关与面板共写 config.json → 对一次保存可能连发多个 restart 请求。
 *    去抖窗口内合并成一轮:发起方多发的亚毫秒级事件直接丢弃——这一轮的 start 在
 *    establishVpn 时重读 config.json,必然读到完整落盘的写入,无需补跑。
 *  - 去抖吸收后仍可能重叠(新写入发生在上一轮 stop→start 中途):start 已按最新文件
 *    重建,原则上无需再起;但为防「上一轮 start 已读过文件、写入在其后才落盘」的
 *    窄窗口,把新请求记 pending,本轮 start 落地后(宽松持有)补跑一轮。
 *  - 任何时刻只允许一轮 stop→start 在飞,杜绝双 start(第二个 establishVpn 的
 *    startRouter 报 "router is already running" → stopSelf 会把第一个隧道一起杀掉)。
 *  - 用户显式停止(圆球/通知)会递增世代号:重启循环的 delayed start 与收尾补跑前比对
 *    世代,用户在此期间停过就放弃——保证"关闭后隧道不被重新拉起,图标不残留";
 *    VPN 未在跑时的配置变更只落盘,不自动把 VPN 拉起来。
 */
object VpnControl {

    private const val TAG = "SmartProxyVpn"

    private val main = Handler(Looper.getMainLooper())
    private val lock = Any()

    /** 同一轮重启请求的去抖窗口:吸收一次写入引发的 fsnotify 多发事件(亚毫秒级)。 */
    private const val DEBOUNCE_MS = 300L
    /** stop 与 start 之间留白:等旧会话把 fd / 引擎停净再起(原 MainActivity.restartVpn 同款)。 */
    private const val STOP_LEAD_MS = 500L
    /** start 异步落地(establish→StartRouter)足够宽裕的持有时间,之后才放开重启锁。 */
    private const val LATCH_HOLD_MS = 3000L

    /** 一轮 stop→start 在飞;期间的新重启请求只记 pending,不叠起双 start。 */
    private var restartInFlight = false
    private var restartPending = false
    private var lastRestartAt = 0L   // SystemClock.elapsedRealtime()

    /** 用户显式停止的世代号:圆球 / 通知停止时由 SmartProxyVpnService 递增(restart 的
     *  内部 stop 带 EXTRA_INTERNAL_STOP,不算)。重启循环在 delayed start 与收尾补跑前
     *  比对它——用户在这期间停过,就放弃本轮重启。否则隧道被关后又被拉起来,状态栏
     *  VPN 图标不消失(正是"关闭后图标还在")。 */
    private var userStopEpoch = 0L

    /** 仅用户路径调用(SmartProxyVpnService 的 ACTION_STOP 处理;restart 内部 stop 不经过)。 */
    fun noteUserStop() {
        synchronized(lock) {
            userStopEpoch++
            Log.i(TAG, "[VpnControl] noteUserStop() called. New userStopEpoch=$userStopEpoch")
        }
    }

    fun dispatch(context: Context, action: String): String {
        Log.i(TAG, "[VpnControl] dispatch() called with action=$action")
        when (action) {
            "start" -> {
                // prepare() 非空 = 用户撤销过 VPN 授权,必须先回 App 重新授权,面板办不到。
                // 仅代理(SOCKS5)模式(§8)不建 VpnService,无需该授权,跳过检查。
                if (AppPrefs.serviceMode(context) != AppPrefs.MODE_SOCKS5 &&
                    VpnService.prepare(context) != null
                ) {
                    Log.w(TAG, "[VpnControl] dispatch start: VPN permission not granted.")
                    return "未授权 VPN,请先在 App 首页启动一次"
                }
                main.post { SmartProxyVpnService.start(context) }
                return ""
            }
            "stop" -> {
                main.post { SmartProxyVpnService.stop(context) }
                return ""
            }
            "restart" -> {
                requestRestart(context)
                return ""
            }
            else -> {
                Log.w(TAG, "[VpnControl] dispatch unknown action: $action")
                return "未知动作: $action"
            }
        }
    }

    /** 串行化重启请求:调用线程不定(Go 回调线程 / 主线程补跑),状态变更全上锁。
     *  显式 Unit:表达式体 + 块内自调用会让 Kotlin 推断返回类型时撞上递归问题。 */
    private fun requestRestart(context: Context): Unit = synchronized(lock) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastRestartAt < DEBOUNCE_MS) {
            Log.i(TAG, "[VpnControl] requestRestart: debounced (${now - lastRestartAt} ms < $DEBOUNCE_MS ms)")
            return@synchronized   // 同一次写入的多发事件 → 本轮 start 已会重读最新 config
        }
        lastRestartAt = now

        if (restartInFlight) {
            Log.i(TAG, "[VpnControl] requestRestart: restart already in flight. Setting restartPending=true")
            restartPending = true   // 上一轮在飞;必要时由该轮收尾补跑
            return@synchronized
        }
        restartInFlight = true
        restartPending = false

        val epoch = userStopEpoch
        Log.i(TAG, "[VpnControl] requestRestart: starting restart flow. userStopEpoch=$epoch")
        main.post {
            // VPN 没在跑:配置变更只落盘,不把用户已停掉的 VPN 拉起来。
            if (!SmartProxyVpnService.isRunning.value) {
                Log.i(TAG, "[VpnControl] requestRestart: VPN is not running, skipping restart.")
                synchronized(lock) { restartInFlight = false }
                return@post
            }
            Log.i(TAG, "[VpnControl] requestRestart: calling SmartProxyVpnService.stopInternal(context)...")
            SmartProxyVpnService.stopInternal(context)
            main.postDelayed({
                // 窗口内用户显式停止 → 放弃本轮重启,清空残余状态(否则隧道被关后又被拉起,
                // 状态栏图标不消失)。stopInternal 不递增世代,重启循环自身的 stop 不触发此分支。
                val cancelled = synchronized(lock) {
                    if (userStopEpoch != epoch) {
                        Log.i(TAG, "[VpnControl] requestRestart: user stopped VPN during lead window! (epoch changed $epoch -> $userStopEpoch). Cancelling restart.")
                        restartInFlight = false
                        restartPending = false
                        true
                    } else {
                        false
                    }
                }
                if (cancelled) return@postDelayed
                // 窗口内已被用户 / 其它路径启动(如看到"未连接"又点了圆球)→ 不再重复起,
                // 否则双 start,后一次 startRouter 报 "router is already running" 把隧道杀掉。
                if (SmartProxyVpnService.isRunning.value) {
                    Log.i(TAG, "[VpnControl] requestRestart: VPN is already running. Skipping duplicate start.")
                    synchronized(lock) { restartInFlight = false }
                    return@postDelayed
                }
                Log.i(TAG, "[VpnControl] requestRestart: starting VPN now...")
                SmartProxyVpnService.start(context)
                // 宽松持有后收尾:放开重启锁;持有期间有新请求则补跑一轮(重读最新 config)。
                main.postDelayed({
                    synchronized(lock) {
                        restartInFlight = false
                        if (restartPending) {
                            restartPending = false
                            // 用户没在窗口内停过才补跑;停过则放弃,由下次手动启动读最新配置。
                            if (userStopEpoch == epoch) {
                                Log.i(TAG, "[VpnControl] requestRestart: pending restart found, re-triggering requestRestart.")
                                requestRestart(context)
                            } else {
                                Log.i(TAG, "[VpnControl] requestRestart: pending restart ignored due to user stop.")
                            }
                        }
                    }
                }, LATCH_HOLD_MS)
            }, STOP_LEAD_MS)
        }
    }
}

