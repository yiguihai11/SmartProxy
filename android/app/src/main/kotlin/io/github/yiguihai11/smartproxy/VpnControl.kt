package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

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
 */
object VpnControl {

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

    fun dispatch(context: Context, action: String): String {
        when (action) {
            "start" -> {
                // prepare() 非空 = 用户撤销过 VPN 授权,必须先回 App 重新授权,面板办不到。
                if (VpnService.prepare(context) != null) {
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
            else -> return "未知动作: $action"
        }
    }

    /** 串行化重启请求:调用线程不定(Go 回调线程 / 主线程补跑),状态变更全上锁。 */
    private fun requestRestart(context: Context) = synchronized(lock) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastRestartAt < DEBOUNCE_MS) {
            return@synchronized   // 同一次写入的多发事件 → 本轮 start 已会重读最新 config
        }
        lastRestartAt = now

        if (restartInFlight) {
            restartPending = true   // 上一轮在飞;必要时由该轮收尾补跑
            return@synchronized
        }
        restartInFlight = true
        restartPending = false

        main.post {
            if (SmartProxyVpnService.isRunning.value) {
                SmartProxyVpnService.stop(context)
            }
            main.postDelayed({
                SmartProxyVpnService.start(context)
                // 宽松持有后收尾:放开重启锁;持有期间有新请求则补跑一轮(重读最新 config)。
                main.postDelayed({
                    synchronized(lock) {
                        restartInFlight = false
                        if (restartPending) {
                            restartPending = false
                            requestRestart(context)
                        }
                    }
                }, LATCH_HOLD_MS)
            }, STOP_LEAD_MS)
        }
    }
}
