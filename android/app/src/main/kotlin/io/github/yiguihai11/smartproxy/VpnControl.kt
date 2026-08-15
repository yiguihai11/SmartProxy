package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.VpnService
import android.os.Handler
import android.os.Looper

/**
 * M5:面板启停控制。Go admin 的 HTTP goroutine 回调 bridge 时,当前线程没有 Looper
 * (JNI attach 的纯 Go 线程),直接调 start/stop 会崩——这里统一 post 到主线程执行。
 *
 * 启停只在安卓端(§4.4);面板对 VPN 的唯一交互是保存后 restart,start/stop 仅供
 * 完整性(也走同一通道)。返回值约定:空串 = 已受理,非空 = 错误描述(返给面板 400)。
 */
object VpnControl {

    private val main = Handler(Looper.getMainLooper())

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
                main.post {
                    if (SmartProxyVpnService.isRunning.value) {
                        SmartProxyVpnService.stop(context)
                    }
                    // 旧会话完全释放 fd、引擎停净后再起(同 MainActivity.restartVpn)。
                    main.postDelayed({ SmartProxyVpnService.start(context) }, 500)
                }
                return ""
            }
            else -> return "未知动作: $action"
        }
    }
}
