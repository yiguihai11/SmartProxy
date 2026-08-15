package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * gomobile 反向桥实现(§4.4)。纯 Go 面板还原后,/api/prefs、/api/vpn 桥接端点已删除,
 * 桥只保留 Vpn(action):mobile/bridge.go 的 configReload 检测到隧道参数变更时经它触发
 * Android 侧 VPN 重启(重建 VpnService 才生效的字段)。
 *
 * 注册时机:SmartProxyApp.onCreate()(任何入口——Activity/BootReceiver——之前),
 * 保证 configReload 取 currentBridge() 时桥已就位。
 *
 * 线程:vpn 会触发启停,统一走 VpnControl 主线程派发(Go 回调线程无 Looper)。
 */
object AndroidBridgeImpl : smartproxy.mobile.AndroidBridge {

    @Volatile
    private var appContext: Context? = null

    fun register(context: Context) {
        appContext = context.applicationContext
        // 反向桥注册:把本对象交给 gobind → mobile.SetAndroidBridge(...)。必须在任何
        // VpnService 启动之前执行(引擎 watcher 可能在引擎启动后立刻触发重载)。
        smartproxy.mobile.Mobile.setAndroidBridge(this)
    }

    private fun ctx(): Context = appContext
        ?: throw IllegalStateException("AndroidBridgeImpl 未注册(缺少 Application 初始化?)")

    override fun vpn(action: String): String = VpnControl.dispatch(ctx(), action)
}
