package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * M5:gomobile 反向桥实现(§4.4)。Go admin server 的 /api/ 桥接端点经
 * `mobile.AndroidBridge`(生成 Java 接口 smartproxy.mobile.AndroidBridge)回调到这里,
 * 读写 SharedPreferences / VpnService。
 *
 * 注册时机:SmartProxyApp.onCreate()(任何入口——Activity/BootReceiver——之前),
 * 保证 StartRouter 取 currentBridge() 时桥已就位。
 *
 * 线程:getPrefs/isRunning 是纯读,在 Go 回调线程直接执行;
 * setPrefs/vpn 会触发启停,统一走 VpnControl 主线程派发(Go 线程无 Looper)。
 */
object AndroidBridgeImpl : smartproxy.mobile.AndroidBridge {

    @Volatile
    private var appContext: Context? = null

    fun register(context: Context) {
        appContext = context.applicationContext
        // 反向桥注册:把本对象交给 gobind → mobile.SetAndroidBridge(...),StartRouter
        // 启动引擎后再挂到 admin server。必须在任何 VpnService 启动之前执行。
        smartproxy.mobile.Mobile.setAndroidBridge(this)
    }

    private fun ctx(): Context = appContext
        ?: throw IllegalStateException("AndroidBridgeImpl 未注册(缺少 Application 初始化?)")

    override fun getPrefs(): String = PrefsService.getJson(ctx())

    /**
     * 保存偏好。返回非空 = 错误(admin 回 400);空 = 成功。
     * 重启由面板显式 POST /api/vpn/set {action:restart} 触发——重启会把当前 admin
     * server 一并带走,若在 setPrefs 里自动重启,HTTP 响应可能被切断,面板的
     * "保存成功→重启中→恢复"状态机就会乱。所以这里只落盘,不重启。
     */
    override fun setPrefs(json: String): String = PrefsService.set(ctx(), json)

    override fun isRunning(): Boolean = SmartProxyVpnService.isRunning.value

    override fun vpn(action: String): String = VpnControl.dispatch(ctx(), action)
}
