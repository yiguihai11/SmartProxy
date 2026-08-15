package io.github.yiguihai11.smartproxy

import android.app.Application

/**
 * Application 入口(M5):一上来就把 Go→Android 桥注册好,并把 config.json 真源就位。
 * 必须在任何组件(Activity / VpnService / BootReceiver)之前执行,否则 VpnService
 * 经 StartRouter 后 configReload 取 currentBridge() 会取到 nil(自动重启静默跳过),
 * 首页开关初始态也读不到 config.json。
 */
class SmartProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AndroidBridgeImpl.register(this)
        // 路由数据(chnroute/acl)→ cacheDir + filesDir/config.json 应用不变量:
        // 首页开关、面板 /files、dashboard 首次进入都要读它们。
        ConfigProvider.ensureRuntimeFiles(this)
        ConfigProvider.ensureConfig(this)
    }
}
