package io.github.yiguihai11.smartproxy

import android.app.Application

/**
 * Application 入口:config.json 真源就位。Go→Android 反向桥(自动重启)已删除
 * (2026-08,见 mobile/bridge.go 注释),这里只做幂等的路由数据落盘 + config 不变量。
 */
class SmartProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // 路由数据(chnroute/acl)→ cacheDir + filesDir/config.json 应用不变量:
        // 首页开关、面板 /files、dashboard 首次进入都要读它们。
        //
        // P0#8:整体包 runCatching,任何一步异常(asset 缺失、IO 失败)都不能让
        // Application.onCreate 抛异常把整个 App 闪退掉。ensureConfig 内部已做
        // 损坏回退 + 原子写,这里是最外层兜底。
        runCatching {
            ConfigProvider.ensureRuntimeFiles(this)
            ConfigProvider.ensureConfig(this)
        }
    }
}
