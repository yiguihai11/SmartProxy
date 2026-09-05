package io.github.yiguihai11.smartproxy

import android.app.Application
import io.github.yiguihai11.smartproxy.shizuku.ShizukuForegroundRecovery

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
        // Android 14+ 受保护共享恢复兜底:Shizuku 的 replacement-Binder 通知可能被系统推迟到
        // 进程回前台,这里挂全局生命周期回调在每次 resume 时请求替换 Binder。register 内部只在
        // SDK≥34 且主进程注册(SharedProcess 与 shell UserService 进程都不该挂)。
        runCatching {
            ShizukuForegroundRecovery.register(this)
        }
    }
}
