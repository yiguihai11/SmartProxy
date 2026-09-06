package io.github.yiguihai11.smartproxy

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import io.github.yiguihai11.smartproxy.shizuku.ShizukuForegroundRecovery
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Application 入口:config.json 真源就位。Go→Android 反向桥(自动重启)已删除
 * (2026-08,见 mobile/bridge.go 注释),这里只做幂等的路由数据落盘 + config 不变量。
 *
 * 主进程额外做分应用列表(§5)的预加载与装/卸订阅:进程一活就把「全量应用 + label +
 * 首屏图标」拉到内存缓存,用户点进应用选择页时 cached() 直接命中零等待。动态订阅
 * ACTION_PACKAGE_ADDED/REMOVED/REPLACED(系统限定广播,进程活着时送达)→ 失效缓存 +
 * 后台重拉。进程被杀后广播收不到没关系——缓存是进程内内存,随进程一起消失,冷启动
 * 重新预加载即最新,两态天然一致,无需静态注册(Android 8+ 也收不到这类隐式广播)。
 */
class SmartProxyApp : Application() {

    /** 预加载 / 包事件重拉跑在 IO;进程级 scope,生命周期与进程同长,无泄露。 */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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
        // 只主进程预加载分应用列表 + 订阅装/卸(SharedProcess 与 shell UserService 进程
        // 没有 UI / 分应用页,不该白枚举应用也不该注册 receiver)。
        if (isMainProcess()) {
            preloadAppList()
            subscribePackageChanges()
        }
        // Android 14+ 受保护共享恢复兜底:Shizuku 的 replacement-Binder 通知可能被系统推迟到
        // 进程回前台,这里挂全局生命周期回调在每次 resume 时请求替换 Binder。register 内部只在
        // SDK≥34 且主进程注册(SharedProcess 与 shell UserService 进程都不该挂)。
        runCatching {
            ShizukuForegroundRecovery.register(this)
        }
    }

    /** 主进程判定。API 28+ 用 Application.getProcessName();26/27 读 /proc/self/cmdline
     *  (本 App 只有主进程与 :shizuku_tethering,cmdline 前缀即 applicationId)。 */
    private fun isMainProcess(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return Application.getProcessName() == packageName
        }
        return try {
            val bytes = File("/proc/self/cmdline").readBytes()
            val end = bytes.indexOf(0)
            val cmd = if (end < 0) bytes else bytes.copyOfRange(0, end)
            String(cmd) == packageName
        } catch (_: Exception) {
            true // 兜底:读不到就当主进程,最坏情况只是多一次无害的预加载
        }
    }

    /** 启动即后台预加载分应用列表:用户在 MainActivity 操作、点进应用选择页时缓存早已就绪。 */
    private fun preloadAppList() {
        appScope.launch {
            val apps = AppEnumerator.load(this@SmartProxyApp)
            AppEnumerator.warmIcons(this@SmartProxyApp, apps)
        }
    }

    /** 动态订阅应用安装 / 卸载 / 覆盖(更新)。系统只把这些广播发给存活进程;进程死了缓存
     *  也没了(见类注释),冷启动重拉兜底,故不静态注册。 */
    private fun subscribePackageChanges() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        // API 34+ 动态注册必须带 flags;receiver 只收系统限定的 PACKAGE_* 广播,
        // RECEIVER_EXPORTED 收系统广播必需且无第三方注入面。
        ContextCompat.registerReceiver(this, packageChangeReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
    }

    private val packageChangeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            // 覆盖安装可能 ADDED+REPLACED 连发,refresh 幂等,重复无害。
            AppEnumerator.invalidate()
            appScope.launch {
                val apps = AppEnumerator.refresh(context)
                AppEnumerator.warmIcons(context, apps)
            }
        }
    }
}
