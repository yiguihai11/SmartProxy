package io.github.yiguihai11.smartproxy.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import rikka.shizuku.Shizuku
import smartproxy.mobile.Mobile

/**
 * App 侧热点共享桥(M7):绑定 Shizuku 持久 UserService → startHotspot 拿 test TUN fd →
 * dup+detachFd 喂给 Go 引擎(AddTunFd)做双 TUN;停止时按逆序回收。
 *
 * fd 三归属(fdsan 纪律,见 plan A 节所有权表,不许破坏):
 *  1. UserService 持有自己的 tunPfd —— stopHotspot() 由服务端关;
 *  2. App 收到的 ParcelFileDescriptor(Binder 自动 dup)—— 本单例持有,stop() 时 close;
 *  3. App dup()+detachFd() 出来的 goFd —— 从此归 Go 引擎独占,RemoveTunFd / StopRouter 关;
 *     Kotlin 拿到 goFd 后绝不碰它(detachFd 已把 fdsan 所有权交给 Go)。
 *
 * start() 是异步的(绑定 + startHotspot 都阻塞,只能后台线程);结果经主线程回调。
 * 生命周期兜底:停 VPN(SmartProxyVpnService.shutdown)会调 [stop];App 被强杀时
 * 服务端 linkToDeath 自动回收(见 ShizukuProbeService)。
 */
object HotspotShare {
    private const val TAG = "HotspotShare"
    private const val BIND_TIMEOUT_SECONDS = 25L
    // 与 ShizukuProbeService.TUN_ADDR_V4/V6 保持一致(喂给 Go 引擎的地址,不能漂移)
    private const val TEST_TUN_V4 = "192.0.2.2/24"
    private const val TEST_TUN_V6 = "2001:db8:9877::1/64"
    // 固定 1500:test TUN 接口默认 MTU 就是 1500,fd 模式 Start 对 ≤0 也兜底 1500;
    // 传 config 的 mtu 若 >1500 会超接口 MTU 触发分片。规避之。
    private const val MTU = 1500L

    private var connection: ServiceConnection? = null
    private var binder: IShizukuProbe? = null
    private var appToken: Binder? = null
    private var pfd: ParcelFileDescriptor? = null
    private var goFd: Int = -1
    @Volatile private var active = false
    @Volatile private var ifaceName: String = ""
    private val mainHandler by lazy { Handler(Looper.getMainLooper()) }

    /** 热点共享是否开启(引擎已挂上额外 TUN)。 */
    fun isActive(): Boolean = active

    /**
     * 异步开启热点共享。要求:Shizuku 已运行 + 已授权 + 引擎已运行(AddTunFd 需要 running)。
     * 开启成功后经主线程回调 (true, "热点已开启 · 接口 xxx");失败回调 (false, 原因)。
     */
    fun start(context: Context, onResult: (Boolean, String) -> Unit) {
        if (active) {
            onResult(true, "热点共享已开启 · 接口 $ifaceName")
            return
        }
        if (!Shizuku.pingBinder()) {
            onResult(false, "Shizuku 未运行。\n请先启动 Shizuku App(无线调试 / ADB / root 任选其一)。")
            return
        }
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            runCatching { Shizuku.requestPermission(0x53A0) }
            onResult(false, "尚未授权 Shizuku。\n已发起授权请求,请在系统弹窗点允许,再重试。")
            return
        }
        if (!Mobile.isRunning()) {
            onResult(false, "请先开启 VPN(热点共享需要引擎先运行,才能挂上第二条 TUN)。")
            return
        }

        val current = binder
        if (current != null && connection != null) {
            // 已绑定过,直接跑(绑定的服务可能已被 Shizuku 杀掉,失败再走重新绑定路径)。
            Thread { runStart(current, onResult) }.start()
            return
        }
        bindAndStart(context, onResult)
    }

    /** 绑定 UserService 并 start;绑定成功与否都走回调。 */
    private fun bindAndStart(context: Context, onResult: (Boolean, String) -> Unit) {
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                val b = IShizukuProbe.Stub.asInterface(service)
                binder = b
                Log.i(TAG, "UserService 已连接,启动热点共享...")
                Thread { runStart(b, onResult) }.start()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                Log.w(TAG, "UserService disconnected(被 Shizuku 回收/重启),重置状态")
                binder = null
                active = false
                goFd = -1
                runCatching { pfd?.close() }
                pfd = null
            }
        }
        connection = conn
        try {
            Shizuku.bindUserService(ShizukuProbeService.createUserServiceArgs(), conn)
        } catch (e: Throwable) {
            connection = null
            onResult(false, "bindUserService 失败: ${e.message}")
        }
    }

    /** 后台线程:调 startHotspot → dup+detachFd → AddTunFd。全程阻塞,不能放主线程。 */
    private fun runStart(b: IShizukuProbe, onResult: (Boolean, String) -> Unit) {
        val fail = { msg: String ->
            active = false
            goFd = -1
            runCatching { b.stopHotspot() }
            runCatching { pfd?.close() }
            pfd = null
            mainHandler.post { onResult(false, msg) }
        }
        try {
            val token = Binder()
            appToken = token
            val result = b.startHotspot(token)
            val err = result.getString(ShizukuProbeService.KEY_ERROR).orEmpty()
            @Suppress("DEPRECATION") // getParcelable(key, class) 需 API 33,minSdk 26 用 core-ktx reified 老签名
            val received: ParcelFileDescriptor? =
                result.getParcelable<ParcelFileDescriptor>(ShizukuProbeService.KEY_PFD)
            if (received == null) {
                fail(if (err.isBlank()) "startHotspot 未返回 fd(无错误信息)" else err)
                return
            }
            pfd = received
            ifaceName = result.getString(ShizukuProbeService.KEY_IFACE) ?: ""

            // dup + detachFd:让 Go 独占一个独立 fd(fdsan 所有权一起交出),Kotlin 此后不碰 goFd。
            val dup = received.dup()
            val fd = dup.detachFd()
            goFd = fd
            val addErr: String? = Mobile.addTunFd(fd.toLong(), TEST_TUN_V4, TEST_TUN_V6, MTU)
            if (addErr != null) {
                // bridge.AddTunFd 失败时已自行 close(fd)(引擎未跑)或内部处理;这里绝不再关 goFd,
                // 只回收 App 侧 pfd + 服务端热点。goFd 归零避免误关。
                Log.e(TAG, "AddTunFd 失败: $addErr")
                goFd = -1
                runCatching { b.stopHotspot() }
                runCatching { received.close() }
                pfd = null
                mainHandler.post { onResult(false, "挂载额外 TUN 失败: $addErr") }
                return
            }
            active = true
            Log.i(TAG, "热点共享已开启: iface=$ifaceName goFd=$fd")
            mainHandler.post { onResult(true, "热点已开启 · 接口 $ifaceName") }
        } catch (e: Throwable) {
            Log.e(TAG, "startHotspot 调用异常", e)
            fail(e.toString())
        }
    }

    /** 幂等停止:先摘 Go 额外 TUN(引擎关 goFd),再让服务端停热点/teardown,最后关 App pfd。 */
    fun stop() {
        if (!active && binder == null && pfd == null) return
        active = false
        val fd = goFd
        if (fd > 0) {
            // RemoveTunFd 幂等;引擎已停(StopRouter 已清 extras)时返回 nil,忽略即可。
            runCatching { Mobile.removeTunFd(fd.toLong()) }
            goFd = -1
        }
        val b = binder
        if (b != null) runCatching { b.stopHotspot() }
        runCatching { pfd?.close() }
        pfd = null
        ifaceName = ""
        val conn = connection
        if (conn != null) {
            runCatching {
                Shizuku.unbindUserService(ShizukuProbeService.createUserServiceArgs(), conn, false)
            }
            connection = null
            binder = null
        }
        appToken = null
        Log.i(TAG, "热点共享已停止")
    }
}
