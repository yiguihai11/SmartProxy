package io.github.yiguihai11.smartproxy.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * 应用侧探针入口(M6):检查 Shizuku 状态 → 授权 → 后台线程 bind UserService →
 * 同步调 probe() → 结果回主线程。probe() 可能阻塞十几秒,绝不能放主线程,所以
 * bind 和调用都跑在子线程,用 CountDownLatch 等 onServiceConnected 并设超时。
 *
 * 注意:Shizuku 13.x 的 bindUserService 收的是框架的 android.content.ServiceConnection,
 * 不是嵌套的 Shizuku.UserServiceConnection(旧版才有,别照旧教程写)。
 */
object TetheringProbe {
    private const val TAG = "TetheringProbe"
    private const val REQUEST_CODE = 0x53A0
    private const val BIND_TIMEOUT_SECONDS = 25L

    /**
     * @param onResult 主线程回调,入参为多行探测结果文本
     */
    fun run(context: Context, onResult: (String) -> Unit) {
        val main = Handler(Looper.getMainLooper())
        fun post(msg: String) = main.post { onResult(msg) }

        if (!Shizuku.pingBinder()) {
            post("Shizuku 未运行。\n请先启动 Shizuku App(无线调试 / ADB / root 任选其一),再重试。")
            return
        }
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            runCatching { Shizuku.requestPermission(REQUEST_CODE) }
            post("尚未授权 Shizuku。\n已发起授权请求,请在系统弹窗点允许,然后再次点击运行。")
            return
        }

        Thread {
            val connected = CountDownLatch(1)
            var binder: IBinder? = null
            val connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, service: IBinder) {
                    binder = service
                    connected.countDown()
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    // 探测在下面统一收尾;断开时若还没出结果,靠超时兜底。
                    Log.w(TAG, "UserService disconnected early")
                }
            }

            try {
                Shizuku.bindUserService(ShizukuProbeService.createUserServiceArgs(), connection)
            } catch (e: Throwable) {
                post("bindUserService 失败: ${e.message}")
                return@Thread
            }

            if (!connected.await(BIND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                post("${BIND_TIMEOUT_SECONDS}s 内未连上 UserService。\n请确认已在 Shizuku App 里给本应用授权,再重试。")
                return@Thread
            }

            try {
                val result = IShizukuProbe.Stub.asInterface(binder!!).probe()
                post(result)
                Log.i(TAG, "probe() 完成,${result.length} 字符")
            } catch (e: Throwable) {
                post("probe 调用失败: $e")
                Log.e(TAG, "probe 失败", e)
            } finally {
                runCatching {
                    Shizuku.unbindUserService(ShizukuProbeService.createUserServiceArgs(), connection, false)
                }
            }
        }.start()
    }
}
