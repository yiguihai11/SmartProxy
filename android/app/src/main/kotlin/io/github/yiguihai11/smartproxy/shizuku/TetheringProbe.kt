package io.github.yiguihai11.smartproxy.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import rikka.shizuku.Shizuku

/**
 * 应用侧探针入口(M6):检查 Shizuku 状态 → 授权 → 后台线程 bind UserService →
 * 同步调 probe() → 结果回主线程。binder 调用可能阻塞十几秒,绝不能放主线程。
 */
object TetheringProbe {
    private const val TAG = "TetheringProbe"
    private const val REQUEST_CODE = 0x53A0

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
            val connection = object : Shizuku.UserServiceConnection {
                override fun onServiceConnected(componentName: ComponentName, binder: IBinder) {
                    try {
                        val result = IShizukuProbe.Stub.asInterface(binder).probe()
                        post(result)
                        Log.i(TAG, "probe() 完成,${result.length} 字符")
                    } catch (e: Throwable) {
                        post("probe 调用失败: $e")
                        Log.e(TAG, "probe 失败", e)
                    } finally {
                        runCatching { Shizuku.unbindUserService(this, false) }
                    }
                }

                override fun onServiceDisconnected(componentName: ComponentName) {
                    post("UserService 意外断开。")
                }
            }
            val bound = runCatching {
                Shizuku.bindUserService(ShizukuProbeService.createUserServiceArgs(), connection)
            }.getOrDefault(false)
            if (!bound) post("bindUserService 失败(Shizuku 版本过低? UserService 加载异常?)")
        }.start()
    }
}
