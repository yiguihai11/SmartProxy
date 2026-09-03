package io.github.yiguihai11.smartproxy.shizuku

import android.content.pm.PackageManager
import android.util.Log
import rikka.shizuku.Shizuku
import java.util.concurrent.TimeUnit

/**
 * 以 shell(uid 2000,Shizuku ADB/Root 模式)身份跑单条系统命令的薄封装。
 *
 * Shizuku 授权后起的进程跟 `adb shell` 同权——持有 WRITE_SECURE_SETTINGS、DEVICE_POWER
 * 等签名级权限,dumpsys/cmd/settings/svc/pm/am 这一整面 shell 命令都够得着,免 root 干
 * 以前要 root 的活(加电池白名单、全局代理、静默安装、冻结 App…)。不需要起 tethering
 * 那种重 UserService,适合一次性轻量控制。
 */
object ShizukuShell {

    private const val TAG = "ShizukuShell"

    /** Shizuku binder 存活、非史前版本、且已拿到授权:三者齐备才能起 shell 进程。 */
    fun available(): Boolean =
        runCatching {
            Shizuku.pingBinder() &&
                !Shizuku.isPreV11() &&
                Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)

    // ponytail: 13.1.5 里 Shizuku.newProcess 是 private+deprecated(API 14 计划移除),
    // 没有公开的等价格;反射调它是最短路径,返回值 ShizukuRemoteProcess 是 public 的
    // Process 子类。它真被移除的那天,run() 反射失败返回 false,调用方回退系统弹框即可;
    // 要彻底去掉反射,升级路径是 bindUserService 起一个跑命令的 UserService。
    private val newProcessMethod: java.lang.reflect.Method? by lazy {
        runCatching {
            Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java, Array<String>::class.java, String::class.java
            ).apply { isAccessible = true }
        }.getOrNull()
    }

    /**
     * 以 shell 跑 [cmd] 并等它结束,返回是否 exit 0。调用方必须在 IO 线程(waitFor 阻塞)。
     * stderr 单独开线程抽干,避免命令输出撑满管道把进程卡死。
     */
    fun run(vararg cmd: String): Boolean {
        val method = newProcessMethod ?: return false
        val process = try {
            method.invoke(null, *arrayOf<Any?>(cmd, null, null)) as Process
        } catch (e: Throwable) {
            Log.w(TAG, "newProcess ${cmd.joinToString(" ")} failed: ${e.message}")
            return false
        }
        val errDrain = Thread { runCatching { process.errorStream.bufferedReader().readText() } }
            .apply { isDaemon = true; start() }
        return try {
            runCatching { process.inputStream.bufferedReader().readText() }
            val completed = process.waitFor(10, TimeUnit.SECONDS)
            if (!completed) {
                Log.w(TAG, "${cmd.joinToString(" ")} timed out after 10s")
                return false
            }
            val code = process.exitValue()
            if (code != 0) Log.w(TAG, "${cmd.joinToString(" ")} exited $code")
            code == 0
        } catch (e: Throwable) {
            Log.w(TAG, "${cmd.joinToString(" ")} waitFor failed: ${e.message}")
            false
        } finally {
            runCatching { errDrain.join(1000) }
            runCatching { process.destroy() }
        }
    }

    /**
     * 把 [pkg] 加进系统 doze 电池优化白名单(等价于系统设置里「忽略电池优化」,
     * PowerManager.isIgnoringBatteryOptimizations 随之 true)。免 root、不弹系统框。
     * 注意:这只覆盖 AOSP doze;厂商私有冻结(如 OriginOS 智能冻结)不在此列,仍需厂商引导。
     */
    fun addBatteryWhitelist(pkg: String): Boolean =
        run("dumpsys", "deviceidle", "whitelist", "+$pkg")
}
