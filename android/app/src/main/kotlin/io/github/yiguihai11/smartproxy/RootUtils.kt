package io.github.yiguihai11.smartproxy

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * 设备 Root 权限检测工具类。
 * 用于判断当前设备是否具备 su / Root 权限，以决定是否开放 system 或 mixed 等协议栈。
 * 适配传统 Magisk、KernelSU、APatch 以及 su 隔离环境。
 */
object RootUtils {

    @Volatile
    private var cachedRootStatus: Boolean? = null

    /**
     * 判断当前系统是否拥有 Root 权限。
     * 具备缓存机制；当未获得 Root 时支持按需重新探测，避免用户在授权管理器中授权后需重启 App。
     */
    val isDeviceRooted: Boolean
        get() = checkRoot(forceRefresh = false)

    /**
     * 检测设备 Root 权限。
     * @param forceRefresh 是否强制刷新检测结果。
     */
    @Synchronized
    fun checkRoot(forceRefresh: Boolean = false): Boolean {
        if (!forceRefresh) {
            cachedRootStatus?.let { return it }
        }
        val rooted = checkSuCommand() || checkSuBinary() || checkWhichSu()
        cachedRootStatus = rooted
        return rooted
    }

    /**
     * 针对 KernelSU / APatch / Magisk 的真实执行探测。
     * KernelSU 和 APatch 在未调用 su 之前对普通应用环境进行命名空间挂载隔离，
     * 静态探测文件存在性会失效，但执行 `su -c id` 能直接获得 uid=0。
     */
    private fun checkSuCommand(): Boolean {
        val testCommands = arrayOf(
            arrayOf("su", "-c", "id"),
            arrayOf("/system/bin/su", "-c", "id")
        )
        for (cmd in testCommands) {
            var process: Process? = null
            try {
                process = Runtime.getRuntime().exec(cmd)
                val line = process.inputStream.bufferedReader().use { it.readLine() } ?: ""
                val exited = try {
                    process.waitFor(1500, TimeUnit.MILLISECONDS)
                } catch (_: Throwable) {
                    false
                }
                if (line.contains("uid=0") || (exited && process.exitValue() == 0 && line.isNotEmpty())) {
                    return true
                }
            } catch (_: Throwable) {
                // 忽略异常，尝试下一个命令
            } finally {
                process?.let { p ->
                    runCatching { p.inputStream.close() }
                    runCatching { p.outputStream.close() }
                    runCatching { p.errorStream.close() }
                    runCatching { p.destroy() }
                }
            }
        }
        return false
    }

    /**
     * 传统 Magisk / Superuser 静态文件路径探测。
     */
    private fun checkSuBinary(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        return paths.any {
            try {
                File(it).exists()
            } catch (_: Throwable) {
                false
            }
        }
    }

    /**
     * 使用 which 查询系统 PATH 中是否存在 su。
     */
    private fun checkWhichSu(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val line = process.inputStream.bufferedReader().use { it.readLine() }
            val exited = try {
                process.waitFor(1000, TimeUnit.MILLISECONDS)
            } catch (_: Throwable) {
                false
            }
            exited && process.exitValue() == 0 && !line.isNullOrBlank()
        } catch (_: Throwable) {
            false
        } finally {
            process?.let { p ->
                runCatching { p.inputStream.close() }
                runCatching { p.outputStream.close() }
                runCatching { p.errorStream.close() }
                runCatching { p.destroy() }
            }
        }
    }
}

