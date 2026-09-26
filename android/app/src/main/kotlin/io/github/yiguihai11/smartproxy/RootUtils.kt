package io.github.yiguihai11.smartproxy

import java.io.File

/**
 * 设备 Root 权限检测工具类。
 * 用于判断当前设备是否具备 su / Root 权限，以决定是否开放 system 或 mixed 等内核级协议栈。
 */
object RootUtils {

    /**
     * 判断当前系统是否拥有 Root 权限。
     * 检测常见 su 二进制文件路径及 which su 执行状态。
     */
    val isDeviceRooted: Boolean by lazy {
        checkSuBinary() || checkSuExec()
    }

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

    private fun checkSuExec(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val line = process.inputStream.bufferedReader().readLine()
            process.destroy()
            !line.isNullOrBlank()
        } catch (_: Throwable) {
            false
        }
    }
}
