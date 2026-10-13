package io.github.yiguihai11.smartproxy

import android.app.job.JobParameters
import android.app.job.JobService
import android.util.Log

/**
 * 监听网络恢复并自动重连 VPN 的 JobService。
 * - 符合 Android 12~15 规范:JobService 是系统豁免允许从后台启动前台服务 (FGS) 的官方通道。
 * - 当因网络断开等原因被动暂停 VPN 时由 NetworkRecoveryManager 注册。
 * - 网络恢复后系统调起此类执行 attemptRestore,拉起 SmartProxyVpnService。
 */
class NetworkRestoreJobService : JobService() {
    companion object {
        private const val TAG = "NetRestoreJob"
    }

    override fun onStartJob(params: JobParameters?): Boolean {
        Log.i(TAG, "onStartJob: Network available, attempting to restore VPN...")
        NetworkRecoveryManager.attemptRestore(applicationContext)
        return false // 同步执行完毕，无需额外异步保持
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        Log.i(TAG, "onStopJob: Network lost again while restoring")
        return true // 网络再次丢失时允许系统在下次网络就绪时重试
    }
}
