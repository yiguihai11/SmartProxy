package io.github.yiguihai11.smartproxy

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * 网络断开恢复与重连管理器。
 *
 * 核心逻辑:
 * 1. 当 VPN 处于运行意图 (vpnDesired=true),但因网络断开 (onRevoke/无网络) 被迫停止时,进入挂起等待恢复态 (vpnSuspended=true)。
 * 2. 同时激活双重恢复机制:
 *    - 进程内活跃 NetworkCallback:秒级响应网络恢复;
 *    - JobScheduler (NetworkRestoreJobService):即使后台进程被杀,系统也在网络连上时调起恢复,且符合 Android 12~15 后台启动 FGS 豁免。
 * 3. 当用户主动停止 (点击关闭/通知停止) 时,取消所有恢复监听并清空 vpnDesired 与 vpnSuspended。
 */
object NetworkRecoveryManager {
    private const val TAG = "SmartProxyNetRecovery"
    const val JOB_ID = 9801

    private val mainHandler = Handler(Looper.getMainLooper())
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** 检查当前是否处于等待网络恢复的挂起态 */
    fun isSuspended(context: Context): Boolean = AppPrefs.vpnSuspended(context)

    /** 启动网络恢复监听与调度 */
    @Synchronized
    fun startRecovery(context: Context) {
        val app = context.applicationContext
        if (!AppPrefs.vpnDesired(app)) {
            Log.i(TAG, "startRecovery skipped: user has manually stopped VPN (vpnDesired=false)")
            return
        }

        AppPrefs.setVpnSuspended(app, true)
        Log.i(TAG, "Entering suspended state: waiting for network connectivity to restore VPN...")

        // 1. 动态注册 NetworkCallback (进程存活时秒级响应)
        registerNetworkCallback(app)

        // 2. 调度 JobScheduler (进程被杀或深度睡眠时的系统级保底唤醒通道)
        scheduleJob(app)
    }

    /** 用户主动停止或 VPN 正常启动时，注销全部恢复监听 */
    @Synchronized
    fun cancelRecovery(context: Context) {
        val app = context.applicationContext
        AppPrefs.setVpnSuspended(app, false)
        unregisterNetworkCallback(app)
        cancelJob(app)
        NotificationHelper.cancelWaitingNotification(app)
        Log.i(TAG, "cancelRecovery: suspended state cleared and all listeners unregistered.")
    }

    /** 尝试恢复 VPN 连接 */
    @Synchronized
    fun attemptRestore(context: Context) {
        val app = context.applicationContext

        // 1. 用户是否已主动关闭
        if (!AppPrefs.vpnDesired(app)) {
            Log.i(TAG, "attemptRestore aborted: vpnDesired is false (user stopped).")
            cancelRecovery(app)
            return
        }

        // 2. VPN 是否已在运行
        if (SmartProxyVpnService.isRunning.value) {
            Log.i(TAG, "attemptRestore aborted: SmartProxyVpnService is already running.")
            cancelRecovery(app)
            return
        }

        // 3. VPN 权限检查
        val needsVpnAuth = AppPrefs.serviceMode(app) == AppPrefs.MODE_VPN
        if (needsVpnAuth && VpnService.prepare(app) != null) {
            Log.w(TAG, "attemptRestore aborted: VPN authorization revoked by system.")
            cancelRecovery(app)
            return
        }

        // 4. 真实物理网络连通性检查
        val cm = app.getSystemService(ConnectivityManager::class.java)
        val activeNet = cm?.activeNetwork
        val caps = activeNet?.let { cm.getNetworkCapabilities(it) }
        val hasInternet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
        val hasPhysical = NetworkUtils.checkPhysicalNetworkAddresses(app).isAnyAvailable
        if (!hasInternet && !hasPhysical) {
            Log.i(TAG, "attemptRestore deferred: active network has no internet and no physical addresses yet.")
            return
        }

        Log.i(TAG, "Network verified available (activeNet=$activeNet, hasInternet=$hasInternet, hasPhysical=$hasPhysical). Restoring SmartProxyVpnService...")
        cancelRecovery(app)
        runCatching {
            SmartProxyVpnService.start(app)
        }.onFailure { e ->
            Log.e(TAG, "Failed to start SmartProxyVpnService during restore", e)
            // 若拉起失败，延迟重新等待，避免高频循环重试
            mainHandler.postDelayed({
                if (AppPrefs.vpnDesired(app) && !SmartProxyVpnService.isRunning.value) {
                    startRecovery(app)
                }
            }, 3000L)
        }
    }

    private fun registerNetworkCallback(context: Context) {
        if (networkCallback != null) return
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "[NetworkCallback] Network available: $network")
                mainHandler.post { attemptRestore(context) }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                val hasInternet = networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                val isDataBearing = networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                if (hasInternet || isDataBearing) {
                    mainHandler.post { attemptRestore(context) }
                }
            }
        }

        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
            Log.i(TAG, "Registered default NetworkCallback for network restore.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register default NetworkCallback, trying NetworkRequest", e)
            try {
                val req = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
                cm.registerNetworkCallback(req, callback)
                networkCallback = callback
            } catch (ex: Exception) {
                Log.e(TAG, "Failed to register NetworkCallback", ex)
            }
        }
    }

    private fun unregisterNetworkCallback(context: Context) {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        try {
            cm.unregisterNetworkCallback(cb)
            Log.i(TAG, "Unregistered NetworkCallback.")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister NetworkCallback: ${e.message}")
        }
    }

    private fun scheduleJob(context: Context) {
        val js = context.getSystemService(JobScheduler::class.java) ?: return
        try {
            val job = JobInfo.Builder(
                JOB_ID,
                ComponentName(context, NetworkRestoreJobService::class.java)
            )
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(false)
                .build()
            js.schedule(job)
            Log.i(TAG, "Scheduled NetworkRestoreJobService via JobScheduler (JOB_ID=$JOB_ID).")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to schedule JobScheduler job", e)
        }
    }

    private fun cancelJob(context: Context) {
        val js = context.getSystemService(JobScheduler::class.java) ?: return
        try {
            js.cancel(JOB_ID)
            Log.i(TAG, "Cancelled JobScheduler job (JOB_ID=$JOB_ID).")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to cancel JobScheduler job: ${e.message}")
        }
    }
}
