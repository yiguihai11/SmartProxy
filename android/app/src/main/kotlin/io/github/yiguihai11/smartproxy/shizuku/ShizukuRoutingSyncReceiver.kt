package io.github.yiguihai11.smartproxy.shizuku

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Build
import android.os.DeadObjectException
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import io.github.yiguihai11.smartproxy.AppPrefs
import rikka.shizuku.Shizuku
import java.io.Serializable
import java.util.ArrayDeque
import java.util.concurrent.Executors

private const val TAG = "ShizukuSyncReceiver"

/** Relays app-core lifecycle updates to the shell-owned Shizuku UserService over Binder. */
class ShizukuRoutingSyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        intent.setExtrasClassLoader(HotspotRoutingSync::class.java.classLoader)
        val update = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra("content", HotspotRoutingSync::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("content") as? HotspotRoutingSync
        } ?: run {
            Log.w(TAG, "Ignoring malformed hotspot synchronization broadcast")
            return
        }
        // 慢同步(建测试网络/等 tethering 状态,可达 30s)交给进程级单例 dispatcher 的 worker
        // 线程异步跑,不用 goAsync:慢路径只在 EVENT_CORE_STARTED 触发,此刻 VPN 前台服务(FGS)
        // 活着、进程不会被回收;而 goAsync 只有 ~10s 预算,onReceive 里同步等 synchronizeRouting
        // 跑完才 finish 反而超预算触发广播 ANR。
        ShizukuRoutingSyncDispatcher.enqueue(context.applicationContext, update, intent.coreTetheringLease())
    }
}

/** Keeps updates ordered across the normal core's stop/start process boundary. */
private object ShizukuRoutingSyncDispatcher {
    private const val BIND_TIMEOUT_MS = 10_000L

    private data class PendingUpdate(
        val context: Context,
        val update: HotspotRoutingSync,
        val coreLease: ICoreTetheringLease?,
        val retryAfterDisconnect: Boolean = true,
    )

    private val mainHandler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val queue = ArrayDeque<PendingUpdate>()
    private var service: IShizukuTetheringService? = null
    private var binding = false
    private var inFlight = false
    private var bindGeneration = 0

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = IShizukuTetheringService.Stub.asInterface(binder)
            binding = false
            pump()
        }

        override fun onServiceDisconnected(name: ComponentName) {
            service = null
            binding = false
            failAll("Shizuku tethering service disconnected")
        }
    }

    fun enqueue(context: Context, update: HotspotRoutingSync, coreLease: ICoreTetheringLease?) {
        mainHandler.post {
            queue.addLast(PendingUpdate(context, update, coreLease))
            pump()
        }
    }

    private fun pump() {
        if (inFlight || queue.isEmpty()) return
        val currentService = service
        if (currentService == null) {
            bindIfNeeded()
            return
        }

        val pending = queue.removeFirst()
        inFlight = true
        worker.execute {
            val result = runCatching { forward(currentService, pending) }
            mainHandler.post {
                if (result.exceptionOrNull() is DeadObjectException && pending.retryAfterDisconnect) {
                    service = null
                    queue.addFirst(pending.copy(retryAfterDisconnect = false))
                } else {
                    result.onFailure { Log.e(TAG, "Unable to forward hotspot synchronization", it) }
                }
                inFlight = false
                pump()
            }
        }
    }

    private fun bindIfNeeded() {
        if (binding) return
        if (!Shizuku.pingBinder() ||
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED
        ) {
            failAll("Shizuku is unavailable or permission is missing")
            return
        }

        binding = true
        val generation = ++bindGeneration
        runCatching {
            Shizuku.bindUserService(ShizukuTetheringService.createUserServiceArgs(), connection)
        }.onFailure {
            binding = false
            failAll("Unable to bind Shizuku tethering service: ${it.message.orEmpty()}")
        }
        mainHandler.postDelayed({
            if (binding && generation == bindGeneration) {
                binding = false
                failAll("Timed out binding Shizuku tethering service")
            }
        }, BIND_TIMEOUT_MS)
    }

    private fun forward(service: IShizukuTetheringService, pending: PendingUpdate) {
        val update = pending.update
        val result = when (update.event) {
            HotspotRoutingSync.EVENT_CORE_STOPPING -> service.notifyCoreStopping(update.token)
            HotspotRoutingSync.EVENT_CORE_STARTED -> {
                val snapshot = requireNotNull(update.snapshot) { "Core-start update has no snapshot" }
                val coreLease = requireNotNull(pending.coreLease) {
                    "Core-start update has no protected-network lease"
                }
                val parameters = HotspotRoutingConfig.parametersFromSnapshot(snapshot)
                // 无活会话时服务端 synchronizeRouting 已用 fresh-自愈补一次完整启动(仅当本
                // UserService 进程没被显式停过),这里不再无条件 startRouting 复活——那会把
                // 「用户显式停掉的路由」在下一次主 core 换代时又拉起来。INVALID 留给外层按失效
                // 会话处理(清 token)。
                service.synchronizeRouting(
                    update.token,
                    parameters.profileName,
                    parameters.dnsServers.toTypedArray(),
                    parameters.ipv6Enabled,
                    parameters.launchId,
                    coreLease,
                )
            }
            HotspotRoutingSync.EVENT_CORE_START_FAILED -> {
                service.notifyCoreStartFailed(update.token, update.detail)
            }
            else -> error("Unknown hotspot synchronization event ${update.event}")
        }
        if (result == ShizukuTetheringService.RESULT_INVALID_SESSION) {
            clearSyncTokenIfCurrent(pending.context, update.token)
            Log.w(TAG, "Dropped stale Shizuku tethering synchronization session")
            return
        }
        check(result == ShizukuTetheringService.RESULT_OK) {
            "Shizuku tethering service rejected synchronization with result $result"
        }
        Log.i(TAG, "Forwarded hotspot sync event ${update.event}")
    }

    private fun clearSyncTokenIfCurrent(context: Context, token: String) {
        if (AppPrefs.shizukuSyncToken(context) == token) {
            AppPrefs.setShizukuSyncToken(context, "")
        }
    }

    private fun failAll(message: String) {
        if (queue.isNotEmpty()) Log.w(TAG, message)
        queue.clear()
        inFlight = false
    }
}
