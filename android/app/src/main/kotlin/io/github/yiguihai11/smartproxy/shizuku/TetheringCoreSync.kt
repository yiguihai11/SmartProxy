package io.github.yiguihai11.smartproxy.shizuku

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.util.Log
import io.github.yiguihai11.smartproxy.AppPrefs
import io.github.yiguihai11.smartproxy.ConfigProvider
import io.github.yiguihai11.smartproxy.SmartProxyVpnService
import io.github.yiguihai11.smartproxy.TunConfig
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuProvider
import java.io.File
import java.io.Serializable
import java.util.UUID

data class HotspotRoutingSync(
    val token: String,
    val event: Int,
    val snapshot: HotspotRoutingSnapshot? = null,
    val detail: String = "",
) : Serializable {
    companion object {
        const val EVENT_CORE_STOPPING = 1
        const val EVENT_CORE_STARTED = 2
        const val EVENT_CORE_START_FAILED = 3
    }
}

/** Keeps the normal core's lifecycle and the privileged tethering core synchronized. */
object TetheringCoreSync {
    private const val TAG = "TetheringCoreSync"

    @Volatile
    private var snapshot = HotspotRoutingSnapshot()
    private val coreLease = CoreTetheringLease()
    private var watchingShizuku = false
    // Shizuku binder 死亡 → 恢复只对「仍在跑的主 core」生效;显式 stop / 换代(核心启停)必须让
    // 它失效。用不可变状态机表达,避免几个过程式布尔在 binder 事件与前台事件之间互相覆盖
    // (规格见 TetheringCoreSyncTest)。
    @Volatile
    private var recoveryState = TetheringRecoveryState()

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        val recovery = recoveryState.onBinderReceived()
        recoveryState = recovery.state
        if (recovery.action != TetheringRecoveryAction.RECOVER) return@OnBinderReceivedListener
        val currentSnapshot = snapshot.takeIf { it.running } ?: return@OnBinderReceivedListener
        Log.i(TAG, "Shizuku restarted; recovering protected tethering")
        send(SmartProxyVpnService.getAppContext() ?: return@OnBinderReceivedListener, HotspotRoutingSync.EVENT_CORE_STARTED, currentSnapshot)
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        recoveryState = recoveryState.onBinderDied()
    }

    fun onStarting() {
        clearCoreState()
        recoveryState = recoveryState.onCoreStopped()
    }

    fun onStarted(service: Service, coreConfig: String) {
        val currentSnapshot = createSnapshot(service)
        coreLease.attach(service, currentSnapshot, coreConfig)
        snapshot = currentSnapshot
        recoveryState = recoveryState.onCoreStarted()
        watchShizuku(service)
        send(service, HotspotRoutingSync.EVENT_CORE_STARTED, snapshot)
    }

    fun onStartFailed(service: Service, detail: String) {
        send(service, HotspotRoutingSync.EVENT_CORE_START_FAILED, detail = detail)
    }

    fun onStopping(service: Service) {
        send(service, HotspotRoutingSync.EVENT_CORE_STOPPING)
        clearCoreState()
        recoveryState = recoveryState.onCoreStopped()
    }

    fun clear() = clearCoreState()

    fun onAppForegrounded(context: Context) {
        val recovery = recoveryState.onAppForegrounded(Build.VERSION.SDK_INT)
        recoveryState = recovery.state
        if (recovery.action != TetheringRecoveryAction.REQUEST_BINDER) return

        // Android 14+ 会把 Shizuku 的 replacement-Binder 通知延迟到 app 进程回前台;回前台时主动
        // 请求它恢复受保护共享。请求失败清 coalesce 位允许下次回前台再试,但失败绝不上抛。
        runCoreSyncHook(
            block = { ShizukuProvider.requestBinderForNonProviderProcess(context) },
            onError = {
                recoveryState = recoveryState.onForegroundRequestFailed()
                Log.e(TAG, "Unable to request Shizuku recovery", it)
            },
        )
    }

    private fun clearCoreState() {
        snapshot = HotspotRoutingSnapshot()
        coreLease.clearEngineConfig()
    }

    private fun watchShizuku(context: Context) {
        if (watchingShizuku) return
        watchingShizuku = true
        Shizuku.addBinderReceivedListener(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        // 首次绑定也可能落在 Shizuku 服务已死的窗口:与 binder 死亡事件同路径标记待恢复,
        // 等恢复事件(或前台兜底)到达时若主 core 仍在跑则重推配置。
        if (!Shizuku.pingBinder()) {
            recoveryState = recoveryState.onBinderDied()
            Log.i(TAG, "Shizuku binder is dead on first watch; waiting for its recovery")
        }
        ShizukuProvider.requestBinderForNonProviderProcess(context)
    }

    fun getCurrentSnapshot(context: Context, coreRunning: Boolean): HotspotRoutingSnapshot {
        return if (coreRunning) snapshot else HotspotRoutingSnapshot()
    }

    fun getCoreLease(): ICoreTetheringLease? = coreLease.takeIf { snapshot.running }

    private fun createSnapshot(service: Service): HotspotRoutingSnapshot {
        val configJson = ConfigProvider.readConfig(service)
        val tun = TunConfig.parse(configJson)
        val dnsV4 = AppPrefs.dnsV4(service).ifBlank { AppPrefs.DEFAULT_DNS_V4 }
        val dnsV6 = AppPrefs.dnsV6(service).ifBlank { AppPrefs.DEFAULT_DNS_V6 }

        return HotspotRoutingSnapshot(
            running = true,
            vpnMode = service is SmartProxyVpnService,
            profileName = "SmartProxy",
            ipv6Enabled = tun.inet6 != null,
            vpnDnsServers = listOf(dnsV4, dnsV6),
            launchId = UUID.randomUUID().toString().replace("-", ""),
        )
    }

    private fun send(
        context: Context,
        event: Int,
        snapshot: HotspotRoutingSnapshot? = null,
        detail: String = "",
    ) {
        val token = AppPrefs.shizukuSyncToken(context).takeIf { it.isNotBlank() } ?: run {
            Log.i(TAG, "Tethering sync event $event skipped: no active Shizuku session")
            return
        }
        Log.i(TAG, "Sending tethering sync event $event")
        runCatching {
            context.sendBroadcast(
                Intent(context, ShizukuRoutingSyncReceiver::class.java)
                    .putExtra("content", HotspotRoutingSync(token, event, snapshot, detail))
                    .withCoreLease(coreLease.takeIf { snapshot != null }),
            )
        }.onFailure { Log.e(TAG, "Unable to send tethering synchronization", it) }
    }
}

/**
 * One recovery transition: an action for the caller plus the resulting state.
 *
 * 状态机规格见 TetheringCoreSyncTest:binder 死亡只对「仍在跑的主 core」标 RECOVER;显式停 core
 * 全量重置;Android 14+ 前台请求 binder 有 API 下界,且同一 pending 未完成前再去重(coalesced)。
 */
class TetheringRecoveryResult(
    val action: TetheringRecoveryAction,
    val state: TetheringRecoveryState,
)

enum class TetheringRecoveryAction { NONE, RECOVER, REQUEST_BINDER }

data class TetheringRecoveryState(
    val coreRunning: Boolean = false,
    val recoverWhenShizukuReturns: Boolean = false,
    val foregroundRequestPending: Boolean = false,
) {
    fun onCoreStarted(): TetheringRecoveryState = copy(coreRunning = true)

    fun onCoreStopped(): TetheringRecoveryState = TetheringRecoveryState()

    fun onBinderDied(): TetheringRecoveryState = copy(recoverWhenShizukuReturns = coreRunning)

    fun onBinderReceived(): TetheringRecoveryResult {
        val recover = coreRunning && recoverWhenShizukuReturns
        return if (recover) {
            TetheringRecoveryResult(
                TetheringRecoveryAction.RECOVER,
                copy(recoverWhenShizukuReturns = false, foregroundRequestPending = false),
            )
        } else {
            TetheringRecoveryResult(TetheringRecoveryAction.NONE, this)
        }
    }

    fun onAppForegrounded(sdkInt: Int): TetheringRecoveryResult {
        val shouldRequest = sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
            recoverWhenShizukuReturns && !foregroundRequestPending
        return if (shouldRequest) {
            TetheringRecoveryResult(
                TetheringRecoveryAction.REQUEST_BINDER,
                copy(foregroundRequestPending = true),
            )
        } else {
            TetheringRecoveryResult(TetheringRecoveryAction.NONE, this)
        }
    }

    fun onForegroundRequestFailed(): TetheringRecoveryState =
        copy(foregroundRequestPending = false)
}

/**
 * Runs a Shizuku-side sync hook so a failure can never leak into the primary core's start path
 * (spec: TetheringCoreSyncTest). True only when [block] completes; any failure is reported through
 * [onError] — an onError that itself throws is swallowed too.
 */
fun runCoreSyncHook(block: () -> Unit, onError: (Throwable) -> Unit): Boolean {
    return try {
        block()
        true
    } catch (error: Throwable) {
        try {
            onError(error)
        } catch (_: Throwable) {
            // 状态/日志回调自己挂了也不能再上抛:主 core 不该被共享功能的失败拖垮。
        }
        false
    }
}

internal class CoreTetheringLease : ICoreTetheringLease.Stub() {
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var tun: ParcelFileDescriptor? = null
    private var routingSnapshot: HotspotRoutingSnapshot? = null
    private var coreConfig: String? = null
    private var assetDirectory: File? = null
    // 引擎运行文件(chnroute.txt / acl.txt)在 cacheDir;Shizuku 用户服务以 shell UID 运行,
    // 读不了主应用私有路径,必须把 cacheDir 资源一并暴露给它 stage 到 /data/local/tmp。
    private var assetCacheDirectory: File? = null
    private var launchId: String? = null

    @Synchronized
    fun attach(context: Context, snapshot: HotspotRoutingSnapshot, coreConfig: String) {
        connectivityManager = context.getSystemService(ConnectivityManager::class.java)
        routingSnapshot = snapshot
        launchId = snapshot.launchId.takeIf { it.isNotBlank() }
        this.coreConfig = coreConfig
        assetDirectory = context.filesDir
        assetCacheDirectory = context.cacheDir
    }

    @Synchronized
    fun clearEngineConfig() {
        routingSnapshot = null
        launchId = null
        coreConfig = null
        assetDirectory = null
        assetCacheDirectory = null
    }

    /** 主 core 进程内校验:只有「当前这一代 core 启动」的配置才是活会话能用的。 */
    @Synchronized
    override fun isCurrentLaunch(launchId: String): Boolean = this.launchId == launchId

    @Synchronized
    override fun openEngineConfig(): ParcelFileDescriptor {
        val content = checkNotNull(coreConfig) { "Core configuration is unavailable" }
        val (readSide, writeSide) = ParcelFileDescriptor.createReliablePipe()
        Thread({
            runCatching {
                ParcelFileDescriptor.AutoCloseOutputStream(writeSide).use {
                    it.write(content.toByteArray(Charsets.UTF_8))
                }
            }.onFailure { Log.e("CoreTetheringLease", "Unable to stream tethering configuration", it) }
        }, "TetheringConfigWriter").apply {
            isDaemon = true
            start()
        }
        return readSide
    }

    @Synchronized
    override fun assetFingerprint(): String = assetFiles().joinToString("|") {
        "${it.name}:${it.length()}:${it.lastModified()}"
    }

    @Synchronized
    override fun listAssetFiles(): Array<String> = assetFiles().map { it.name }.toTypedArray()

    @Synchronized
    override fun openAssetFile(name: String): ParcelFileDescriptor {
        require(name.isNotBlank() && File(name).name == name) { "Invalid asset name" }
        val file = resolveAsset(name)
            ?: throw IllegalArgumentException("Core asset is unavailable: $name")
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    private fun resolveAsset(name: String): File? {
        listOfNotNull(assetDirectory, assetCacheDirectory).forEach { dir ->
            val file = File(dir, name)
            if (file.isFile) return file
        }
        return null
    }

    private fun assetFiles(): List<File> =
        listOfNotNull(assetDirectory, assetCacheDirectory)
            .flatMap { dir ->
                dir.listFiles()?.asSequence()
                    ?.filter { it.isFile && (it.name.endsWith(".txt") || it.name.endsWith(".json")) }
                    ?.toList()
                    .orEmpty()
            }
            .distinctBy { it.name }
            .sortedBy { it.name }

    @Synchronized
    override fun holdTestNetwork(tun: ParcelFileDescriptor) {
        releaseTestNetwork()
        val manager = checkNotNull(connectivityManager) { "Core network manager is unavailable" }
        val callback = ConnectivityManager.NetworkCallback()
        try {
            manager.requestNetwork(TetheringPlatformCompat.testNetworkRequest(), callback)
            networkCallback = callback
            this.tun = tun
        } catch (error: Throwable) {
            runCatching { tun.close() }
            throw error
        }
    }

    @Synchronized
    override fun releaseTestNetwork() {
        networkCallback?.let { callback ->
            runCatching { connectivityManager?.unregisterNetworkCallback(callback) }
        }
        networkCallback = null
        tun?.let { runCatching { it.close() } }
        tun = null
    }
}

private const val EXTRA_CORE_LEASE = "core_tethering_lease"

internal fun Intent.withCoreLease(lease: ICoreTetheringLease?): Intent = apply {
    lease ?: return@apply
    putExtra(EXTRA_CORE_LEASE, Bundle().apply { putBinder(EXTRA_CORE_LEASE, lease.asBinder()) })
}

internal fun Intent.coreTetheringLease(): ICoreTetheringLease? =
    getBundleExtra(EXTRA_CORE_LEASE)?.getBinder(EXTRA_CORE_LEASE)
        ?.let(ICoreTetheringLease.Stub::asInterface)
