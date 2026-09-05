package io.github.yiguihai11.smartproxy.shizuku

import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.Keep
import androidx.annotation.RequiresApi
import io.github.yiguihai11.smartproxy.BuildConfig
import org.json.JSONObject
import rikka.shizuku.Shizuku
import rikka.shizuku.SystemServiceHelper
import java.io.File
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Privileged Shizuku process that controls Android tethering and owns its proxy upstream.
 *
 * Android's TestNetworkManager creates a real kernel TUN without root when called by the shell
 * UID. TetheringManager is then told to prefer test networks, so Android's Wi-Fi/USB DHCP,
 * forwarding, NAT and DNS machinery sends client traffic into that TUN.
 *
 * 线程模型:所有改路由/热点状态的入口(startRouting/stopRouting/synchronizeRouting/
 * setWifiHotspotEnabled、notifyCoreStopping/notifyCoreStartFailed、onTetheringChanged、
 * binder 死亡回调)都在 [routingWorker]
 * 单线程上串行——Locked 后缀方法的「Locked」指 worker 独占状态,不是 synchronized(this)。
 * this 监视器只在 getStatus 快照和 statusListener 发布时短暂持有:建测试网络(~15s)、
 * 等 tethering 状态(每类型最多 ~10s)、上游重试 sleep(8s)这些长操作绝不能抱着状态锁,
 * 否则 UI 状态轮询和 fail-closed 回调会在锁队列里堵几十秒。
 */
@Keep
class ShizukuTetheringService(context: Context) : IShizukuTetheringService.Stub() {

    private val executor = Executor { command -> command.run() }
    private val appContext = context.applicationContext
    private val shellContext = ShellContextCompat.create(context)
    private val tetheringManager = if (usesPublicTetheringApi()) {
        TetheringApi36.getManager(shellContext)
    } else {
        requireNotNull(shellContext.getSystemService(TETHERING_SERVICE)) {
            "TetheringManager is unavailable"
        }
    }
    private val connectivityManager = requireNotNull(
        shellContext.getSystemService(ConnectivityManager::class.java)
    ) { "ConnectivityManager is unavailable" }

    // routingWorker 独占写;getStatus 在 binder 线程读,@Volatile 保证可见性。
    @Volatile private var routingState = ROUTING_STATE_DISABLED
    @Volatile private var routingDetail = ""
    @Volatile private var routingProfileName = ""
    @Volatile private var routingSession: RoutingSession? = null
    @Volatile private var testNetworkHandle: TestNetworkHandle? = null
    @Volatile private var upstreamMonitor: TetheringUpstreamMonitor? = null
    // statusListener 走 this 监视器发布(见 setStatusListener / notifyStatusChangedLocked)。
    private var statusListener: ITetheringStatusListener? = null
    // 仅 routingWorker 读写。
    private var requestedTetheringTypes = 0
    // getStatus 在 binder 线程 getAndSet 清零,worker 端 or 位标记,用原子整数免锁。
    private val wrongUpstreamWarningTypes = AtomicInteger(0)
    private val upstreamRejections = AtomicLong(0)
    @Volatile private var coreLease: ICoreTetheringLease? = null
    @Volatile private var coreLifetime: LifetimeWatch? = null
    private var stagedAssetFingerprint = ""

    private val routingWorker = Executors.newSingleThreadExecutor { r ->
        Thread(r, "ShizukuTetheringRouting").apply { isDaemon = true }.also { workerThread = it }
    }
    @Volatile private var workerThread: Thread? = null

    // 本 UserService 进程是否还没被「显式启动/停止」过。刚随 Shizuku 复活时 fresh=true;
    // startRouting 成功或任何显式停(stopRouting/destroy)后置 false。synchronizeRouting 撞到
    // 空会话时:fresh → 自动补一次完整启动(单跳自愈,覆盖 Shizuku 重启丢会话);
    // 非 fresh → RESULT_INVALID_SESSION,让 App 显式重建(用户已停就不该被旧事件复活)。
    @Volatile private var freshUserService = true
    // 引擎健康心跳:ACTIVE 期每 2s fixed-delay 探一次 Mobile.isRunning(),引擎意外死亡 →
    // ERROR + 通知 UI。只在 routingWorker 上启停与回调(见 setRoutingActiveLocked /
    // stopRoutingEngineLocked),绝不直接在心跳线程碰 Locked 状态。
    private var healthScheduler: ScheduledExecutorService? = null
    private var engineHealthCheck: ScheduledFuture<*>? = null

    /**
     * 把状态变更丢到 [routingWorker] 串行执行,binder 线程同步等结果(调用方本来就忍受同等
     * 耗时;getStatus 不再被长操作堵在锁外)。回调若已在 worker 线程上(直接 executor 重入)
     * 就地执行,防 submit().get() 自死锁。
     */
    private fun <T> runRoutingWork(block: () -> T): T {
        if (Thread.currentThread() === workerThread) return block()
        return routingWorker.submit(Callable { block() }).get()
    }

    private val routingActive: Boolean
        get() = routingState == ROUTING_STATE_ACTIVE

    private val testTun: ParcelFileDescriptor?
        get() = testNetworkHandle?.tun
    private val testInterfaceName: String?
        get() = testNetworkHandle?.interfaceName

    private data class RoutingSession(
        val token: String,
        var dnsServers: List<String>,
        var ipv6Enabled: Boolean,
        var desiredTetheringTypes: Int,
        var coreRestartPending: Boolean = false,
    )

    private data class LifetimeWatch(
        val binder: IBinder,
        val recipient: IBinder.DeathRecipient,
    ) {
        fun unlink() {
            runCatching { binder.unlinkToDeath(recipient, 0) }
        }
    }

    private class TestNetworkHandle(
        val manager: Any,
        private val interfaceLifetime: Any,
        val tun: ParcelFileDescriptor,
        val interfaceName: String,
        private val connectivityManager: ConnectivityManager,
        val networkLifetimeToken: IBinder,
    ) {
        private val published = CountDownLatch(1)
        var network: Network? = null
            private set

        val callback = object : ConnectivityManager.NetworkCallback() {
            private fun capture(network: Network, interfaceName: String?) {
                if (interfaceName == this@TestNetworkHandle.interfaceName) {
                    this@TestNetworkHandle.network = network
                    published.countDown()
                }
            }

            override fun onAvailable(network: Network) {
                capture(network, connectivityManager.getLinkProperties(network)?.interfaceName)
            }

            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                capture(network, properties.interfaceName)
            }
        }

        fun awaitPublished(): Boolean =
            published.await(TEST_NETWORK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        fun release() {
            runCatching { connectivityManager.unregisterNetworkCallback(callback) }
            network?.let { publishedNetwork ->
                runCatching {
                    manager.javaClass.getMethod("teardownTestNetwork", Network::class.java)
                        .invoke(manager, publishedNetwork)
                }.onFailure { Log.w(TAG, "Unable to tear down test network", it) }
            }
            runCatching { tun.close() }
        }
    }

    override fun setWifiHotspotEnabled(enabled: Boolean): Int = runRoutingWork {
        if (enabled && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return@runRoutingWork RESULT_ROUTING_FAILED
        }
        val result = setTetheringEnabled(TETHERING_TYPE_WIFI, enabled)
        if (result == RESULT_OK) {
            val bit = tetheringTypeBit(TETHERING_TYPE_WIFI)
            routingSession?.let { session ->
                session.desiredTetheringTypes = if (enabled) {
                    session.desiredTetheringTypes or bit
                } else {
                    session.desiredTetheringTypes and bit.inv()
                }
            }
        }
        notifyStatusChangedLocked()
        result
    }

    private fun getActiveTetheringTypes(): Int {
        return try {
            tetheringTypeMask(getTetheredInterfaces())
        } catch (error: Throwable) {
            Log.e(TAG, "Unable to read tethering state", error)
            TETHERING_TYPES_UNKNOWN
        }
    }

    private fun tetheringTypeMask(interfaces: List<ActiveTetheringInterface>): Int {
        return interfaces.fold(0) { mask, item -> mask or tetheringTypeBit(item.type) }
    }

    private fun ipv6TetheringTypeMask(interfaces: List<ActiveTetheringInterface>): Int {
        return interfaces.fold(0) { mask, item ->
            if (hasDelegatedIpv6Prefix(item.name)) mask or tetheringTypeBit(item.type) else mask
        }
    }

    private fun getTetheredInterfaces(): List<ActiveTetheringInterface> {
        return if (usesPublicTetheringApi()) {
            TetheringApi36.getTetheredInterfaces(
                tetheringManager,
                executor,
                CALLBACK_TIMEOUT_SECONDS,
            ) ?: error("Timed out while reading tethered interfaces")
        } else {
            TetheringPlatformCompat.getTetheredInterfaces(tetheringManager)
        }
    }

    private fun hasDelegatedIpv6Prefix(interfaceName: String): Boolean {
        val prefix = TETHERING_IPV6_PREFIX ?: return false
        val addresses = NetworkInterface.getByName(interfaceName)?.inetAddresses ?: return false
        return addresses.asSequence().any(prefix::contains)
    }

    private fun currentRoutingStateLocked(): Int {
        // getStatus 在 binder 线程跑:核心意外死亡的兜底改写可能与 worker 的状态迁移竞争,
        // ponytail: 瞬时 ERROR 快照无害,worker 下一次迁移/UI 下一轮轮询即覆盖,无需回队列。
        if (routingState == ROUTING_STATE_ACTIVE && !smartproxy.mobile.Mobile.isRunning()) {
            setRoutingError("SmartProxy core stopped unexpectedly")
        }
        return routingState
    }

    private fun currentRoutingDetailLocked(): String {
        // ERROR 状态必须透传 setRoutingError 存的根因,否则对话框只看到「路由错误」、
        // 具体失败被整段吞掉(曾导致排查只能靠猜)。
        if (routingState == ROUTING_STATE_ERROR) return routingDetail
        if (!routingActive && routingState != ROUTING_STATE_WAITING) return ""
        val upstreamInterface = upstreamMonitor?.currentInterfaceNames.orEmpty()
        return formatRoutingDetail(upstreamInterface)
    }

    private fun consumeWarningLocked(): Int {
        return if (wrongUpstreamWarningTypes.getAndSet(0) == 0) RESULT_OK else RESULT_UNPROTECTED_UPSTREAM
    }

    override fun getStatus(includeIpv6: Boolean): TetheringStatusSnapshot {
        val interfaces = runCatching { getTetheredInterfaces() }
            .onFailure { Log.e(TAG, "Unable to read tethering status", it) }
            .getOrNull()
        val activeTypes = interfaces?.let(::tetheringTypeMask) ?: TETHERING_TYPES_UNKNOWN
        val ipv6Types = if (includeIpv6 && interfaces != null) {
            runCatching { ipv6TetheringTypeMask(interfaces) }
                .onFailure { Log.e(TAG, "Unable to read tethered IPv6 state", it) }
                .getOrDefault(TETHERING_TYPES_UNKNOWN)
        } else {
            TETHERING_TYPES_UNKNOWN
        }
        return synchronized(this) {
            TetheringStatusSnapshot(
                routingState = currentRoutingStateLocked(),
                routingDetail = currentRoutingDetailLocked(),
                activeTetheringTypes = activeTypes,
                ipv6TetheringTypes = ipv6Types,
                warning = consumeWarningLocked(),
                // 「会话开关」的信号:routingSession 非空即认为路由会话存在(fail-closed 下引擎
                // ERROR 也会保留会话,让 UI 仍能关掉),跟 routingState 只反映瞬时引擎状态。
                hasRoutingSession = routingSession != null,
            )
        }
    }

    @Synchronized
    override fun setStatusListener(listener: ITetheringStatusListener?) {
        statusListener = listener
    }

    override fun startRouting(
        profileName: String,
        dnsServers: Array<out String>,
        ipv6Enabled: Boolean,
        syncToken: String,
        launchId: String,
        coreLease: ICoreTetheringLease,
    ): Int = runRoutingWork {
        startRoutingInternal(profileName, dnsServers, ipv6Enabled, syncToken, launchId, coreLease)
    }

    /**
     * 真正的路由启动(调用方保证在 routingWorker 上)。synchronizeRouting 的 fresh-自愈分支直接
     * 复用它,不套第二次 runRoutingWork(runRoutingWork 对 worker 线程就地执行,重入无害)。
     */
    private fun startRoutingInternal(
        profileName: String,
        dnsServers: Array<out String>,
        ipv6Enabled: Boolean,
        syncToken: String,
        launchId: String,
        coreLease: ICoreTetheringLease,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return RESULT_ROUTING_FAILED
        }
        // launchId 代次校验:停→启竞态里在途的旧 EVENT 带旧 launchId,isCurrentLaunch 判 false
        // 即静默丢弃——绝不把已换代(或已死)主 core 的配置应用到一个还活着的会话上。
        if (!coreLease.isCurrentLaunch(launchId)) {
            Log.i(TAG, "Ignoring tethering routing start for a replaced core launch")
            return RESULT_OK
        }
        if (syncToken.isBlank()) {
            routingDetail = "Tethering synchronization token is empty"
            return RESULT_INVALID_SESSION
        }
        val activeTypes = getActiveTetheringTypes()
        if (activeTypes < 0) {
            setRoutingError("Unable to determine active tethering before enabling its protected route")
            return RESULT_ROUTING_FAILED
        }
        val engineConfig = runCatching { readEngineConfig(coreLease) }.getOrElse {
            setRoutingError(rootCauseMessage(it))
            return RESULT_ROUTING_FAILED
        }
        val launchConfig = HotspotRoutingLaunchConfig(
            engineContent = engineConfig,
            profileName = profileName,
            dnsServers = dnsServers.toList(),
            ipv6Enabled = ipv6Enabled,
        )
        val newSession = RoutingSession(
            token = syncToken,
            dnsServers = launchConfig.dnsServers,
            ipv6Enabled = launchConfig.ipv6Enabled,
            desiredTetheringTypes = activeTypes,
        )

        try {
            watchCoreLifetimeLocked(coreLease)
        } catch (error: Throwable) {
            clearCoreLifetimeWatchLocked()
            setRoutingError(rootCauseMessage(error))
            return RESULT_ROUTING_FAILED
        }
        val result = startRoutingLocked(launchConfig, activeTypes)
        if (result == RESULT_OK) {
            routingSession = newSession
            freshUserService = false
        } else {
            clearCoreLifetimeWatchLocked()
        }
        result
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun startRoutingLocked(config: HotspotRoutingLaunchConfig, activeTypes: Int): Int {
        if (routingActive) {
            routingDetail = "Tethering routing is already active"
            return RESULT_ALREADY_ACTIVE
        }

        return try {
            if (testTun == null) {
                check(stopActiveTetheringLocked(clearDesired = false) == RESULT_OK) {
                    "Unable to stop tethering before replacing its protected route"
                }
                createRoutingLocked(config)
                val failedTypes = restoreTetheringTypesLocked(activeTypes)
                reportTetheringRestoreFailuresLocked(failedTypes)
            } else {
                val failedTypes = rebuildRoutingLocked(config, activeTypes)
                reportTetheringRestoreFailuresLocked(failedTypes)
            }
            RESULT_OK
        } catch (error: Throwable) {
            val detail = rootCauseMessage(error)
            Log.e(TAG, "Unable to start SmartProxy tethering routing: $detail", error)
            setRoutingError(detail)
            RESULT_ROUTING_FAILED
        }
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun createRoutingLocked(config: HotspotRoutingLaunchConfig) {
        cleanupRouting()
        routingState = ROUTING_STATE_STARTING
        routingDetail = "Creating Android test-network TUN"

        try {
            startUpstreamMonitorLocked()
            setPreferTestNetworks(true)
            createTestNetwork(config.dnsServers, config.ipv6Enabled)
            val tun = checkNotNull(testTun) { "Test TUN file descriptor is unavailable" }
            startRoutingEngineLocked(config, tun)
            setRoutingActiveLocked(config)
        } catch (error: Throwable) {
            cleanupRouting()
            throw error
        }
    }

    override fun stopRouting(): Int = runRoutingWork {
        val result = shutdownRoutingLocked()
        notifyStatusChangedLocked()
        result
    }

    private fun shutdownRoutingLocked(): Int {
        val tetheringResult = stopActiveTetheringLocked(clearDesired = true)
        if (tetheringResult != RESULT_OK) {
            setRoutingError("Unable to disable tethering safely before removing its protected route")
            return tetheringResult
        }
        routingSession = null
        // 显式停过一次就不再 fresh:此后的同步必须走显式 startRouting 重建,防旧事件复活。
        freshUserService = false
        routingState = ROUTING_STATE_STOPPING
        routingDetail = "Stopping SmartProxy tethering routing"
        cleanupRouting()
        clearCoreLifetimeWatchLocked()
        routingState = ROUTING_STATE_DISABLED
        routingDetail = ""
        return RESULT_OK
    }

    private fun stopActiveTetheringLocked(
        clearDesired: Boolean,
        activeTypes: Int = getActiveTetheringTypes(),
    ): Int {
        val knownTypes = requestedTetheringTypes or (routingSession?.desiredTetheringTypes ?: 0)
        if (activeTypes < 0 && knownTypes == 0) return RESULT_INTERNAL_ERROR
        val typesToStop = activeTypes.coerceAtLeast(0) or knownTypes
        if (clearDesired) routingSession?.desiredTetheringTypes = 0

        var result = RESULT_OK
        forEachTetheringType(typesToStop) { type, _ ->
            val stopResult = stopTetheringTypeLocked(type)
            if (stopResult != RESULT_OK && result == RESULT_OK) result = stopResult
        }
        return result
    }

    override fun notifyCoreStopping(token: String): Int = runRoutingWork {
        val session = findRoutingSession(token) ?: return@runRoutingWork RESULT_INVALID_SESSION
        pauseForCoreRestartLocked(session, "Main core stopping")
        notifyStatusChangedLocked()
        RESULT_OK
    }

    private fun pauseForCoreRestartLocked(session: RoutingSession, reason: String) {
        val activeTypes = getActiveTetheringTypes()
        if (activeTypes >= 0 && (routingActive || session.desiredTetheringTypes == 0)) {
            session.desiredTetheringTypes = activeTypes
        }
        stopRoutingEngineLocked()
        session.coreRestartPending = true
        if (testTun != null) {
            routingState = ROUTING_STATE_WAITING
            updateRoutingDetailLocked()
            Log.i(
                TAG,
                "$reason; tethering core stopped while preserving the protected test network " +
                    "and tethering types 0x${session.desiredTetheringTypes.toString(16)}",
            )
        } else {
            val tetheringResult = stopActiveTetheringLocked(clearDesired = false)
            setRoutingError("Protected test network is unavailable")
            Log.e(
                TAG,
                "$reason without a protected test network; disabled tethering with result $tetheringResult",
            )
        }
    }

    override fun synchronizeRouting(
        token: String,
        profileName: String,
        dnsServers: Array<out String>,
        ipv6Enabled: Boolean,
        launchId: String,
        coreLease: ICoreTetheringLease,
    ): Int = runRoutingWork {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return@runRoutingWork RESULT_ROUTING_FAILED
        }
        // 同 startRouting:代次不符的同步静默丢弃。
        if (!coreLease.isCurrentLaunch(launchId)) {
            Log.i(TAG, "Ignoring tethering synchronization for a replaced core launch")
            return@runRoutingWork RESULT_OK
        }
        val session = findRoutingSession(token)
        val result = if (session == null) {
            // 没有活会话:仅当本 UserService 进程 fresh(没被显式启/停过,典型是 Shizuku 重启
            // 复活后)才补一次完整启动单跳自愈;用户显式停过就保持停,INVALID 让 App 清 token。
            if (freshUserService) {
                Log.i(TAG, "Fresh UserService without a routing session; recreating it")
                startRoutingInternal(profileName, dnsServers, ipv6Enabled, token, launchId, coreLease)
            } else {
                Log.w(TAG, "Rejecting routing synchronization after an explicit stop")
                RESULT_INVALID_SESSION
            }
        } else {
            runCatching {
                val launchConfig = HotspotRoutingLaunchConfig(
                    engineContent = readEngineConfig(coreLease),
                    profileName = profileName,
                    dnsServers = dnsServers.toList(),
                    ipv6Enabled = ipv6Enabled,
                )
                watchCoreLifetimeLocked(coreLease)
                applyRoutingConfigLocked(launchConfig, session)
                RESULT_OK
            }.getOrElse {
                failRoutingSynchronizationLocked(it, session)
                RESULT_ROUTING_FAILED
            }
        }
        notifyStatusChangedLocked()
        result
    }

    override fun notifyCoreStartFailed(token: String, detail: String): Int = runRoutingWork {
        val session = findRoutingSession(token) ?: return@runRoutingWork RESULT_INVALID_SESSION
        failRoutingSynchronizationLocked(
            IllegalStateException(detail.ifBlank { "SmartProxy failed to restart" }),
            session,
        )
        notifyStatusChangedLocked()
        RESULT_OK
    }

    private fun findRoutingSession(token: String): RoutingSession? {
        val session = routingSession
        if (session == null || token.isBlank() || token != session.token) {
            Log.w(TAG, "Ignoring hotspot update for an inactive or invalid session")
            return null
        }
        return session
    }

    private fun watchCoreLifetimeLocked(coreLease: ICoreTetheringLease) {
        val binder = coreLease.asBinder()
        if (coreLifetime?.binder === binder && binder.isBinderAlive) return
        clearCoreLifetimeWatchLocked()
        val recipient = IBinder.DeathRecipient {
            runRoutingWork {
                if (coreLifetime?.binder !== binder) return@runRoutingWork
                coreLifetime = null
                this.coreLease = null
                routingSession?.let {
                    Log.w(TAG, "Main core process died without a stop notification")
                    pauseForCoreRestartLocked(it, "Main core process died")
                    notifyStatusChangedLocked()
                }
            }
        }
        this.coreLease = coreLease
        coreLifetime = LifetimeWatch(binder, recipient)
        try {
            binder.linkToDeath(recipient, 0)
            shareTestNetworkWithCoreLocked()
        } catch (error: Throwable) {
            this.coreLease = null
            coreLifetime = null
            throw IllegalStateException("Main core is no longer running", error)
        }
    }

    private fun shareTestNetworkWithCoreLocked() {
        val lease = coreLease ?: return
        val tun = testTun ?: return
        ParcelFileDescriptor.dup(tun.fileDescriptor).use {
            lease.holdTestNetwork(it)
        }
    }

    private fun clearCoreLifetimeWatchLocked() {
        runCatching { coreLease?.releaseTestNetwork() }
        coreLifetime?.unlink()
        coreLease = null
        coreLifetime = null
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun applyRoutingConfigLocked(
        launchConfig: HotspotRoutingLaunchConfig,
        session: RoutingSession,
    ) {
        Log.i(TAG, "Synchronizing hotspot routing to profile ${launchConfig.profileName.ifBlank { "<unnamed>" }}")
        val currentlyActive = getActiveTetheringTypes().coerceAtLeast(0)
        val restoreTypes = if (session.coreRestartPending) {
            session.desiredTetheringTypes or currentlyActive
        } else {
            currentlyActive
        }
        session.desiredTetheringTypes = restoreTypes

        val switchedInPlace = launchConfig.dnsServers == session.dnsServers &&
            launchConfig.ipv6Enabled == session.ipv6Enabled &&
            testTun != null &&
            (routingActive || routingState == ROUTING_STATE_WAITING) &&
            runCatching {
                restartRoutingEngineLocked(launchConfig)
            }.onFailure {
                Log.w(TAG, "In-place hotspot engine switch failed; rebuilding test network", it)
            }.isSuccess

        val failedTypes = if (switchedInPlace) {
            restoreTetheringTypesLocked(restoreTypes)
        } else {
            rebuildRoutingLocked(launchConfig, restoreTypes)
        }
        session.dnsServers = launchConfig.dnsServers
        session.ipv6Enabled = launchConfig.ipv6Enabled
        session.coreRestartPending = false
        reportTetheringRestoreFailuresLocked(failedTypes)
    }

    private fun restartRoutingEngineLocked(config: HotspotRoutingLaunchConfig) {
        routingState = ROUTING_STATE_STARTING
        routingDetail = "Switching tethering to new SmartProxy connection"
        stopRoutingEngineLocked()
        val tun = checkNotNull(testTun) { "Test TUN file descriptor is unavailable" }
        startRoutingEngineLocked(config, tun)
        setRoutingActiveLocked(config)
    }

    private fun restoreTetheringTypesLocked(types: Int): Int {
        val activeTypes = getActiveTetheringTypes()
        if (activeTypes < 0) return types

        var failedTypes = 0
        forEachTetheringType(types) { type, bit ->
            val result = setTetheringEnabled(type, true, activeTypes)
            if (result != RESULT_OK) failedTypes = failedTypes or bit
        }
        return failedTypes
    }

    private inline fun forEachTetheringType(types: Int, action: (type: Int, bit: Int) -> Unit) {
        var remaining = types
        while (remaining > 0) {
            val bit = Integer.lowestOneBit(remaining)
            action(Integer.numberOfTrailingZeros(bit), bit)
            remaining = remaining xor bit
        }
    }

    private fun failRoutingSynchronizationLocked(error: Throwable, session: RoutingSession) {
        val detail = rootCauseMessage(error)
        Log.e(TAG, "Unable to synchronize hotspot routing: $detail", error)
        stopRoutingEngineLocked()
        session.coreRestartPending = true
        if (testTun != null) {
            routingState = ROUTING_STATE_WAITING
            updateRoutingDetailLocked()
            Log.w(TAG, "Tethering remains fail-closed on ${testInterfaceName.orEmpty()}")
        } else {
            val tetheringResult = stopActiveTetheringLocked(clearDesired = false)
            if (tetheringResult == RESULT_OK) cleanupRouting()
            setRoutingError(detail)
        }
    }

    override fun destroy() {
        val safeToExit = runRoutingWork { shutdownRoutingLocked() == RESULT_OK }
        if (!safeToExit) {
            Log.e(TAG, "Refusing to destroy UserService while tethering is active")
            return
        }
        routingWorker.shutdown()
        System.exit(0)
    }

    private fun setTetheringEnabled(type: Int, enabled: Boolean, activeTypes: Int = getActiveTetheringTypes()): Int {
        val bit = tetheringTypeBit(type)
        if (bit == 0) return RESULT_INTERNAL_ERROR

        val result = if (!enabled) {
            val alreadyStopped = activeTypes >= 0 && activeTypes and bit == 0 &&
                requestedTetheringTypes and bit == 0
            if (alreadyStopped) RESULT_OK else stopTetheringTypeLocked(type)
        } else {
            startTetheringTypeLocked(type, activeTypes >= 0 && activeTypes and bit != 0)
        }
        if (enabled) {
            wrongUpstreamWarningTypes.updateAndGet { mask ->
                when (result) {
                    RESULT_OK -> mask and bit.inv()
                    RESULT_UNPROTECTED_UPSTREAM -> mask or bit
                    else -> mask
                }
            }
        }
        return result
    }

    private fun startTetheringTypeLocked(type: Int, alreadyEnabled: Boolean): Int {
        val firstResult = startTetheringTypeAttemptLocked(type, alreadyEnabled)
        if (firstResult != RESULT_UNPROTECTED_UPSTREAM) return firstResult

        Log.w(TAG, "Waiting before retrying protected tethering type $type")
        if (!sleepForUpstreamRetry()) return firstResult
        return startTetheringTypeAttemptLocked(type, alreadyEnabled = false)
    }

    private fun startTetheringTypeAttemptLocked(type: Int, alreadyEnabled: Boolean): Int {
        val rejection = upstreamRejections.get()
        val bit = tetheringTypeBit(type)
        val expectedUpstream = testInterfaceName
        if (!isRoutingReadyLocked() || testTun == null || expectedUpstream.isNullOrBlank()) {
            Log.e(TAG, "Refusing to start tethering before protected routing is ready")
            return RESULT_ROUTING_FAILED
        }

        requestedTetheringTypes = requestedTetheringTypes or bit
        val preferenceReady = runCatching { setPreferTestNetworks(true) }
            .onFailure { Log.e(TAG, "Unable to select protected tethering upstream", it) }
            .isSuccess
        if (!preferenceReady) return stopAfterFailedStartLocked(type, RESULT_INTERNAL_ERROR)

        var needsStart = !alreadyEnabled
        if (alreadyEnabled && !awaitProtectedUpstream(expectedUpstream)) {
            Log.w(TAG, "Resetting tethering type $type before protected startup")
            val stopResult = stopTetheringTypeLocked(type)
            if (stopResult != RESULT_OK) return stopAfterFailedStartLocked(type, stopResult)
            needsStart = true
        }

        if (needsStart) {
            val startResult = changeTetheringEnabled(type, true)
            if (startResult != RESULT_OK) return stopAfterFailedStartLocked(type, startResult)
            if (!awaitTetheringTypeState(type, enabled = true)) {
                return stopAfterFailedStartLocked(type, RESULT_INTERNAL_ERROR)
            }
        }

        if (!awaitProtectedUpstream(expectedUpstream) || rejection != upstreamRejections.get()) {
            val actualUpstream = readUpstreamInterface()
            Log.e(TAG, "Refusing tethering type $type on unprotected upstream ${actualUpstream.ifBlank { "<none>" }}")
            val result = if (actualUpstream.isBlank()) {
                RESULT_ROUTING_FAILED
            } else {
                RESULT_UNPROTECTED_UPSTREAM
            }
            return stopAfterFailedStartLocked(type, result)
        }

        requestedTetheringTypes = requestedTetheringTypes and bit.inv()
        return RESULT_OK
    }

    private fun sleepForUpstreamRetry(): Boolean = try {
        Thread.sleep(UPSTREAM_RETRY_DELAY_MILLIS)
        true
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    private fun readUpstreamInterface(): String = runCatching {
        upstreamMonitor?.currentInterfaceNames.orEmpty()
    }.getOrDefault("")

    private fun startUpstreamMonitorLocked() {
        if (upstreamMonitor != null) return
        upstreamMonitor = if (usesPublicTetheringApi()) {
            TetheringApi36.observeUpstream(
                tetheringManager,
                connectivityManager,
                executor,
                ::onTetheringChanged,
            )
        } else {
            TetheringPlatformCompat.observeUpstreamLegacy(
                tetheringManager,
                connectivityManager,
                executor,
                ::onTetheringChanged,
            )
        }
    }

    private fun onTetheringChanged() {
        stopUnprotectedDownstreams()
        notifyStatusChangedLocked()
    }

    private fun stopUnprotectedDownstreams() {
        val expected = testInterfaceName ?: return
        val actual = upstreamMonitor?.currentInterfaceNames ?: return
        if (actual.isBlank() || TetheringPlatformCompat.isProtectedUpstream(actual, expected)) return

        val activeTypes = upstreamMonitor?.currentInterfaces?.let(::tetheringTypeMask)
            ?: getActiveTetheringTypes()
        val affectedTypes = activeTypes.coerceAtLeast(0) or requestedTetheringTypes or
            (routingSession?.desiredTetheringTypes ?: 0)
        if (affectedTypes == 0) return

        upstreamRejections.incrementAndGet()
        wrongUpstreamWarningTypes.updateAndGet { it or affectedTypes }
        Log.e(TAG, "Android moved tethering to unprotected upstream $actual; stopping downstreams")
        forEachTetheringType(affectedTypes) { type, _ ->
            if (usesPublicTetheringApi()) {
                runCatching {
                    TetheringApi36.requestStopTethering(tetheringManager, type, executor) { result ->
                        if (result != RESULT_OK) Log.e(TAG, "Unable to stop downstream type $type: $result")
                    }
                }.onFailure {
                    Log.e(TAG, "Unable to request stop for downstream type $type", it)
                }
            } else {
                val result = runCatching { TetheringPlatformCompat.stopTethering(tetheringManager, type) }
                    .getOrDefault(RESULT_INTERNAL_ERROR)
                if (result != RESULT_OK) Log.e(TAG, "Unable to stop downstream type $type: $result")
            }
        }
    }

    private fun enforceProtectedUpstreamLocked() {
        val expected = testInterfaceName ?: return
        val actual = upstreamMonitor?.currentInterfaceNames ?: return
        if (actual.isBlank() || TetheringPlatformCompat.isProtectedUpstream(actual, expected)) return

        val activeTypes = getActiveTetheringTypes()
        val affectedTypes = activeTypes.coerceAtLeast(0) or requestedTetheringTypes or
            (routingSession?.desiredTetheringTypes ?: 0)
        if (affectedTypes == 0) return

        wrongUpstreamWarningTypes.updateAndGet { it or affectedTypes }
        Log.e(TAG, "Android moved tethering to unprotected upstream $actual; stopping downstreams")
        val result = stopActiveTetheringLocked(clearDesired = false, activeTypes = activeTypes)
        if (result != RESULT_OK) {
            Log.e(TAG, "Unable to stop downstreams: $result")
        }
    }

    private fun notifyStatusChangedLocked() {
        // listener 是对主 App 的 binder 回调,可能慢;只在取/清引用时短暂持有 this,
        // 回调本身在锁外跑(以前是抱着锁回调,App 端一卡就堵死全部路由操作)。
        val listener = synchronized(this) { statusListener } ?: return
        if (runCatching { listener.onStatusChanged() }.isFailure) {
            synchronized(this) { if (statusListener === listener) statusListener = null }
        }
    }

    private fun isRoutingReadyLocked(): Boolean {
        return routingState == ROUTING_STATE_ACTIVE && smartproxy.mobile.Mobile.isRunning()
    }

    private fun stopAfterFailedStartLocked(type: Int, startResult: Int): Int {
        val stopResult = stopTetheringTypeLocked(type)
        return if (stopResult == RESULT_OK) startResult else stopResult
    }

    private fun stopTetheringTypeLocked(type: Int): Int {
        val bit = tetheringTypeBit(type)
        val stopResult = changeTetheringEnabled(type, false)
        if (awaitTetheringTypeState(type, enabled = false)) {
            requestedTetheringTypes = requestedTetheringTypes and bit.inv()
            return RESULT_OK
        }
        Log.e(TAG, "Timed out waiting for tethering type $type to stop")
        return if (stopResult == RESULT_OK) RESULT_INTERNAL_ERROR else stopResult
    }

    private fun awaitTetheringTypeState(type: Int, enabled: Boolean): Boolean {
        val bit = tetheringTypeBit(type)
        return awaitResult(TETHERING_STATE_TIMEOUT_SECONDS) {
            val activeTypes = getActiveTetheringTypes()
            if (activeTypes >= 0 && (activeTypes and bit != 0) == enabled) true else null
        }
    }

    private fun awaitProtectedUpstream(expectedInterface: String) = awaitResult(
        UPSTREAM_SELECTION_TIMEOUT_SECONDS,
    ) {
        val actualInterface = readUpstreamInterface()
        when {
            TetheringPlatformCompat.isProtectedUpstream(actualInterface, expectedInterface) -> true
            actualInterface.isNotBlank() -> false
            else -> null
        }
    }

    private inline fun awaitResult(timeoutSeconds: Long, poll: () -> Boolean?): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (true) {
            poll()?.let { return it }
            if (System.nanoTime() >= deadline) return false
            try {
                Thread.sleep(TETHERING_STATE_POLL_MILLIS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            }
        }
    }

    private fun changeTetheringEnabled(type: Int, enabled: Boolean): Int {
        return runCatching {
            when {
                enabled -> TetheringPlatformCompat.startTethering(
                    tetheringManager,
                    type,
                    executor,
                    CALLBACK_TIMEOUT_SECONDS,
                )
                usesPublicTetheringApi() ->
                    TetheringApi36.stopTethering(
                        tetheringManager,
                        type,
                        executor,
                        CALLBACK_TIMEOUT_SECONDS,
                    )
                else -> TetheringPlatformCompat.stopTethering(
                    tetheringManager,
                    type,
                )
            }
        }.onFailure {
            Log.e(TAG, "Unable to set tethering type $type enabled=$enabled", it)
        }.getOrDefault(RESULT_INTERNAL_ERROR)
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun rebuildRoutingLocked(config: HotspotRoutingLaunchConfig, restoreTypes: Int): Int {
        val stopResult = stopActiveTetheringLocked(clearDesired = false)
        check(stopResult == RESULT_OK) {
            "Unable to pause tethering before rebuilding protected route"
        }
        createRoutingLocked(config)
        return restoreTetheringTypesLocked(restoreTypes)
    }

    private fun reportTetheringRestoreFailuresLocked(failedTypes: Int) {
        if (failedTypes == 0) return
        routingDetail += " · Unable to restore tethering types 0x${failedTypes.toString(16)}"
        Log.w(TAG, routingDetail)
    }

    @RequiresApi(Build.VERSION_CODES.Q)
    private fun createTestNetwork(dnsServers: List<String>, ipv6Enabled: Boolean) {
        val manager = checkNotNull(shellContext.getSystemService(TEST_NETWORK_SERVICE)) {
            "TestNetworkManager is unavailable"
        }
        val addresses = buildList {
            add(createLinkAddress(HotspotRoutingConfig.SHIZUKU_TUN_ADDR_V4))
            if (ipv6Enabled) add(createLinkAddress(HotspotRoutingConfig.SHIZUKU_TUN_ADDR_V6))
        }
        val handle = createTestNetworkHandle(manager, addresses)
        testNetworkHandle = handle

        shareTestNetworkWithCoreLocked()
        connectivityManager.requestNetwork(TetheringPlatformCompat.testNetworkRequest(), handle.callback)

        val properties = LinkProperties().apply {
            interfaceName = handle.interfaceName
            setLinkAddresses(addresses)
            // 通告 DNS 跟随 IPv6 开关:主 VPN 没开 v6 时,testtun 没有 v6 链路,若仍把
            // AppPrefs 的 v6 DNS(默认 2400:3200::1)通告给连接设备,设备会优先探测这个
            // 不可达的 v6 resolver。与主 core 的 addDnsServer(按族加)行为对齐:关 v6 即
            // 滤掉 v6 DNS;开 v6 且配置无 v6 DNS 时,才由下方 ULA hint 补内部地址来通告 /64。
            val configuredDns = dnsServers.map(InetAddress::getByName).filter { dns ->
                ipv6Enabled || dns !is Inet6Address
            }
            setDnsServers(buildList {
                addAll(configuredDns)
                if (ipv6Enabled && configuredDns.none { it is Inet6Address }) {
                    add(InetAddress.getByName(HotspotRoutingConfig.SHIZUKU_TUN_DNS_HINT_V6))
                }
            })
        }
        val setupMethod = manager.javaClass.getMethod(
            "setupTestNetwork",
            LinkProperties::class.java,
            java.lang.Boolean.TYPE,
            IBinder::class.java,
        )
        setupMethod.invoke(manager, properties, true, handle.networkLifetimeToken)

        check(handle.awaitPublished()) { "Android did not publish the test-network TUN" }
    }

    private fun createTestNetworkHandle(
        manager: Any,
        addresses: List<LinkAddress>,
    ): TestNetworkHandle {
        val addressArray = addresses.toTypedArray()
        val testInterface = manager.javaClass
            .getMethod("createTunInterface", addressArray.javaClass)
            .invoke(manager, addressArray as Any)
            ?: error("TestNetworkManager returned no TUN interface")
        val tun = testInterface.javaClass.getMethod("getFileDescriptor")
            .invoke(testInterface) as ParcelFileDescriptor

        return try {
            val interfaceName = testInterface.javaClass.getMethod("getInterfaceName")
                .invoke(testInterface) as String
            TestNetworkHandle(
                manager = manager,
                interfaceLifetime = testInterface,
                tun = tun,
                interfaceName = interfaceName,
                connectivityManager = connectivityManager,
                networkLifetimeToken = checkNotNull(SystemServiceHelper.getSystemService(Context.CONNECTIVITY_SERVICE)) {
                    "Android connectivity service has no Binder"
                },
            )
        } catch (error: Throwable) {
            runCatching { tun.close() }
            throw error
        }
    }

    private fun setPreferTestNetworks(prefer: Boolean) {
        tetheringManager.javaClass
            .getMethod("setPreferTestNetworks", java.lang.Boolean.TYPE)
            .invoke(tetheringManager, prefer)
    }

    private fun startRoutingEngineLocked(config: HotspotRoutingLaunchConfig, tunPfd: ParcelFileDescriptor) {
        val lease = checkNotNull(coreLease) { "Core lease is unavailable" }
        val stagedDir = stageNativeAssets(lease)
        val configFile = File(stagedDir, "config.json")
        // 引擎按 config 的 routing.chnroute_file / acl_file 加载文件;本进程以 shell UID
        // 运行,读不了主应用私有 cacheDir,必须把这两个路径重定向到已 stage 的同名文件,
        // 否则 engine.New → chnroute.Load 直接 permission denied,startRouting 报 -2。
        configFile.writeText(relocateRoutingFilesForShell(config.engineContent, stagedDir))

        // Go sing-tun 用 os.NewFile 直接包传入的 fd 号(不 dup),StopRouter 关栈时 close 它。
        // 若把 TestNetworkManager 原 PFD 的 fd 号直接给 Go,cleanupRouting 的 release() 再
        // tun.close() 就是 fdsan double-close(fd 75 实测 SIGABRT,关路由即闪退,整个特权
        // 进程死给你看)。dup 出独立 fd 交 Go 独占并 detachFd 转移 fdsan 所有权;原 PFD 始终
        // 归 TestNetworkHandle.release() 关闭。失败路径 Go 的 startRouter 自己关 goFd
        // (bridge closeFdOnErr),Kotlin 绝不碰——与 VpnService.establishVpn 同款归属。
        val goFd = tunPfd.dup().detachFd()
        try {
            smartproxy.mobile.Mobile.startRouter(configFile.absolutePath, goFd.toLong(), true)
            check(smartproxy.mobile.Mobile.isRunning()) { "SmartProxy tethering core did not start" }
        } catch (error: Throwable) {
            stopRoutingEngineLocked()
            throw error
        }
    }

    private fun stageNativeAssets(coreLease: ICoreTetheringLease): String {
        val directory = File(SHELL_RUNTIME_DIR, ASSET_DIRECTORY_NAME).apply { mkdirs() }
        check(directory.isDirectory) { "Unable to create tethering asset directory" }
        val names = coreLease.listAssetFiles().toList()
        val fingerprint = coreLease.assetFingerprint()
        if (fingerprint == stagedAssetFingerprint && names.all { File(directory, it).isFile }) {
            return directory.absolutePath
        }

        directory.listFiles()?.filter { it.isFile && it.name !in names && it.name != "config.json" }?.forEach { it.delete() }
        names.forEach { name ->
            val target = File(directory, name)
            val temporary = File(directory, ".$name.tmp")
            runCatching {
                ParcelFileDescriptor.AutoCloseInputStream(coreLease.openAssetFile(name)).use { input ->
                    temporary.outputStream().use { output -> input.copyTo(output) }
                }
                check(!target.exists() || target.delete()) { "Unable to replace asset $name" }
                check(temporary.renameTo(target)) { "Unable to install asset $name" }
            }.onFailure {
                temporary.delete()
                throw it
            }
        }
        stagedAssetFingerprint = fingerprint
        return directory.absolutePath
    }

    private fun relocateRoutingFilesForShell(engineContent: String, stagedDir: String): String {
        val json = runCatching { JSONObject(engineContent) }.getOrElse { return engineContent }
        val routing = json.optJSONObject("routing") ?: JSONObject().also { json.put("routing", it) }
        routing.put("chnroute_file", File(stagedDir, "chnroute.txt").absolutePath)
        routing.put("acl_file", File(stagedDir, "acl.txt").absolutePath)
        return json.toString()
    }

    private fun readEngineConfig(coreLease: ICoreTetheringLease): String {
        val descriptor = coreLease.openEngineConfig()
        return ParcelFileDescriptor.AutoCloseInputStream(descriptor)
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
            .also { require(it.isNotBlank()) { "Tethering engine configuration is empty" } }
    }

    private fun startEngineHealthCheck() {
        if (engineHealthCheck != null) return
        val scheduler = healthScheduler ?: Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "ShizukuCoreHealth").apply { isDaemon = true }
        }.also { healthScheduler = it }
        // fixed-delay 2s:任务在心跳线程起头,状态迁移与上报经 runRoutingWork 回 worker 串行
        // (runRoutingWork 对 worker 就地执行,重入无害),心跳线程绝不直接碰 Locked 状态。
        engineHealthCheck = scheduler.scheduleWithFixedDelay({
            runRoutingWork {
                if (routingState != ROUTING_STATE_ACTIVE) return@runRoutingWork
                if (!smartproxy.mobile.Mobile.isRunning()) {
                    stopEngineHealthCheck()
                    setRoutingError("SmartProxy core stopped unexpectedly")
                    notifyStatusChangedLocked()
                }
            }
        }, 2L, 2L, TimeUnit.SECONDS)
    }

    private fun stopEngineHealthCheck() {
        engineHealthCheck?.cancel(false)
        engineHealthCheck = null
    }

    private fun setRoutingActiveLocked(config: HotspotRoutingLaunchConfig) {
        routingProfileName = config.profileName
        routingState = ROUTING_STATE_ACTIVE
        updateRoutingDetailLocked()
        startEngineHealthCheck()
    }

    private fun setRoutingError(detail: String) {
        routingState = ROUTING_STATE_ERROR
        routingDetail = detail
        Log.e(TAG, detail)
    }

    private fun updateRoutingDetailLocked() {
        routingDetail = formatRoutingDetail(testInterfaceName.orEmpty())
    }

    private fun formatRoutingDetail(interfaceName: String): String {
        return listOf(interfaceName, routingProfileName)
            .filter(String::isNotBlank)
            .joinToString(" · ")
    }

    private fun stopRoutingEngineLocked() {
        stopEngineHealthCheck()
        runCatching { smartproxy.mobile.Mobile.stopRouter() }
            .onFailure { Log.w(TAG, "Unable to stop tethering router", it) }
    }

    private fun cleanupRouting() {
        stopRoutingEngineLocked()
        runCatching { coreLease?.releaseTestNetwork() }

        upstreamMonitor?.close()
        upstreamMonitor = null
        testNetworkHandle?.release()
        testNetworkHandle = null
        routingProfileName = ""

        runCatching { setPreferTestNetworks(false) }
            .onFailure { Log.w(TAG, "Unable to restore tethering upstream preference", it) }
    }

    private fun createLinkAddress(cidr: String): LinkAddress {
        return LinkAddress::class.java.getDeclaredConstructor(String::class.java).run {
            isAccessible = true
            newInstance(cidr)
        }
    }

    private fun rootCauseMessage(error: Throwable): String {
        var current = error
        while (current.cause != null && current.cause !== current) current = current.cause!!
        return current.message?.takeIf { it.isNotBlank() } ?: current.javaClass.simpleName
    }

    companion object {
        private const val TAG = "ShizukuTethering"
        // 跟随构建号变化(app/build.gradle.kts 的 shizukuServiceVersion:CI run number /
        // 构建时间戳),不是写死的日期。Shizuku 只在 version 变化时重启常驻用户服务进程;
        // 固定值会让升级 APK 后仍复用旧进程,其 classloader 指向已删除的旧 APK,native 库
        // libgojni.so 路径失效 → 启动共享引擎时 dlopen failed / -2。每次打包都变 → 重装即重启守护。
        val USER_SERVICE_VERSION: Int = BuildConfig.ShizukuServiceVersion
        private const val TETHERING_SERVICE = "tethering"
        private const val TEST_NETWORK_SERVICE = "test_network"
        private val TETHERING_IPV6_PREFIX = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            HotspotRoutingConfig.SHIZUKU_TUN_ADDR_V6.let { cidr ->
                IpPrefix(
                    InetAddress.getByName(cidr.substringBefore('/')),
                    cidr.substringAfter('/').toInt(),
                )
            }
        } else null
        private const val SHELL_RUNTIME_DIR = "/data/local/tmp"
        private const val ASSET_DIRECTORY_NAME = "smartproxy-tethering-assets"
        private const val CALLBACK_TIMEOUT_SECONDS = 10L
        private const val TEST_NETWORK_TIMEOUT_SECONDS = 15L
        private const val TETHERING_STATE_TIMEOUT_SECONDS = 10L
        private const val UPSTREAM_SELECTION_TIMEOUT_SECONDS = 5L
        private const val UPSTREAM_RETRY_DELAY_MILLIS = 8_000L
        private const val TETHERING_STATE_POLL_MILLIS = 200L

        const val TETHERING_TYPE_WIFI = 0
        const val TETHERING_TYPE_USB = 1
        const val TETHERING_TYPES_UNKNOWN = -1

        const val ROUTING_STATE_DISABLED = 0
        const val ROUTING_STATE_STARTING = 1
        const val ROUTING_STATE_ACTIVE = 2
        const val ROUTING_STATE_STOPPING = 4
        const val ROUTING_STATE_ERROR = 5
        const val ROUTING_STATE_WAITING = 6

        const val RESULT_OK = 0
        const val RESULT_INTERNAL_ERROR = -1
        const val RESULT_ROUTING_FAILED = -2
        const val RESULT_INVALID_SESSION = -4
        const val RESULT_ALREADY_ACTIVE = -5
        const val RESULT_UNPROTECTED_UPSTREAM = -6

        internal fun createUserServiceArgs() = Shizuku.UserServiceArgs(
            ComponentName(BuildConfig.APPLICATION_ID, ShizukuTetheringService::class.java.name)
        )
            .daemon(true)
            .processNameSuffix("shizuku_tethering")
            .debuggable(BuildConfig.DEBUG)
            .version(USER_SERVICE_VERSION)
    }
}
