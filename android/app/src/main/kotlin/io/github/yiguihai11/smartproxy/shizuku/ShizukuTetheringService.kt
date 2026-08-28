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
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

/**
 * Privileged Shizuku process that controls Android tethering and owns its proxy upstream.
 *
 * Android's TestNetworkManager creates a real kernel TUN without root when called by the shell
 * UID. TetheringManager is then told to prefer test networks, so Android's Wi-Fi/USB DHCP,
 * forwarding, NAT and DNS machinery sends client traffic into that TUN.
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

    private var routingState = ROUTING_STATE_DISABLED
    private var routingDetail = ""
    private var routingProfileName = ""
    private var routingSession: RoutingSession? = null
    private var testNetworkHandle: TestNetworkHandle? = null
    private var upstreamMonitor: TetheringUpstreamMonitor? = null
    private var statusListener: ITetheringStatusListener? = null
    private var requestedTetheringTypes = 0
    private var wrongUpstreamWarningTypes = 0
    private var coreLease: ICoreTetheringLease? = null
    private var coreLifetime: LifetimeWatch? = null
    private var stagedAssetFingerprint = ""

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

    @Synchronized
    override fun setWifiHotspotEnabled(enabled: Boolean): Int {
        if (enabled && Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return RESULT_ROUTING_FAILED
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
        return result
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
        val warning = if (wrongUpstreamWarningTypes == 0) {
            RESULT_OK
        } else {
            RESULT_UNPROTECTED_UPSTREAM
        }
        wrongUpstreamWarningTypes = 0
        return warning
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
            )
        }
    }

    @Synchronized
    override fun setStatusListener(listener: ITetheringStatusListener?) {
        statusListener = listener
    }

    @Synchronized
    override fun startRouting(
        profileName: String,
        dnsServers: Array<out String>,
        ipv6Enabled: Boolean,
        syncToken: String,
        coreLease: ICoreTetheringLease,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return RESULT_ROUTING_FAILED
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
        } else {
            clearCoreLifetimeWatchLocked()
        }
        return result
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
            startRoutingEngineLocked(config, tun.fd)
            setRoutingActiveLocked(config)
        } catch (error: Throwable) {
            cleanupRouting()
            throw error
        }
    }

    @Synchronized
    override fun stopRouting(): Int {
        val result = shutdownRoutingLocked()
        notifyStatusChangedLocked()
        return result
    }

    private fun shutdownRoutingLocked(): Int {
        val tetheringResult = stopActiveTetheringLocked(clearDesired = true)
        if (tetheringResult != RESULT_OK) {
            setRoutingError("Unable to disable tethering safely before removing its protected route")
            return tetheringResult
        }
        routingSession = null
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

    @Synchronized
    override fun notifyCoreStopping(token: String): Int {
        val session = findRoutingSession(token) ?: return RESULT_INVALID_SESSION
        pauseForCoreRestartLocked(session, "Main core stopping")
        notifyStatusChangedLocked()
        return RESULT_OK
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

    @Synchronized
    override fun synchronizeRouting(
        token: String,
        profileName: String,
        dnsServers: Array<out String>,
        ipv6Enabled: Boolean,
        coreLease: ICoreTetheringLease,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return RESULT_ROUTING_FAILED
        val session = findRoutingSession(token) ?: return RESULT_INVALID_SESSION
        val result = runCatching {
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
        notifyStatusChangedLocked()
        return result
    }

    @Synchronized
    override fun notifyCoreStartFailed(token: String, detail: String): Int {
        val session = findRoutingSession(token) ?: return RESULT_INVALID_SESSION
        failRoutingSynchronizationLocked(
            IllegalStateException(detail.ifBlank { "SmartProxy failed to restart" }),
            session,
        )
        notifyStatusChangedLocked()
        return RESULT_OK
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
            synchronized(this) {
                if (coreLifetime?.binder !== binder) return@synchronized
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
        startRoutingEngineLocked(config, tun.fd)
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
        val safeToExit = synchronized(this) {
            shutdownRoutingLocked() == RESULT_OK
        }
        if (!safeToExit) {
            Log.e(TAG, "Refusing to destroy UserService while tethering is active")
            return
        }
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
            wrongUpstreamWarningTypes = when (result) {
                RESULT_OK -> wrongUpstreamWarningTypes and bit.inv()
                RESULT_UNPROTECTED_UPSTREAM -> wrongUpstreamWarningTypes or bit
                else -> wrongUpstreamWarningTypes
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

        if (!awaitProtectedUpstream(expectedUpstream)) {
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
        synchronized(this) {
            enforceProtectedUpstreamLocked()
            notifyStatusChangedLocked()
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

        wrongUpstreamWarningTypes = wrongUpstreamWarningTypes or affectedTypes
        Log.e(TAG, "Android moved tethering to unprotected upstream $actual; stopping downstreams")
        val result = stopActiveTetheringLocked(clearDesired = false, activeTypes = activeTypes)
        if (result != RESULT_OK) {
            Log.e(TAG, "Unable to stop downstreams: $result")
        }
    }

    private fun notifyStatusChangedLocked() {
        val listener = statusListener ?: return
        runCatching { listener.onStatusChanged() }
            .onFailure { statusListener = null }
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
            val configuredDns = dnsServers.map(InetAddress::getByName)
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

    private fun startRoutingEngineLocked(config: HotspotRoutingLaunchConfig, fd: Int) {
        val lease = checkNotNull(coreLease) { "Core lease is unavailable" }
        val stagedDir = stageNativeAssets(lease)
        val configFile = File(stagedDir, "config.json")
        // 引擎按 config 的 routing.chnroute_file / acl_file 加载文件;本进程以 shell UID
        // 运行,读不了主应用私有 cacheDir,必须把这两个路径重定向到已 stage 的同名文件,
        // 否则 engine.New → chnroute.Load 直接 permission denied,startRouting 报 -2。
        configFile.writeText(relocateRoutingFilesForShell(config.engineContent, stagedDir))

        try {
            smartproxy.mobile.Mobile.startRouter(configFile.absolutePath, fd.toLong(), true)
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

    private fun setRoutingActiveLocked(config: HotspotRoutingLaunchConfig) {
        routingProfileName = config.profileName
        routingState = ROUTING_STATE_ACTIVE
        updateRoutingDetailLocked()
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
        const val USER_SERVICE_VERSION = 20_260_828
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
