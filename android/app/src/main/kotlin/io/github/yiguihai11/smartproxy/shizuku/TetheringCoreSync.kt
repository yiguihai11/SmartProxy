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
    @Volatile
    private var recoverWhenShizukuReturns = false
    @Volatile
    private var foregroundRecoveryRequested = false

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        if (!recoverWhenShizukuReturns) return@OnBinderReceivedListener
        recoverWhenShizukuReturns = false
        foregroundRecoveryRequested = false
        val currentSnapshot = snapshot.takeIf { it.running } ?: return@OnBinderReceivedListener
        Log.i(TAG, "Shizuku restarted; recovering protected tethering")
        send(SmartProxyVpnService.getAppContext() ?: return@OnBinderReceivedListener, HotspotRoutingSync.EVENT_CORE_STARTED, currentSnapshot)
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        recoverWhenShizukuReturns = snapshot.running
        foregroundRecoveryRequested = false
    }

    fun onStarting() {
        clearCoreState()
    }

    fun onStarted(service: Service, coreConfig: String) {
        val currentSnapshot = createSnapshot(service)
        coreLease.attach(service, currentSnapshot, coreConfig)
        snapshot = currentSnapshot
        watchShizuku(service)
        send(service, HotspotRoutingSync.EVENT_CORE_STARTED, snapshot)
    }

    fun onStartFailed(service: Service, detail: String) {
        send(service, HotspotRoutingSync.EVENT_CORE_START_FAILED, detail = detail)
    }

    fun onStopping(service: Service) {
        send(service, HotspotRoutingSync.EVENT_CORE_STOPPING)
        clearCoreState()
    }

    fun clear() = clearCoreState()

    fun onAppForegrounded(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            !recoverWhenShizukuReturns || foregroundRecoveryRequested
        ) return

        foregroundRecoveryRequested = true
        runCatching { ShizukuProvider.requestBinderForNonProviderProcess(context) }
            .onFailure {
                foregroundRecoveryRequested = false
                Log.e(TAG, "Unable to request Shizuku recovery", it)
            }
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
        recoverWhenShizukuReturns = !Shizuku.pingBinder()
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

internal class CoreTetheringLease : ICoreTetheringLease.Stub() {
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var tun: ParcelFileDescriptor? = null
    private var routingSnapshot: HotspotRoutingSnapshot? = null
    private var coreConfig: String? = null
    private var assetDirectory: File? = null

    @Synchronized
    fun attach(context: Context, snapshot: HotspotRoutingSnapshot, coreConfig: String) {
        connectivityManager = context.getSystemService(ConnectivityManager::class.java)
        routingSnapshot = snapshot
        this.coreConfig = coreConfig
        assetDirectory = context.filesDir
    }

    @Synchronized
    fun clearEngineConfig() {
        routingSnapshot = null
        coreConfig = null
        assetDirectory = null
    }

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
        val file = File(checkNotNull(assetDirectory) { "Core asset directory is unavailable" }, name)
        require(file.isFile) { "Core asset is unavailable: $name" }
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    private fun assetFiles(): List<File> = assetDirectory?.listFiles()
        ?.filter { it.isFile && (it.name.endsWith(".txt") || it.name.endsWith(".json")) }
        ?.sortedBy { it.name }
        .orEmpty()

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
