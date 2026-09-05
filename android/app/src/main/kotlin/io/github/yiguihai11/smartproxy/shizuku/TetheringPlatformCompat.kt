package io.github.yiguihai11.smartproxy.shizuku

import android.annotation.SuppressLint
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TetheringManager
import android.os.Build
import androidx.annotation.ChecksSdkIntAtLeast
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** TetheringManager compatibility for Android 13 through 15. */
internal object TetheringPlatformCompat {

    @SuppressLint("WrongConstant")
    fun testNetworkRequest(): NetworkRequest = NetworkRequest.Builder()
        .addTransportType(TRANSPORT_TEST)
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
        .build()

    fun observeUpstreamLegacy(
        service: Any,
        connectivityManager: ConnectivityManager,
        executor: Executor,
        onChanged: () -> Unit,
    ): TetheringUpstreamMonitor {
        require(Build.VERSION.SDK_INT in Build.VERSION_CODES.TIRAMISU until Build.VERSION_CODES.BAKLAVA)
        val callbackClass = Class.forName(TETHERING_EVENT_CALLBACK_CLASS)
        check(callbackClass.isInterface) { "Tethering event callback is not an interface" }
        val interfaceClass = Class.forName("android.net.TetheringInterface")
        val getType = interfaceClass.getMethod("getType")
        val getInterface = interfaceClass.getMethod("getInterface")
        val interfaceNames = AtomicReference<String?>(null)
        val interfaces = AtomicReference<List<ActiveTetheringInterface>?>(null)
        val interfacesReceived = CountDownLatch(1)
        val changeExecutor = newTetheringChangeExecutor()
        val callback = Proxy.newProxyInstance(
            TetheringPlatformCompat::class.java.classLoader,
            arrayOf(callbackClass),
        ) { proxy, method, arguments ->
            when (method.name) {
                "onUpstreamChanged" -> {
                    val network = arguments?.firstOrNull() as? Network
                    interfaceNames.set(upstreamInterfaceNames(connectivityManager, network))
                    runCatching { changeExecutor.execute(onChanged) }
                    null
                }
                "onTetheredInterfacesChanged" -> {
                    interfaces.set(runCatching {
                        val downstreams = arguments?.firstOrNull() as? Set<*>
                            ?: error("Tethering callback did not supply interface identities")
                        downstreams.map { downstream ->
                            ActiveTetheringInterface(
                                getType.invoke(downstream) as Int,
                                getInterface.invoke(downstream) as String,
                            )
                        }
                    }.getOrNull())
                    interfacesReceived.countDown()
                    runCatching { changeExecutor.execute(onChanged) }
                    null
                }
                "equals" -> proxy === arguments?.firstOrNull()
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "SmartProxy tethering upstream callback"
                else -> null
            }
        }
        val register = service.javaClass.methods.firstOrNull {
            it.name == "registerTetheringEventCallback" &&
                it.parameterTypes.contentEquals(arrayOf(Executor::class.java, callbackClass))
        } ?: error("TetheringManager.registerTetheringEventCallback is unavailable")
        val unregister = service.javaClass.methods.firstOrNull {
            it.name == "unregisterTetheringEventCallback" &&
                it.parameterTypes.contentEquals(arrayOf(callbackClass))
        } ?: error("TetheringManager.unregisterTetheringEventCallback is unavailable")
        try {
            register.invoke(service, executor, callback)
        } catch (error: Throwable) {
            changeExecutor.shutdownNow()
            throw error
        }
        return TetheringUpstreamMonitor(interfaceNames, interfaces, interfacesReceived) {
            runCatching { unregister.invoke(service, callback) }
            changeExecutor.shutdownNow()
        }
    }

    internal fun isProtectedUpstream(actual: String, expected: String): Boolean {
        if (expected.isBlank()) return false
        return actual.split(',').map(String::trim).filter(String::isNotEmpty)
            .let { it.isNotEmpty() && it.all { name -> name == expected } }
    }

    @SuppressLint("NewApi")
    fun startTethering(service: Any, type: Int, executor: Executor, timeoutSeconds: Long): Int {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        val manager = service as TetheringManager
        var result = ShizukuTetheringService.RESULT_INTERNAL_ERROR
        val callbackReceived = CountDownLatch(1)
        manager.startTethering(
            TetheringManager.TetheringRequest.Builder(type).build(),
            executor,
            object : TetheringManager.StartTetheringCallback {
                override fun onTetheringStarted() {
                    result = ShizukuTetheringService.RESULT_OK
                    callbackReceived.countDown()
                }
                override fun onTetheringFailed(error: Int) {
                    result = error
                    callbackReceived.countDown()
                }
            },
        )
        return if (callbackReceived.await(timeoutSeconds, TimeUnit.SECONDS)) result
        else ShizukuTetheringService.RESULT_INTERNAL_ERROR
    }

    fun getTetheredInterfaces(service: Any): List<ActiveTetheringInterface> {
        require(Build.VERSION.SDK_INT in Build.VERSION_CODES.TIRAMISU until Build.VERSION_CODES.BAKLAVA)
        val monitor = service
        val interfaces = invokeStringList(monitor, "getTetheredIfaces")
            ?: error("TetheringManager.getTetheredIfaces is unavailable")
        val regexesByType = mapOf(
            ShizukuTetheringService.TETHERING_TYPE_WIFI to compileRegexes(invokeStringList(monitor, "getTetherableWifiRegexs")),
            ShizukuTetheringService.TETHERING_TYPE_USB to compileRegexes(invokeStringList(monitor, "getTetherableUsbRegexs")),
            LEGACY_TETHERING_TYPE_BLUETOOTH to compileRegexes(invokeStringList(monitor, "getTetherableBluetoothRegexs")),
        )
        return interfaces.map { interfaceName ->
            ActiveTetheringInterface(requireLegacyTetheringType(interfaceName, regexesByType), interfaceName)
        }
    }

    fun stopTethering(service: Any, type: Int): Int {
        require(Build.VERSION.SDK_INT in Build.VERSION_CODES.TIRAMISU until Build.VERSION_CODES.BAKLAVA)
        val method = service.javaClass.methods.firstOrNull {
            it.name == "stopTethering" && it.parameterTypes.contentEquals(arrayOf(Integer.TYPE))
        } ?: error("TetheringManager.stopTethering(int) is unavailable")
        method.invoke(service, type)
        return ShizukuTetheringService.RESULT_OK
    }

    internal fun inferLegacyTetheringType(interfaceName: String): Int? {
        val name = interfaceName.lowercase()
        return when {
            name.startsWith("wlan") || name.startsWith("ap") || name.startsWith("softap") -> ShizukuTetheringService.TETHERING_TYPE_WIFI
            name.startsWith("usb") || name.startsWith("rndis") -> ShizukuTetheringService.TETHERING_TYPE_USB
            name.startsWith("bt-pan") || name.startsWith("bnep") -> LEGACY_TETHERING_TYPE_BLUETOOTH
            name.startsWith("p2p") -> LEGACY_TETHERING_TYPE_WIFI_P2P
            name.startsWith("ncm") -> LEGACY_TETHERING_TYPE_NCM
            name.startsWith("eth") -> LEGACY_TETHERING_TYPE_ETHERNET
            else -> null
        }
    }

    internal fun requireLegacyTetheringType(interfaceName: String, regexesByType: Map<Int, List<Regex>>): Int =
        inferLegacyTetheringType(interfaceName)
            ?: regexesByType.entries.firstOrNull { (_, regexes) -> regexes.any { it.matches(interfaceName) } }?.key
            ?: error("Unknown active tethering interface: $interfaceName")

    private fun invokeStringList(service: Any, methodName: String): List<String>? {
        val method = service.javaClass.methods.firstOrNull { it.name == methodName && it.parameterCount == 0 } ?: return null
        return when (val result = method.invoke(service)) {
            null -> null
            is Array<*> -> result.filterIsInstance<String>()
            is Collection<*> -> result.filterIsInstance<String>()
            else -> null
        }
    }

    private fun compileRegexes(patterns: List<String>?): List<Regex> = patterns.orEmpty().mapNotNull { runCatching { Regex(it) }.getOrNull() }

    private const val TETHERING_EVENT_CALLBACK_CLASS = "android.net.TetheringManager\$TetheringEventCallback"
    private const val TRANSPORT_TEST = 7
    private const val LEGACY_TETHERING_TYPE_BLUETOOTH = 2
    private const val LEGACY_TETHERING_TYPE_WIFI_P2P = 3
    private const val LEGACY_TETHERING_TYPE_NCM = 4
    private const val LEGACY_TETHERING_TYPE_ETHERNET = 5
}

internal class TetheringUpstreamMonitor(
    private val interfaceNames: AtomicReference<String?>,
    private val interfaces: AtomicReference<List<ActiveTetheringInterface>?>,
    private val interfacesReceived: CountDownLatch,
    private val closeAction: () -> Unit,
) : AutoCloseable {
    val currentInterfaceNames: String? get() = interfaceNames.get()
    val currentInterfaces: List<ActiveTetheringInterface>? get() = interfaces.get()
    fun awaitInterfaces(timeoutSeconds: Long): List<ActiveTetheringInterface> {
        check(interfacesReceived.await(timeoutSeconds, TimeUnit.SECONDS)) { "Timed out reading tethered interfaces" }
        return checkNotNull(currentInterfaces) { "Unable to identify active tethering interfaces" }
    }
    override fun close() = closeAction()
}

@ChecksSdkIntAtLeast(api = Build.VERSION_CODES.BAKLAVA)
internal fun usesPublicTetheringApi(): Boolean = isPublicTetheringApiLevel(Build.VERSION.SDK_INT)
internal fun isPublicTetheringApiLevel(sdkInt: Int): Boolean = sdkInt >= Build.VERSION_CODES.BAKLAVA
internal fun upstreamInterfaceNames(connectivityManager: ConnectivityManager, network: Network?): String {
    val properties = network?.let(connectivityManager::getLinkProperties) ?: return ""
    return properties.interfaceName.orEmpty()
}
internal fun newTetheringChangeExecutor(): ExecutorService = Executors.newSingleThreadExecutor { command ->
    Thread(command, "TetheringUpstreamMonitor").apply { isDaemon = true }
}
internal data class ActiveTetheringInterface(val type: Int, val name: String)
internal fun tetheringTypeBit(type: Int): Int = if (type in 0..30) 1 shl type else 0
