package io.github.yiguihai11.smartproxy.shizuku

import android.annotation.SuppressLint
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TetheringManager
import android.os.Build
import androidx.annotation.ChecksSdkIntAtLeast
import java.io.File
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
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
        require(Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA)
        val callbackClass = Class.forName(TETHERING_EVENT_CALLBACK_CLASS)
        check(callbackClass.isInterface) { "Tethering event callback is not an interface" }
        val interfaceClass = Class.forName("android.net.TetheringInterface")
        val getType = interfaceClass.getMethod("getType")
        val getInterface = interfaceClass.getMethod("getInterface")
        val interfaceNames = AtomicReference<String?>(null)
        val interfaces = AtomicReference<List<ActiveTetheringInterface>?>(null)
        val interfacesReceived = CountDownLatch(1)
        val clients = AtomicReference<List<TetheredClientInfo>>(emptyList())
        val clientsReceived = AtomicBoolean(false)
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
                "onClientsChanged", "onTetheredClientsChanged" -> {
                    runCatching {
                        val collection = arguments?.firstOrNull() as? Collection<*>
                        if (collection != null) {
                            clients.set(extractTetheredClients(collection))
                            clientsReceived.set(true)
                        }
                    }
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
        return TetheringUpstreamMonitor(interfaceNames, interfaces, interfacesReceived, clients, clientsReceived) {
            runCatching { unregister.invoke(service, callback) }
            changeExecutor.shutdownNow()
        }
    }

    internal fun isProtectedUpstream(actual: String, expected: String): Boolean {
        if (expected.isBlank()) return false
        return actual.split(',').map(String::trim).filter(String::isNotEmpty)
            .let { it.size == 1 && it.first() == expected }
    }

    @SuppressLint("NewApi")
    fun startTethering(service: Any, type: Int, executor: Executor, timeoutSeconds: Long): Int {
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
        require(Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA)
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
        require(Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA)
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
    private val clients: AtomicReference<List<TetheredClientInfo>> = AtomicReference(emptyList()),
    private val clientsReceived: AtomicBoolean = AtomicBoolean(false),
    private val closeAction: () -> Unit,
) : AutoCloseable {
    val currentInterfaceNames: String? get() = interfaceNames.get()
    val currentInterfaces: List<ActiveTetheringInterface>? get() = interfaces.get()
    val currentClients: List<TetheredClientInfo> get() = clients.get()
    val hasClientsReceived: Boolean get() = clientsReceived.get()
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

internal data class TetheredClientInfo(
    val mac: String,
    val ip: String,
    val hostname: String?,
    val tetheringType: Int,
    val isRandomMac: Boolean = false,
    val assignedIps: List<String> = emptyList(),
)

internal fun isLocallyAdministeredMac(mac: String): Boolean {
    val clean = mac.replace(":", "").replace("-", "").trim()
    if (clean.length < 2) return false
    val firstByte = clean.substring(0, 2).toIntOrNull(16) ?: return false
    return (firstByte and 0x02) != 0
}

internal fun createTetheredClientInfo(
    mac: String,
    ip: String,
    hostname: String?,
    tetheringType: Int,
    assignedIps: List<String> = emptyList(),
): TetheredClientInfo {
    val cleanMac = mac.trim().lowercase()
    val isRandom = if (cleanMac.isNotEmpty()) isLocallyAdministeredMac(cleanMac) else false
    val normalizedIps = (listOf(ip) + assignedIps)
        .map { it.trim().substringBefore('%') }
        .filter { it.isNotBlank() }
        .distinct()
    val primaryIp = normalizedIps.firstOrNull { !it.contains(':') }
        ?: normalizedIps.firstOrNull { !it.startsWith("fe80:", ignoreCase = true) }
        ?: normalizedIps.firstOrNull()
        ?: ""
    return TetheredClientInfo(
        mac = cleanMac,
        ip = primaryIp,
        hostname = hostname?.trim()?.ifBlank { null },
        tetheringType = tetheringType,
        isRandomMac = isRandom,
        assignedIps = normalizedIps,
    )
}


internal fun extractTetheredClients(collection: Collection<*>): List<TetheredClientInfo> {
    val results = mutableListOf<TetheredClientInfo>()
    for (client in collection) {
        if (client == null) continue
        val clientClass = client.javaClass
        val mac = runCatching {
            clientClass.methods.firstOrNull { it.name == "getMacAddress" }?.invoke(client)?.toString()
        }.getOrNull().orEmpty()
        val type = runCatching {
            clientClass.methods.firstOrNull { it.name == "getTetheringType" }?.invoke(client) as? Int
        }.getOrNull() ?: -1

        val addresses = runCatching {
            clientClass.methods.firstOrNull { it.name == "getAddresses" }?.invoke(client) as? Collection<*>
        }.getOrNull()

        val allIps = mutableListOf<String>()
        var resolvedHostname: String? = null

        if (!addresses.isNullOrEmpty()) {
            for (addrInfo in addresses) {
                if (addrInfo == null) continue
                val addrClass = addrInfo.javaClass
                val linkAddress = runCatching {
                    addrClass.methods.firstOrNull { it.name == "getAddress" }?.invoke(addrInfo)
                }.getOrNull()
                val inetAddr = runCatching {
                    linkAddress?.javaClass?.methods?.firstOrNull { it.name == "getAddress" }?.invoke(linkAddress) as? InetAddress
                }.getOrNull()
                val hostname = runCatching {
                    addrClass.methods.firstOrNull { it.name == "getHostname" }?.invoke(addrInfo) as? String
                }.getOrNull()

                if (!hostname.isNullOrBlank() && resolvedHostname.isNullOrBlank()) {
                    resolvedHostname = hostname
                }

                if (inetAddr != null) {
                    val hostAddr = inetAddr.hostAddress?.substringBefore('%').orEmpty()
                    if (hostAddr.isNotEmpty()) {
                        allIps.add(hostAddr)
                    }
                }
            }
        }

        if (mac.isNotEmpty() || allIps.isNotEmpty()) {
            val primaryIp = allIps.firstOrNull { !it.contains(':') } ?: allIps.firstOrNull().orEmpty()
            results.add(
                createTetheredClientInfo(
                    mac = mac,
                    ip = primaryIp,
                    hostname = resolvedHostname,
                    tetheringType = type,
                    assignedIps = allIps,
                )
            )
        }
    }
    return results
}

internal fun parseNeighborLines(
    lines: Sequence<String>,
    downstreamInterfaces: Set<String> = emptySet(),
    upstreamInterfaces: Set<String> = emptySet(),
): List<TetheredClientInfo> {
    if (downstreamInterfaces.isEmpty()) return emptyList()
    return lines.mapNotNull { line ->
        val tokens = line.trim().split(Regex("\\s+"))
        if (tokens.size < 4) return@mapNotNull null
        val rawIp = tokens[0].substringBefore('%').trim()
        if (rawIp.isBlank()) return@mapNotNull null

        val devIdx = tokens.indexOfFirst { it.equals("dev", ignoreCase = true) || it.equals("Device:", ignoreCase = true) }
        val lladdrIdx = tokens.indexOfFirst { it.equals("lladdr", ignoreCase = true) }
        if (devIdx < 0 || devIdx + 1 >= tokens.size) return@mapNotNull null
        if (lladdrIdx < 0 || lladdrIdx + 1 >= tokens.size) return@mapNotNull null

        val iface = tokens[devIdx + 1].trim().removeSuffix(":")
        val mac = tokens[lladdrIdx + 1].trim().lowercase()

        if (mac == "00:00:00:00:00:00" || !mac.contains(':')) return@mapNotNull null
        if (upstreamInterfaces.contains(iface)) return@mapNotNull null
        if (!downstreamInterfaces.contains(iface)) return@mapNotNull null

        // 丢弃不可达或失败的邻居状态
        val lastToken = tokens.last().uppercase()
        if (lastToken == "FAILED" || lastToken == "INCOMPLETE") return@mapNotNull null

        val type = TetheringPlatformCompat.inferLegacyTetheringType(iface) ?: -1
        createTetheredClientInfo(
            mac = mac,
            ip = rawIp,
            hostname = null,
            tetheringType = type,
            assignedIps = listOf(rawIp),
        )
    }.toList()
}

internal fun parseArpLines(
    lines: Sequence<String>,
    downstreamInterfaces: Set<String> = emptySet(),
    upstreamInterfaces: Set<String> = emptySet(),
): List<TetheredClientInfo> {
    if (downstreamInterfaces.isEmpty()) return emptyList()
    return lines.drop(1).mapNotNull { line ->
        val tokens = line.trim().split(Regex("\\s+"))
        if (tokens.size >= 6 && tokens[3] != "00:00:00:00:00:00") {
            val ip = tokens[0]
            val mac = tokens[3]
            val iface = tokens[5]

            // 1. 如果属于上游出口接口(如手机连接的 Wi-Fi wlan0)，坚决丢弃，防止将上游 Wi-Fi 网关误判为热点客户端
            if (upstreamInterfaces.contains(iface)) return@mapNotNull null

            // 2. 必须严格属于激活的下游共享接口（如 ap0, swlan0, rndis0 等）
            if (!downstreamInterfaces.contains(iface)) return@mapNotNull null

            val type = TetheringPlatformCompat.inferLegacyTetheringType(iface) ?: -1
            createTetheredClientInfo(mac = mac, ip = ip, hostname = null, tetheringType = type, assignedIps = listOf(ip))
        } else null
    }.toList()
}

internal fun readArpClients(
    downstreamInterfaces: Set<String> = emptySet(),
    upstreamInterfaces: Set<String> = emptySet(),
): List<TetheredClientInfo> {
    if (downstreamInterfaces.isEmpty()) return emptyList()
    val file = File("/proc/net/arp")
    if (!file.canRead()) return emptyList()
    return runCatching {
        file.bufferedReader().useLines { lines ->
            parseArpLines(lines, downstreamInterfaces, upstreamInterfaces)
        }
    }.getOrDefault(emptyList())
}

internal fun readNeighborClients(
    downstreamInterfaces: Set<String> = emptySet(),
    upstreamInterfaces: Set<String> = emptySet(),
): List<TetheredClientInfo> {
    if (downstreamInterfaces.isEmpty()) return emptyList()

    val neighborClients = runCatching {
        val proc = ProcessBuilder("/system/bin/ip", "neigh", "show").redirectErrorStream(true).start()
        val lines = proc.inputStream.bufferedReader().useLines { it.toList() }
        proc.waitFor(1, TimeUnit.SECONDS)
        parseNeighborLines(lines.asSequence(), downstreamInterfaces, upstreamInterfaces)
    }.getOrNull().orEmpty()

    val arpClients = readArpClients(downstreamInterfaces, upstreamInterfaces)
    return mergeTetheredClients(neighborClients, arpClients)
}

internal fun mergeTetheredClients(
    systemClients: List<TetheredClientInfo>,
    arpClients: List<TetheredClientInfo>,
    clientsReceived: Boolean = false,
): List<TetheredClientInfo> {
    if (systemClients.isEmpty() && (clientsReceived || arpClients.isEmpty())) return emptyList()

    // 优先以 MAC 作为唯一物理设备标识聚合(L2 归一化)，无 MAC 时回退 IP
    fun clientKey(c: TetheredClientInfo): String =
        if (c.mac.isNotBlank()) c.mac.lowercase() else c.ip

    val map = LinkedHashMap<String, TetheredClientInfo>()

    fun mergeInto(existing: TetheredClientInfo?, incoming: TetheredClientInfo): TetheredClientInfo {
        if (existing == null) return incoming

        val isExistingIPv4 = existing.ip.isNotBlank() && !existing.ip.contains(':')
        val isIncomingIPv4 = incoming.ip.isNotBlank() && !incoming.ip.contains(':')

        // 若 existing 已具备权威 IPv4，且 incoming 是不同的 IPv4，则 incoming 是过期 stale IPv4，予以过滤
        val incomingIps = if (isExistingIPv4 && isIncomingIPv4 && existing.ip != incoming.ip) {
            (incoming.assignedIps + incoming.ip).filter { it.contains(':') }
        } else {
            incoming.assignedIps + incoming.ip
        }

        val allIps = (existing.assignedIps + incomingIps + listOf(existing.ip))
            .map { it.trim().substringBefore('%') }
            .filter { it.isNotBlank() }
            .distinct()

        val primaryIp = if (isExistingIPv4) existing.ip else (allIps.firstOrNull { !it.contains(':') } ?: existing.ip.ifBlank { incoming.ip })
        val mergedMac = existing.mac.ifBlank { incoming.mac }
        val mergedHost = existing.hostname ?: incoming.hostname
        val mergedType = if (existing.tetheringType >= 0) existing.tetheringType else incoming.tetheringType
        return createTetheredClientInfo(
            mac = mergedMac,
            ip = primaryIp,
            hostname = mergedHost,
            tetheringType = mergedType,
            assignedIps = allIps,
        )
    }

    val systemMacs = systemClients.map { it.mac.lowercase() }.filter { it.isNotBlank() }.toSet()
    val hasSystemClients = systemClients.isNotEmpty()

    for (sys in systemClients) {
        val key = clientKey(sys)
        if (key.isNotBlank()) {
            map[key] = mergeInto(map[key], sys)
        }
    }

    for (arp in arpClients) {
        val key = clientKey(arp)
        if (key.isBlank()) continue

        if (hasSystemClients) {
            val arpMac = arp.mac.lowercase()
            // 只有系统权威客户端已包含该 MAC 时，才允许使用 ARP 记录补充缺失信息(如 hostname 或 IP)
            // 若 ARP 记录中的 MAC 不在系统客户端中，属于已断开/切换 MAC 滞留在内核 ARP 缓存的离线设备，坚决丢弃！
            if (arpMac.isNotBlank() && systemMacs.contains(arpMac)) {
                map[arpMac] = mergeInto(map[arpMac], arp)
            }
        } else if (!clientsReceived) {
            // 只有未收到系统客户端回调的降级容灾模式下，才允许从 ARP 记录冒泡新设备
            map[key] = mergeInto(map[key], arp)
        }
    }
    return map.values.toList()
}

