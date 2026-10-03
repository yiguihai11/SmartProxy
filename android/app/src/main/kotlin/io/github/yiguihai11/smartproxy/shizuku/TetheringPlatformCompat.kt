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
        return TetheringUpstreamMonitor(interfaceNames, interfaces, interfacesReceived, clients) {
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
    private val closeAction: () -> Unit,
) : AutoCloseable {
    val currentInterfaceNames: String? get() = interfaceNames.get()
    val currentInterfaces: List<ActiveTetheringInterface>? get() = interfaces.get()
    val currentClients: List<TetheredClientInfo> get() = clients.get()
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
    val vendor: String? = null,
    val isRandomMac: Boolean = false,
    val osGuess: String? = null,
    val assignedIps: List<String> = emptyList(),
)

internal fun isLocallyAdministeredMac(mac: String): Boolean {
    val clean = mac.replace(":", "").replace("-", "").trim()
    if (clean.length < 2) return false
    val firstByte = clean.substring(0, 2).toIntOrNull(16) ?: return false
    return (firstByte and 0x02) != 0
}

internal fun lookupMacVendor(mac: String): String? {
    val clean = mac.replace(":", "").replace("-", "").uppercase().trim()
    if (clean.length < 6) return null
    val oui = clean.substring(0, 6)
    return MAC_OUI_TABLE[oui]
}

internal fun inferDeviceOs(hostname: String?, vendor: String?, isRandomMac: Boolean = false): String {
    val host = hostname?.lowercase()?.trim().orEmpty()
    return when {
        host.contains("iphone") -> "iOS (iPhone)"
        host.contains("ipad") -> "iPadOS (iPad)"
        host.contains("macbook") || host.contains("imac") || host.contains("mac-") || host.contains("macmini") || host.contains("macpro") -> "macOS"
        host.contains("desktop-") || host.contains("laptop-") || host.contains("windows") || host.contains("msft") -> "Windows PC"
        host.contains("galaxy") || host.contains("samsung") -> "Android (Samsung)"
        host.contains("xiaomi") || host.contains("redmi") || host.contains("poco") -> "Android (Xiaomi)"
        host.contains("huawei") || host.contains("honor") -> "Android / HarmonyOS"
        host.contains("oppo") || host.contains("oneplus") || host.contains("realme") -> "Android (OPPO/OnePlus)"
        host.contains("vivo") || host.contains("iqoo") -> "Android (vivo)"
        host.contains("pixel") -> "Android (Google Pixel)"
        host.contains("android") -> "Android"
        host.contains("ubuntu") || host.contains("debian") || host.contains("arch") || host.contains("fedora") || host.contains("kali") -> "Linux"
        host.contains("esp_") || host.contains("tasmota") || host.contains("wled") || host.contains("sonoff") -> "IoT (ESP)"
        host.contains("switch") || host.contains("nintendo") -> "Nintendo Switch"
        host.contains("playstation") || host.contains("ps5") || host.contains("ps4") -> "PlayStation"
        host.contains("xbox") -> "Xbox"
        host.contains("kindle") -> "Amazon Kindle"
        vendor != null -> when (vendor) {
            "Apple" -> "Apple (iOS / macOS)"
            "Microsoft" -> "Windows PC"
            "Intel" -> "PC (Windows / Linux)"
            "Xiaomi" -> "Android (Xiaomi)"
            "Huawei" -> "Android / HarmonyOS"
            "Samsung" -> "Android (Samsung)"
            "Google" -> "Android (Google Pixel)"
            "OPPO" -> "Android (OPPO)"
            "Vivo" -> "Android (vivo)"
            "Espressif" -> "IoT (ESP)"
            "Raspberry Pi" -> "Linux (Raspberry Pi)"
            "Nintendo" -> "Nintendo Switch"
            "Sony" -> "PlayStation / Sony"
            else -> vendor
        }
        isRandomMac -> "局域网设备 (私有/随机 MAC)"
        else -> "未知设备"
    }
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
    val vendor = if (cleanMac.isNotEmpty() && !isRandom) lookupMacVendor(cleanMac) else null
    val os = inferDeviceOs(hostname, vendor, isRandom)
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
        vendor = vendor,
        isRandomMac = isRandom,
        osGuess = os,
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
): List<TetheredClientInfo> {
    if (systemClients.isEmpty() && arpClients.isEmpty()) return emptyList()

    // 优先以 MAC 作为唯一物理设备标识聚合(L2 归一化)，无 MAC 时回退 IP
    fun clientKey(c: TetheredClientInfo): String =
        if (c.mac.isNotBlank()) c.mac.lowercase() else c.ip

    val map = LinkedHashMap<String, TetheredClientInfo>()

    fun mergeInto(existing: TetheredClientInfo?, incoming: TetheredClientInfo): TetheredClientInfo {
        if (existing == null) return incoming
        val allIps = (existing.assignedIps + incoming.assignedIps + listOf(existing.ip, incoming.ip))
            .map { it.trim().substringBefore('%') }
            .filter { it.isNotBlank() }
            .distinct()
        val mergedIp = allIps.firstOrNull { !it.contains(':') }
            ?: allIps.firstOrNull()
            ?: existing.ip.ifBlank { incoming.ip }
        val mergedMac = existing.mac.ifBlank { incoming.mac }
        val mergedHost = existing.hostname ?: incoming.hostname
        val mergedType = if (existing.tetheringType >= 0) existing.tetheringType else incoming.tetheringType
        return createTetheredClientInfo(
            mac = mergedMac,
            ip = mergedIp,
            hostname = mergedHost,
            tetheringType = mergedType,
            assignedIps = allIps,
        )
    }

    for (sys in systemClients) {
        val key = clientKey(sys)
        if (key.isNotBlank()) {
            map[key] = mergeInto(map[key], sys)
        }
    }
    for (arp in arpClients) {
        val key = clientKey(arp)
        if (key.isBlank()) continue
        map[key] = mergeInto(map[key], arp)
    }
    return map.values.toList()
}

internal val MAC_OUI_TABLE: Map<String, String> = mapOf(
    // Apple
    "0017F2" to "Apple", "001CB3" to "Apple", "002500" to "Apple", "0026BB" to "Apple",
    "040CCE" to "Apple", "041552" to "Apple", "080007" to "Apple", "109397" to "Apple",
    "14109F" to "Apple", "147DC5" to "Apple", "1499E2" to "Apple", "18AF61" to "Apple",
    "28CFE9" to "Apple", "3408BC" to "Apple", "38CADA" to "Apple", "3C0754" to "Apple",
    "40A6D9" to "Apple", "442A60" to "Apple", "48D705" to "Apple", "4C3275" to "Apple",
    "50BC96" to "Apple", "542696" to "Apple", "5855CA" to "Apple", "600308" to "Apple",
    "6476BA" to "Apple", "68967B" to "Apple", "6C4008" to "Apple", "701124" to "Apple",
    "784F43" to "Apple", "7C6D62" to "Apple", "80E650" to "Apple", "843835" to "Apple",
    "88665A" to "Apple", "8C8590" to "Apple", "90FD61" to "Apple", "94E96A" to "Apple",
    "9801A7" to "Apple", "9C207B" to "Apple", "A0999B" to "Apple", "A4C361" to "Apple",
    "A85B78" to "Apple", "ACBC32" to "Apple", "B03495" to "Apple", "B418D1" to "Apple",
    "B8098A" to "Apple", "BC52B7" to "Apple", "C0847A" to "Apple", "C42C03" to "Apple",
    "C869CD" to "Apple", "CC088D" to "Apple", "D0034B" to "Apple", "D4619D" to "Apple",
    "D81C79" to "Apple", "DCA904" to "Apple", "E06678" to "Apple", "E4CE8F" to "Apple",
    "E8802E" to "Apple", "EC3586" to "Apple", "F01898" to "Apple", "F40F24" to "Apple",
    "F83880" to "Apple", "FCFC48" to "Apple",
    // Huawei
    "001E10" to "Huawei", "00259E" to "Huawei", "00464B" to "Huawei", "0425C5" to "Huawei",
    "04F938" to "Huawei", "0819A6" to "Huawei", "0C37DC" to "Huawei", "104780" to "Huawei",
    "14A51A" to "Huawei", "1C8E5C" to "Huawei", "20F41B" to "Huawei", "24DF6A" to "Huawei",
    "283152" to "Huawei", "2C9D1E" to "Huawei", "30D17E" to "Huawei", "342EB6" to "Huawei",
    "384C90" to "Huawei", "3CF808" to "Huawei", "404D7F" to "Huawei", "446E2E" to "Huawei",
    "4846FB" to "Huawei", "4C5499" to "Huawei", "548998" to "Huawei", "582AF7" to "Huawei",
    "5C546D" to "Huawei", "60DE44" to "Huawei", "68A0F6" to "Huawei", "708A09" to "Huawei",
    "786A89" to "Huawei", "80B686" to "Huawei", "8828B3" to "Huawei", "90473C" to "Huawei",
    "94772B" to "Huawei", "9C710D" to "Huawei", "A47174" to "Huawei", "ACE342" to "Huawei",
    "B41513" to "Huawei", "BC7670" to "Huawei", "C07009" to "Huawei", "C85195" to "Huawei",
    "D46E0E" to "Huawei", "DCD2FC" to "Huawei", "E0191D" to "Huawei", "E468A3" to "Huawei",
    "EC233D" to "Huawei", "F4559C" to "Huawei", "F8E71E" to "Huawei", "FCE33C" to "Huawei",
    // Xiaomi
    "00EC0A" to "Xiaomi", "04CF8C" to "Xiaomi", "14EBB6" to "Xiaomi", "18F0E4" to "Xiaomi",
    "286C07" to "Xiaomi", "34800D" to "Xiaomi", "38A4ED" to "Xiaomi", "3CBD3E" to "Xiaomi",
    "50642B" to "Xiaomi", "508F4C" to "Xiaomi", "584498" to "Xiaomi", "640980" to "Xiaomi",
    "64CC2E" to "Xiaomi", "742344" to "Xiaomi", "7802F8" to "Xiaomi", "7C49EB" to "Xiaomi",
    "88C397" to "Xiaomi", "8CDE52" to "Xiaomi", "98FAE3" to "Xiaomi", "A475B9" to "Xiaomi",
    "ACC1EE" to "Xiaomi", "B0E235" to "Xiaomi", "BC6A29" to "Xiaomi", "C40BCB" to "Xiaomi",
    "D4970B" to "Xiaomi", "E4AAEC" to "Xiaomi", "F4F5DB" to "Xiaomi", "FCE557" to "Xiaomi",
    // Samsung
    "0007AB" to "Samsung", "001632" to "Samsung", "001D25" to "Samsung", "04180F" to "Samsung",
    "0808C2" to "Samsung", "0C1420" to "Samsung", "1449E0" to "Samsung", "1C5A3E" to "Samsung",
    "244B81" to "Samsung", "28BAB0" to "Samsung", "30074D" to "Samsung", "3423BA" to "Samsung",
    "380B40" to "Samsung", "4480EB" to "Samsung", "4C6371" to "Samsung", "5492BE" to "Samsung",
    "5CE8EB" to "Samsung", "64B5C6" to "Samsung", "78471D" to "Samsung", "842519" to "Samsung",
    "90187C" to "Samsung", "9463D1" to "Samsung", "A0821F" to "Samsung", "AC5F3E" to "Samsung",
    "B479A7" to "Samsung", "BC8556" to "Samsung", "C0BDD1" to "Samsung", "CC07AB" to "Samsung",
    "D022BE" to "Samsung", "E458B8" to "Samsung", "F47B5E" to "Samsung",
    // Intel
    "0002B3" to "Intel", "000347" to "Intel", "000423" to "Intel", "000E0C" to "Intel",
    "001302" to "Intel", "001500" to "Intel", "001676" to "Intel", "001B21" to "Intel",
    "001E67" to "Intel", "00216A" to "Intel", "0024D7" to "Intel", "081196" to "Intel",
    "3413E8" to "Intel", "3CF011" to "Intel", "4851B7" to "Intel", "5C879C" to "Intel",
    "6805CA" to "Intel", "701CE7" to "Intel", "7C214A" to "Intel", "8086F2" to "Intel",
    "84FDD1" to "Intel", "A434F1" to "Intel", "AC7289" to "Intel", "B49691" to "Intel",
    "C85B76" to "Intel", "DC5360" to "Intel", "F8633F" to "Intel",
    // Microsoft
    "000D3A" to "Microsoft", "00125A" to "Microsoft", "00155D" to "Microsoft", "0017FA" to "Microsoft",
    "001DD8" to "Microsoft", "0025AE" to "Microsoft", "281878" to "Microsoft", "3059B7" to "Microsoft",
    "6045BD" to "Microsoft", "7085C2" to "Microsoft", "DC9840" to "Microsoft",
    // Google
    "001A11" to "Google", "3C5A37" to "Google", "546009" to "Google", "703ACB" to "Google",
    "94EBCD" to "Google", "A47733" to "Google", "D86C63" to "Google", "E4F042" to "Google",
    "F80FF9" to "Google", "F88FC2" to "Google",
    // OPPO / OnePlus / Realme
    "102A97" to "OPPO", "1C77F6" to "OPPO", "2C598A" to "OPPO", "307512" to "OPPO",
    "347DF6" to "OPPO", "44334C" to "OPPO", "4801C5" to "OPPO", "507705" to "OPPO",
    "6C5C14" to "OPPO", "7CA8EC" to "OPPO", "90A4DE" to "OPPO", "A09347" to "OPPO",
    "B83765" to "OPPO", "C0EEFB" to "OPPO", "CCC3EA" to "OPPO", "E88D28" to "OPPO",
    // Vivo / iQOO
    "14EBC6" to "Vivo", "28FF3E" to "Vivo", "3052CB" to "Vivo", "404E36" to "Vivo",
    "542AA2" to "Vivo", "6021C0" to "Vivo", "6CBB8B" to "Vivo", "7C2A31" to "Vivo",
    "842E27" to "Vivo", "A086C6" to "Vivo", "C0A5DD" to "Vivo", "DC44B6" to "Vivo",
    "E0B9E5" to "Vivo",
    // Espressif (IoT)
    "18FE34" to "Espressif", "240AC4" to "Espressif", "2462AB" to "Espressif", "246F28" to "Espressif",
    "24B2DE" to "Espressif", "2C3AE8" to "Espressif", "30AEA4" to "Espressif", "3C71BF" to "Espressif",
    "409151" to "Espressif", "483FDA" to "Espressif", "485519" to "Espressif", "4C11AE" to "Espressif",
    "545AA6" to "Espressif", "600194" to "Espressif", "68C63A" to "Espressif", "70039F" to "Espressif",
    "7C9EBD" to "Espressif", "807D3A" to "Espressif", "840D8E" to "Espressif", "84F3EB" to "Espressif",
    "94B97E" to "Espressif", "A4CF12" to "Espressif", "AC67B2" to "Espressif", "B4E62D" to "Espressif",
    "BCDDD2" to "Espressif", "C44F33" to "Espressif", "C82B96" to "Espressif", "CC50E3" to "Espressif",
    "D8A01D" to "Espressif", "DC4F22" to "Espressif", "ECFABC" to "Espressif",
    // Raspberry Pi
    "28CDC1" to "Raspberry Pi", "B827EB" to "Raspberry Pi", "DCA632" to "Raspberry Pi", "E45F01" to "Raspberry Pi",
    // TP-Link
    "003192" to "TP-Link", "14CC20" to "TP-Link", "18A6F7" to "TP-Link", "1C3BF3" to "TP-Link",
    "30B5C2" to "TP-Link", "503EAA" to "TP-Link", "50C7BF" to "TP-Link", "54E6FC" to "TP-Link",
    "6032B1" to "TP-Link", "7405A5" to "TP-Link", "7883C6" to "TP-Link", "984827" to "TP-Link",
    "A0F3C1" to "TP-Link", "B0487A" to "TP-Link", "C006C3" to "TP-Link", "CC32E5" to "TP-Link",
    "DC16B2" to "TP-Link", "EC086B" to "TP-Link", "EC172F" to "TP-Link",
    // Nintendo
    "0009BF" to "Nintendo", "001656" to "Nintendo", "0017AB" to "Nintendo", "00191D" to "Nintendo",
    "001BEA" to "Nintendo", "001DBC" to "Nintendo", "001E35" to "Nintendo", "001F32" to "Nintendo",
    "002147" to "Nintendo", "00224C" to "Nintendo", "0022D7" to "Nintendo", "002331" to "Nintendo",
    "00241E" to "Nintendo", "002444" to "Nintendo", "0024F3" to "Nintendo", "0025A0" to "Nintendo",
    "002659" to "Nintendo", "7CBB8A" to "Nintendo", "98B6E9" to "Nintendo", "A4C0E1" to "Nintendo",
    "B87826" to "Nintendo", "CC9E00" to "Nintendo", "D4F057" to "Nintendo", "E84ECE" to "Nintendo",
    // Sony
    "00014A" to "Sony", "00041F" to "Sony", "001315" to "Sony", "0015C1" to "Sony",
    "0019C5" to "Sony", "001A80" to "Sony", "001D0D" to "Sony", "001E45" to "Sony",
    "001FA7" to "Sony", "00248D" to "Sony", "709E29" to "Sony", "F8D0AC" to "Sony",
)
