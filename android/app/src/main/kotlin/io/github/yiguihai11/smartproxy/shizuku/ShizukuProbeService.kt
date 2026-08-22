package io.github.yiguihai11.smartproxy.shizuku

import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.Keep
import io.github.yiguihai11.smartproxy.BuildConfig
import rikka.shizuku.Shizuku
import rikka.shizuku.SystemServiceHelper
import java.net.InetAddress
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Shizuku 探针 UserService(M6.1,验证 iQOO12/OriginOS 上免 root 热点共享整条链路)。
 *
 * 流程 = v2rayNG PR #5903 的截断版:shell Context → TestNetworkManager 建双栈测试网络
 * TUN → setupTestNetwork 发布 → setPreferTestNetworks(true) → 启动 WiFi 热点 →
 * 轮询 dumpsys 确认热点上游 = 测试 TUN → 停热点收尾。失败点精确回显,不接引擎、不放流量。
 *
 * 注意:会短暂开启/关闭手机热点(WiFi 客户端会切换),探测完自动恢复。
 * Shizuku 用类名反射实例化,必须 @Keep;构造参数是 Context(UserServiceArgs 约定)。
 */
@Keep
@SuppressLint("WrongConstant", "PrivateApi", "DiscouragedPrivateApi")
class ShizukuProbeService(private val context: Context) : IShizukuProbe.Stub() {

    companion object {
        private const val TAG = "ShizukuProbe"
        const val USER_SERVICE_VERSION = 2 // AIDL 行为变了,版本号 +1 让 Shizuku 重启旧进程

        private const val TEST_NETWORK_SERVICE = "test_network"
        private const val TETHERING_SERVICE = "tethering"
        private const val TEST_NETWORK_TIMEOUT_SECONDS = 15L
        private const val TETHERING_START_TIMEOUT_SECONDS = 10L
        private const val UPSTREAM_POLL_TIMEOUT_SECONDS = 15L
        private const val UPSTREAM_POLL_INTERVAL_MILLIS = 500L
        private const val DUMPSYS_TIMEOUT_SECONDS = 2L
        private const val TRANSPORT_TEST = 7

        private const val RESULT_OK = 0
        private const val RESULT_INTERNAL_ERROR = -1
        private const val TETHERING_TYPE_WIFI = 0 // TetheringManager.TETHERING_TYPE_WIFI(该类是 @SystemApi,不能引用)

        // 与 v2rayNG AppConfig 完全一致:双栈地址 + v6 DNS hint。
        // TestNetworkManager 会为每个地址族装默认路由;热点要广告 IPv6 上游,
        // Android 要求 LinkProperties 里至少有一个 IPv6 DNS server。
        private const val TUN_ADDR_V4 = "192.0.2.2/24"
        private const val TUN_ADDR_V6 = "2001:db8:9877::1/64"
        private const val TUN_DNS_HINT_V6 = "fdfe:dcba:9877::53"
        private const val UPSTREAM_INTERFACES_PREFIX = "Current upstream interface(s):"

        internal fun createUserServiceArgs(): Shizuku.UserServiceArgs =
            Shizuku.UserServiceArgs(
                ComponentName(BuildConfig.APPLICATION_ID, ShizukuProbeService::class.java.name),
            )
                .daemon(true)
                .processNameSuffix("shizuku_probe")
                .debuggable(BuildConfig.DEBUG)
                .version(USER_SERVICE_VERSION)
    }

    /**
     * LinkAddress(String) 在 SDK stub 里是 package-private(公共 API 只有
     * InetAddress+prefix 的构造),只能反射实例化。v2rayNG 同款做法。
     */
    private fun createLinkAddress(cidr: String): LinkAddress =
        LinkAddress::class.java.getDeclaredConstructor(String::class.java).run {
            isAccessible = true
            newInstance(cidr) as LinkAddress
        }

    override fun probe(): String {
        val log = StringBuilder()
        fun step(msg: String) {
            log.append(msg).append('\n')
            Log.i(TAG, msg)
        }

        // 逐步状态,供 finally 统一清理;闭包只读不写。
        var shellContext: Context? = null
        var manager: Any? = null
        var cm: ConnectivityManager? = null
        var tun: ParcelFileDescriptor? = null
        var tetheringManager: Any? = null
        var publishedNetwork: Network? = null
        var callback: ConnectivityManager.NetworkCallback? = null

        try {
            // ① shell 归属 Context(OriginOS 若收紧 ContextImpl 反射,这里就死;首轮已确认可用)
            shellContext = ShellContextCompat.create(context)
            step("✓ ① shellContext 创建成功")

            // ② TestNetworkManager 隐藏服务
            manager = shellContext.getSystemService(TEST_NETWORK_SERVICE)
            if (manager == null) {
                step("✗ ② test_network 服务不可用")
                return log.toString()
            }
            step("✓ ② TestNetworkManager 可用: ${manager.javaClass.name}")

            cm = shellContext.getSystemService(ConnectivityManager::class.java)
            if (cm == null) {
                step("✗ ② ConnectivityManager 不可用")
                return log.toString()
            }

            // ③ 建测试网络 TUN:双栈地址(对齐 v2rayNG)
            val addresses = arrayOf(
                createLinkAddress(TUN_ADDR_V4),
                createLinkAddress(TUN_ADDR_V6),
            )
            val testInterface: Any = try {
                manager.javaClass.getMethod("createTunInterface", addresses.javaClass)
                    .invoke(manager, addresses as Any)
            } catch (e: Throwable) {
                step("✗ ③ createTunInterface 反射失败: $e")
                return log.toString()
            } ?: run {
                step("✗ ③ createTunInterface 返回 null")
                return log.toString()
            }
            tun = testInterface.javaClass.getMethod("getFileDescriptor")
                .invoke(testInterface) as ParcelFileDescriptor
            val iface = testInterface.javaClass.getMethod("getInterfaceName")
                .invoke(testInterface) as String
            step("✓ ③ createTunInterface OK: iface=$iface fd=${tun!!.fd}")

            // ④ 发布为测试网络,等 onAvailable 确认。配双栈地址 + v6 DNS hint,
            //    否则热点可能不广告 IPv6 上游 → 上游为空(首轮 v4-only 的疑点)。
            val lifetimeToken = SystemServiceHelper.getSystemService(Context.CONNECTIVITY_SERVICE) as IBinder
            val latch = CountDownLatch(1)
            callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (cm?.getLinkProperties(network)?.interfaceName == iface) {
                        publishedNetwork = network
                        latch.countDown()
                    }
                }
            }
            val request = NetworkRequest.Builder()
                .addTransportType(TRANSPORT_TEST)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
                .build()
            cm!!.registerNetworkCallback(request, callback)

            val properties = LinkProperties().apply {
                interfaceName = iface
                setLinkAddresses(listOf(createLinkAddress(TUN_ADDR_V4), createLinkAddress(TUN_ADDR_V6)))
                setDnsServers(listOf(InetAddress.getByName(TUN_DNS_HINT_V6)))
            }
            try {
                manager.javaClass.getMethod(
                    "setupTestNetwork",
                    LinkProperties::class.java,
                    Boolean::class.javaPrimitiveType,
                    IBinder::class.java,
                ).invoke(manager, properties, true, lifetimeToken)
                step("✓ ④ setupTestNetwork 调用成功")
            } catch (e: Throwable) {
                step("✗ ④ setupTestNetwork 反射失败: $e")
                return log.toString()
            }

            if (!latch.await(TEST_NETWORK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                step("✗ ④ 等待 test network 发布超时(${TEST_NETWORK_TIMEOUT_SECONDS}s)")
                return log.toString()
            }
            step("✓ ④ test network 已发布: network=$publishedNetwork")

            // ⑤ 让热点以测试网络为上游(TetheringManager.setPreferTestNetworks,隐藏 API 走反射)
            tetheringManager = shellContext.getSystemService(TETHERING_SERVICE)
            if (tetheringManager == null) {
                step("✗ ⑤ tethering 服务不可用")
                return log.toString()
            }
            try {
                tetheringManager.javaClass
                    .getMethod("setPreferTestNetworks", Boolean::class.javaPrimitiveType)
                    .invoke(tetheringManager, true)
                step("✓ ⑤ setPreferTestNetworks(true) 调用成功")
            } catch (e: Throwable) {
                step("✗ ⑤ setPreferTestNetworks 反射失败: $e")
                return log.toString()
            }

            // ⑥ 启动 WiFi 热点(公共 API),验证上游选择 —— 探针真正的裁决点
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                step("✗ ⑥ 启动热点需要 Android 13+(当前 ${Build.VERSION.SDK_INT})")
                return log.toString()
            }
            val startResult = startWifiTethering(tetheringManager, TETHERING_START_TIMEOUT_SECONDS)
            step("⑥ startTethering(WIFI) 结果: $startResult (0=OK, 负数/其他=失败码)")
            if (startResult != RESULT_OK) {
                step("✗ ⑥ 热点启动失败,上游验证跳过")
                return log.toString()
            }

            // ⑦ 轮询 dumpsys:热点上游是否 = 测试 TUN
            val upstream = pollUpstreamInterfaceName(iface, UPSTREAM_POLL_TIMEOUT_SECONDS)
            step("⑦ 上游接口(dumpsys): $upstream | 期望: $iface")
            val protectedUpstream = upstream != null && upstream.isNotBlank() &&
                upstream.split(',').map(String::trim).any { it == iface }
            step(
                if (protectedUpstream) "✓ ⑧ 热点上游=测试 TUN $iface —— 完整链路打通,可以接引擎!"
                else "✗ ⑧ 热点已启动但上游仍非 $iface\n   (OriginOS 需适配,原因看上面 dumpsys 值)"
            )

            return log.toString()
        } catch (e: Throwable) {
            step("✗ 未捕获异常: $e")
            return log.toString()
        } finally {
            // 清理(逆序):先停热点(不然它还在跑在将被撕掉的网络上)→ teardown → 关 fd →
            // 反注册 → 撤销 prefer。全部 best-effort。
            if (tetheringManager != null) stopWifiTethering(tetheringManager)
            runCatching {
                publishedNetwork?.let { n ->
                    manager?.javaClass?.getMethod("teardownTestNetwork", Network::class.java)
                        ?.invoke(manager, n)
                }
            }
            runCatching { tun?.close() }
            runCatching { callback?.let { cm?.unregisterNetworkCallback(it) } }
            runCatching {
                tetheringManager?.javaClass
                    ?.getMethod("setPreferTestNetworks", Boolean::class.javaPrimitiveType)
                    ?.invoke(tetheringManager, false)
            }
            Log.i(TAG, "probe() 清理完成")
        }
    }

    /**
     * 启动 WiFi 热点:startTethering(TetheringRequest, Executor, StartTetheringCallback)。
     * 整个 TetheringManager 类是 @SystemApi,不在公共 android.jar(编译都引用不了),
     * 所以 TetheringRequest / 回调都走反射 + 动态代理。返回 0=成功,非 0=失败码。
     * v2rayNG 同思路(stopTethering 也是反射找方法)。
     */
    private fun startWifiTethering(manager: Any, timeoutSeconds: Long): Int {
        val requestClass = runCatching {
            Class.forName("android.net.TetheringManager\$TetheringRequest")
        }.getOrNull() ?: run {
            Log.e(TAG, "找不到 android.net.TetheringManager\$TetheringRequest")
            return RESULT_INTERNAL_ERROR
        }
        val callbackClass = runCatching {
            Class.forName("android.net.TetheringManager\$StartTetheringCallback")
        }.getOrNull() ?: run {
            Log.e(TAG, "找不到 StartTetheringCallback")
            return RESULT_INTERNAL_ERROR
        }
        val startMethod = manager.javaClass.methods.firstOrNull {
            it.name == "startTethering" &&
                it.parameterCount == 3 &&
                it.parameterTypes[0] == requestClass &&
                it.parameterTypes[1] == Executor::class.java &&
                it.parameterTypes[2] == callbackClass
        } ?: run {
            Log.e(TAG, "TetheringManager 上没有 3 参 startTethering")
            return RESULT_INTERNAL_ERROR
        }

        // TetheringRequest = new TetheringManager.TetheringRequest.Builder(TETHERING_TYPE_WIFI).build()
        val request = runCatching {
            val builderClass = Class.forName("android.net.TetheringManager\$TetheringRequest\$Builder")
            val builder = builderClass.getConstructor(Int::class.javaPrimitiveType).newInstance(TETHERING_TYPE_WIFI)
            builderClass.getMethod("build").invoke(builder)
        }.getOrNull() ?: run {
            Log.e(TAG, "构造 TetheringRequest 失败")
            return RESULT_INTERNAL_ERROR
        }

        var result = RESULT_INTERNAL_ERROR
        val latch = CountDownLatch(1)
        val callback = java.lang.reflect.Proxy.newProxyInstance(
            callbackClass.classLoader,
            arrayOf(callbackClass),
        ) { _, method, args ->
            when (method.name) {
                // API 31+ 的 onTetheringStarted(int result) 带结果码;个别 OEM ROM 走
                // 旧的无参版,取不到参数就当作 0(成功)兜底。
                "onTetheringStarted" -> {
                    result = (args?.firstOrNull() as? Number)?.toInt() ?: RESULT_OK
                    latch.countDown()
                }
                "onTetheringFailed" -> {
                    result = (args?.firstOrNull() as? Number)?.toInt() ?: RESULT_INTERNAL_ERROR
                    latch.countDown()
                }
                else -> null
            }
        }

        return try {
            startMethod.invoke(manager, request, Executor { it.run() }, callback)
            if (latch.await(timeoutSeconds, TimeUnit.SECONDS)) result else RESULT_INTERNAL_ERROR
        } catch (e: Throwable) {
            Log.e(TAG, "startTethering 调用抛异常", e)
            e.hashCode() and 0x7fffffff // 调用即抛(权限/未实现),转失败码
        }
    }

    /** stopTethering(int) 在 13-15 仍是隐藏 API(16+ 才公开),走反射;所有版本通用。 */
    private fun stopWifiTethering(manager: Any) {
        runCatching {
            val method = manager.javaClass.methods.firstOrNull {
                it.name == "stopTethering" && it.parameterTypes.contentEquals(arrayOf(Int::class.javaPrimitiveType))
            } ?: return
            method.invoke(manager, TETHERING_TYPE_WIFI)
        }.onFailure { Log.w(TAG, "stopTethering 失败", it) }
    }

    /** 轮询 dumpsys 直到上游命中期望接口或超时;返回最后一次读到的上游(可能为 null/空)。 */
    private fun pollUpstreamInterfaceName(expected: String, timeoutSeconds: Long): String? {
        val deadline = System.currentTimeMillis() + timeoutSeconds * 1000
        var last: String? = null
        while (System.currentTimeMillis() < deadline) {
            last = runCatching { readUpstreamInterfaceName() }.getOrNull()
            if (last != null && last.isNotBlank() && last.split(',').map(String::trim).any { it == expected }) {
                return last
            }
            try {
                Thread.sleep(UPSTREAM_POLL_INTERVAL_MILLIS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            }
        }
        return last
    }

    /** dumpsys tethering 里读 "Current upstream interface(s):",2s 超时强杀,防挂死。 */
    private fun readUpstreamInterfaceName(): String? {
        val process = ProcessBuilder("dumpsys", "tethering")
            .redirectErrorStream(true)
            .start()
        val output = CompletableFuture.supplyAsync {
            process.inputStream.bufferedReader().useLines { lines ->
                lines.firstNotNullOfOrNull { line ->
                    val trimmed = line.trimStart()
                    if (!trimmed.startsWith(UPSTREAM_INTERFACES_PREFIX)) null
                    else trimmed.substringAfter(UPSTREAM_INTERFACES_PREFIX).trim()
                        .removePrefix("[").removeSuffix("]").takeUnless { it == "null" }
                }.orEmpty()
            }
        }
        return try {
            output.get(DUMPSYS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (error: TimeoutException) {
            throw IllegalStateException("dumpsys tethering 读取超时", error)
        } finally {
            process.destroyForcibly()
            output.cancel(true)
        }
    }
}
