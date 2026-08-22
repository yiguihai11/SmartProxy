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
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.Keep
import io.github.yiguihai11.smartproxy.BuildConfig
import rikka.shizuku.Shizuku
import rikka.shizuku.SystemServiceHelper
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Shizuku 探针 UserService(M6 骨架,验证 iQOO12/OriginOS 上隐藏 API 可用性)。
 *
 * 流程 = v2rayNG PR #5903 的截断版:shell Context → TestNetworkManager 建测试网络 TUN →
 * setupTestNetwork 发布 → setPreferTestNetworks(true) → dumpsys 确认上游,逐步行进,
 * 失败点精确回显。全程不接引擎、不放行流量,验证通了再往下做完整热点共享。
 *
 * Shizuku 用类名反射实例化,必须 @Keep;构造参数是 Context(UserServiceArgs 约定)。
 */
@Keep
@SuppressLint("WrongConstant") // TRANSPORT_TEST(7) 是隐藏传输类型,无 public 常量
class ShizukuProbeService(private val context: Context) : IShizukuProbe.Stub() {

    companion object {
        private const val TAG = "ShizukuProbe"
        const val USER_SERVICE_VERSION = 1

        private const val TEST_NETWORK_SERVICE = "test_network"
        private const val TETHERING_SERVICE = "tethering"
        private const val TEST_NETWORK_TIMEOUT_SECONDS = 15L
        private const val DUMPSYS_TIMEOUT_SECONDS = 2L
        private const val TRANSPORT_TEST = 7

        // 与 v2rayNG SHIZUKU_TUN_ADDR_V4 一致:测试网段,不撞真实流量。
        private const val TUN_ADDR = "192.0.2.2/24"

        internal fun createUserServiceArgs(): Shizuku.UserServiceArgs =
            Shizuku.UserServiceArgs(
                ComponentName(BuildConfig.APPLICATION_ID, ShizukuProbeService::class.java.name),
            )
                .daemon(true)
                .processNameSuffix("shizuku_probe")
                .debuggable(BuildConfig.DEBUG)
                .version(USER_SERVICE_VERSION)
    }

    override fun probe(): String {
        val log = StringBuilder()
        fun step(msg: String) {
            log.append(msg).append('\n')
            Log.i(TAG, msg)
        }

        // 逐步状态,供 finally 统一清理;闭包只读不写,判空后可智能转换。
        var shellContext: Context? = null
        var manager: Any? = null
        var cm: ConnectivityManager? = null
        var tun: ParcelFileDescriptor? = null
        var tetheringManager: Any? = null
        var publishedNetwork: Network? = null
        var callback: ConnectivityManager.NetworkCallback? = null

        try {
            // ① shell 归属 Context(首个探针点:OriginOS 若收紧 ContextImpl 反射,这里就死)
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

            // ③ 建测试网络 TUN(接口名形如 testtun0)
            val addresses = arrayOf(LinkAddress(TUN_ADDR))
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

            // ④ 发布为测试网络,等 onAvailable 确认(TRANSPORT_TEST = 7)
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
                setLinkAddresses(listOf(LinkAddress(TUN_ADDR)))
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

            // ⑤ 让热点以测试网络为上游(TetheringManager.setPreferTestNetworks)
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
            }

            // ⑥ dumpsys 确认上游已被保护为测试 TUN(best-effort,OriginOS 输出格式可能不同)
            val upstream = try {
                readUpstreamInterfaceName()
            } catch (e: Throwable) {
                "读取失败: ${e.message}"
            }
            step("⑥ 上游接口(dumpsys): $upstream | 期望: $iface")
            val protectedUpstream = upstream != null && upstream.isNotBlank() &&
                upstream.split(',').map(String::trim).all { it == iface }
            step(
                if (protectedUpstream) "✓ ⑦ 热点上游=测试 TUN $iface —— 机制可用,可以接引擎!"
                else "⚠ ⑦ 上游非测试 TUN(OriginOS 可能需额外处理)"
            )

            return log.toString()
        } catch (e: Throwable) {
            step("✗ 未捕获异常: $e")
            return log.toString()
        } finally {
            // 清理:反注册回调 → teardown → 关 fd → 撤销 prefer。全部 best-effort。
            runCatching {
                publishedNetwork?.let { n ->
                    manager?.javaClass?.getMethod("teardownTestNetwork", Network::class.java)
                        ?.invoke(manager, n)
                }
            }
            runCatching { cm?.unregisterNetworkCallback(callback) }
            runCatching { tun?.close() }
            runCatching {
                tetheringManager?.javaClass
                    ?.getMethod("setPreferTestNetworks", Boolean::class.javaPrimitiveType)
                    ?.invoke(tetheringManager, false)
            }
            Log.i(TAG, "probe() 清理完成")
        }
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

    private const val UPSTREAM_INTERFACES_PREFIX = "Current upstream interface(s):"
}
