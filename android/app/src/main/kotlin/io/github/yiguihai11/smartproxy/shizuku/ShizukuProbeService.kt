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
import android.os.Bundle
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
 * Shizuku UserService(M6.1 探针 + M7 持久热点共享),跑在 shell UID 进程里,
 * 借 Shizuku 的系统权限调用隐藏 API(TestNetworkManager / TetheringManager)。
 *
 * 两种形态,同一进程内并存:
 *  - [probe]:一次性冒烟探测(建 test TUN → 开热点 → 确认上游 → teardown),供诊断按钮回显。
 *  - [startHotspot] / [stopHotspot]:M7 持久共享——建 test TUN + 开热点后**不拆**,把 fd 返回
 *    App;App 侧 dup+detachFd 喂给 Go 引擎做双 TUN,热点客户端流量进同一套分流/代理。
 *    停止时机:App 显式 stopHotspot(),或 App 进程死亡(linkToDeath → 自动回收)。
 *
 * 注意:startHotspot 会长期开启手机热点(WiFi 客户端会切换),关闭走对话框开关或停 VPN。
 * Shizuku 用类名反射实例化,必须 @Keep;构造参数是 Context(UserServiceArgs 约定)。
 * AIDL 方法可能从不同 binder 线程并发进入,start/stop/isActive 都 @Synchronized。
 */
@Keep
@SuppressLint("WrongConstant", "PrivateApi", "DiscouragedPrivateApi")
class ShizukuProbeService(private val context: Context) : IShizukuProbe.Stub() {

    companion object {
        private const val TAG = "ShizukuProbe"
        const val USER_SERVICE_VERSION = 3 // M7:AIDL 新增 startHotspot 族,版本号 +1 让 Shizuku 重启旧进程

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
        // App 侧(HotspotShare)直接引用这两个常量,保持 Go 引擎喂参一致,防漂移。
        const val TUN_ADDR_V4 = "192.0.2.2/24"
        const val TUN_ADDR_V6 = "2001:db8:9877::1/64"
        const val TUN_DNS_HINT_V6 = "fdfe:dcba:9877::53"
        private const val UPSTREAM_INTERFACES_PREFIX = "Current upstream interface(s):"

        // startHotspot 返回 Bundle 的 key(AIDL 禁 String 作 out 参数,out 信息塞 Bundle)。
        const val KEY_PFD = "pfd" // ParcelFileDescriptor,成功才有;调用方负责 close(Binder 自动 dup)
        const val KEY_IFACE = "iface" // String,测试 TUN 接口名(成功时)
        const val KEY_ERROR = "error" // String,失败原因;成功为空串

        internal fun createUserServiceArgs(): Shizuku.UserServiceArgs =
            Shizuku.UserServiceArgs(
                ComponentName(BuildConfig.APPLICATION_ID, ShizukuProbeService::class.java.name),
            )
                .daemon(true)
                .processNameSuffix("shizuku_probe")
                .debuggable(BuildConfig.DEBUG)
                .version(USER_SERVICE_VERSION)
    }

    // —— M7 持久热点共享状态(@Volatile,读写都持方法锁)——
    @Volatile private var started = false
    private var shellContext: Context? = null
    private var manager: Any? = null
    private var cm: ConnectivityManager? = null
    private var tunPfd: ParcelFileDescriptor? = null
    private var hotIfaceName: String? = null
    private var publishedNetwork: Network? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var tetheringManager: Any? = null
    private var tetheringStarted = false
    private var appToken: IBinder? = null
    private var deathRecipient: IBinder.DeathRecipient? = null

    /**
     * LinkAddress(String) 在 SDK stub 里是 package-private(公共 API 只有
     * InetAddress+prefix 的构造),只能反射实例化。v2rayNG 同款做法。
     */
    private fun createLinkAddress(cidr: String): LinkAddress =
        LinkAddress::class.java.getDeclaredConstructor(String::class.java).run {
            isAccessible = true
            newInstance(cidr) as LinkAddress
        }

    // ════════════════════════ M7 持久热点共享 ════════════════════════

    @Synchronized
    override fun startHotspot(appToken: IBinder): Bundle {
        // 已启动:直接返回现有 fd。Binder 写 Bundle 里的 ParcelFileDescriptor 会重新 dup,
        // 每个调用方都拿到独立 fd,自己负责 close;服务端 tunPfd 不动。
        if (started) {
            tunPfd?.let { pfd ->
                return Bundle().apply {
                    putParcelable(KEY_PFD, pfd)
                    putString(KEY_IFACE, hotIfaceName)
                }
            }
            return Bundle().apply { putString(KEY_ERROR, "状态不一致:started=true 但 tunPfd 为空") }
        }
        // 失败统一出口:error 塞 Bundle + 幂等回收半截状态(started 尚未置位,stopHotspot 也全清)。
        fun fail(msg: String): Bundle {
            Log.w(TAG, "startHotspot 失败: $msg")
            stopHotspot()
            return Bundle().apply { putString(KEY_ERROR, msg) }
        }
        return try {
            // ① shell 归属 Context(与探针同路径)
            val sc = ShellContextCompat.create(context)
            shellContext = sc

            // ② TestNetworkManager
            val m = sc.getSystemService(TEST_NETWORK_SERVICE) ?: return fail("test_network 服务不可用")
            manager = m
            val cmx = sc.getSystemService(ConnectivityManager::class.java) ?: return fail("ConnectivityManager 不可用")
            cm = cmx

            // ③ 建测试网络 TUN(双栈,对齐 v2rayNG)
            val addresses = arrayOf(
                createLinkAddress(TUN_ADDR_V4),
                createLinkAddress(TUN_ADDR_V6),
            )
            val testInterface: Any = try {
                m.javaClass.getMethod("createTunInterface", addresses.javaClass)
                    .invoke(m, addresses as Any)
            } catch (e: Throwable) {
                return fail("createTunInterface 反射失败: $e")
            } ?: return fail("createTunInterface 返回 null")
            val pfd = testInterface.javaClass.getMethod("getFileDescriptor")
                .invoke(testInterface) as ParcelFileDescriptor
            val iface = testInterface.javaClass.getMethod("getInterfaceName")
                .invoke(testInterface) as String
            tunPfd = pfd
            hotIfaceName = iface

            // ④ 发布为测试网络,等 onAvailable(配双栈地址 + v6 DNS hint,否则热点不广告 IPv6)
            val lifetimeToken = SystemServiceHelper.getSystemService(Context.CONNECTIVITY_SERVICE) as IBinder
            val latch = CountDownLatch(1)
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (cmx.getLinkProperties(network)?.interfaceName == iface) {
                        publishedNetwork = network
                        latch.countDown()
                    }
                }
            }
            networkCallback = cb
            val request = NetworkRequest.Builder()
                .addTransportType(TRANSPORT_TEST)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
                .build()
            cmx.registerNetworkCallback(request, cb)
            val properties = LinkProperties().apply {
                interfaceName = iface
                setLinkAddresses(listOf(createLinkAddress(TUN_ADDR_V4), createLinkAddress(TUN_ADDR_V6)))
                setDnsServers(listOf(InetAddress.getByName(TUN_DNS_HINT_V6)))
            }
            try {
                m.javaClass.getMethod(
                    "setupTestNetwork",
                    LinkProperties::class.java,
                    Boolean::class.javaPrimitiveType,
                    IBinder::class.java,
                ).invoke(m, properties, true, lifetimeToken)
            } catch (e: Throwable) {
                return fail("setupTestNetwork 反射失败: $e")
            }
            if (!latch.await(TEST_NETWORK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                return fail("test network 发布超时(${TEST_NETWORK_TIMEOUT_SECONDS}s)")
            }

            // ⑤ 热点以测试网络为上游
            val tm = sc.getSystemService(TETHERING_SERVICE) ?: return fail("tethering 服务不可用")
            tetheringManager = tm
            try {
                tm.javaClass.getMethod("setPreferTestNetworks", Boolean::class.javaPrimitiveType)
                    .invoke(tm, true)
            } catch (e: Throwable) {
                return fail("setPreferTestNetworks 反射失败: $e")
            }

            // ⑥ 自动开 WiFi 热点(公共 API 需 Android 13+)
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                return fail("需要 Android 13+ 才能开热点(当前 ${Build.VERSION.SDK_INT})")
            }
            val startResult = startWifiTethering(tm, TETHERING_START_TIMEOUT_SECONDS)
            if (startResult != RESULT_OK) {
                return fail("startTethering 失败码 $startResult")
            }
            tetheringStarted = true

            // ⑦ 最后才 linkToDeath:App 进程死 → 自动回收热点 + test TUN(免泄漏)。
            val dr = object : IBinder.DeathRecipient {
                override fun binderDied() {
                    Log.w(TAG, "App 进程死亡,自动回收热点 + test TUN")
                    stopHotspot()
                }
            }
            this.appToken = appToken
            deathRecipient = dr
            try {
                appToken.linkToDeath(dr, 0)
            } catch (e: Throwable) {
                // linkToDeath 抛 = App 已死/即将死,没人会来 stopHotspot,就地回收。
                Log.e(TAG, "linkToDeath 失败(App 可能已死),回收", e)
                return fail("linkToDeath 失败: $e")
            }

            started = true
            Log.i(TAG, "startHotspot 成功: iface=$iface fd=${pfd.fd}")
            Bundle().apply {
                putParcelable(KEY_PFD, pfd)
                putString(KEY_IFACE, iface)
            }
        } catch (e: Throwable) {
            Log.e(TAG, "startHotspot 未捕获异常,回收", e)
            fail("未捕获异常: $e")
        }
    }

    /** 幂等停止:停热点 → teardown test network → 关 tunPfd → 反注册 → 撤销 prefer → unlink。 */
    @Synchronized
    override fun stopHotspot() {
        started = false
        if (tetheringStarted) {
            runCatching { tetheringManager?.let { stopWifiTethering(it) } }
            tetheringStarted = false
        }
        runCatching {
            publishedNetwork?.let { n ->
                manager?.javaClass?.getMethod("teardownTestNetwork", Network::class.java)
                    ?.invoke(manager, n)
            }
        }
        runCatching { tunPfd?.close() }
        runCatching { networkCallback?.let { cm?.unregisterNetworkCallback(it) } }
        runCatching {
            tetheringManager?.javaClass
                ?.getMethod("setPreferTestNetworks", Boolean::class.javaPrimitiveType)
                ?.invoke(tetheringManager, false)
        }
        val token = appToken
        val dr = deathRecipient
        if (token != null && dr != null) runCatching { token.unlinkToDeath(dr, 0) }
        // 清全部状态
        shellContext = null; manager = null; cm = null; tunPfd = null; hotIfaceName = null
        publishedNetwork = null; networkCallback = null; tetheringManager = null
        appToken = null; deathRecipient = null
        Log.i(TAG, "stopHotspot 完成")
    }

    @Synchronized
    override fun isHotspotActive(): Boolean = started

    // ════════════════════════ M6.1 一次性探针 ════════════════════════

    override fun probe(): String {
        // 持久热点已开时禁止:探针会再建一条 test TUN + 再开一次热点,且 finally teardown
        // 会把持久热点的上游一起撕掉。让用户先关热点共享再诊断。
        if (started) {
            return "热点共享已开启,请先在对话框关闭热点共享再运行探针。\n" +
                "(探针与持久共享共用 test TUN 机制,同时跑会互相干扰热点上游)"
        }
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
