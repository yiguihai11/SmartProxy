package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.os.Build
import android.os.SystemClock
import android.util.Log
import android.util.LruCache
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * gomobile 反向桥实现:Go TUN 路径按连接回问 Android 该连接属于哪个 UID,
 * 供「禁止联网」(per-app block)判定与连接监控统计。实现 mobile.UIDResolver(Go 接口 → Java 接口),
 * 由 SmartProxyVpnService 在 establish 前注册:Mobile.setUIDResolver(UIDResolver(applicationContext))。
 *
 * 性能优化:
 *  1. 缓存应用级 Context 与 ConnectivityManager 实例,规避高频 getSystemService 查找;
 *  2. 采用 InetAddresses.parseNumericAddress 原生解析 IP,跳过常规 getByName 的 DNS 解析检查;
 *  3. 引入轻量级线程安全 LRU 缓存(容量 256,有效 TTL 3 秒):
 *     Go 侧 isUIDBlocked 与 connStats 对同一连接连续反查时 100% 内存命中;
 *     突发并发流与重试包避免重复打向 system_server,规避 0.5ms~2.0ms 的 Binder IPC 开销。
 *
 * 只支持 API 29+:ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)
 * 四元组(公开 API 只有这一种重载)。
 * 返回 -1(未知)时 Go 侧放行(不误拦系统/自身流量);被拦应用只在明确命中时断网。
 * proto:6=TCP,17=UDP。
 */
class UIDResolver(context: Context) : smartproxy.mobile.UIDResolver {

    companion object {
        private const val TAG = "SmartProxyVpn"
        private const val UNKNOWN = -1
        private const val CACHE_CAPACITY = 256
        private const val POSITIVE_TTL_MS = 3000L  // 命中 UID 缓存 3 秒
        private const val NEGATIVE_TTL_MS = 800L   // 未解析到 UID 缓存 800ms,防频繁重试打满 Binder
    }

    private val appContext = context.applicationContext
    private val cm: ConnectivityManager? by lazy {
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    }

    private data class CacheEntry(val uid: Int, val expireAt: Long)

    /** 线程安全 LRU 缓存:Key 为四元组字符串,Value 为包含过期时间的 UID 条目。 */
    private val lruCache = object : LruCache<String, CacheEntry>(CACHE_CAPACITY) {}

    override fun resolveUID(
        proto: Int,
        localIP: String,
        localPort: Int,
        remoteIP: String,
        remotePort: Int
    ): Int {
        // 只支持 API 29+:老系统无 UID 反查通道(/proc/net 不可读),直接放行不拦。
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return UNKNOWN

        val cacheKey = "$proto:$localPort:$remoteIP:$remotePort"
        val now = SystemClock.elapsedRealtime()

        // 1. 优先查内存 LRU 缓存(纳秒级响应,规避 0.5~2ms 的 Binder IPC 阻塞)
        synchronized(lruCache) {
            val entry = lruCache.get(cacheKey)
            if (entry != null && now < entry.expireAt) {
                return entry.uid
            }
        }

        // 2. 缓存未命中,发起系统 IPC 调用
        return try {
            val manager = cm ?: return UNKNOWN
            val localAddr = InetAddresses.parseNumericAddress(localIP)
            val remoteAddr = InetAddresses.parseNumericAddress(remoteIP)
            val local = InetSocketAddress(localAddr, localPort)
            val remote = InetSocketAddress(remoteAddr, remotePort)

            val uid = manager.getConnectionOwnerUid(proto, local, remote)
            val ttl = if (uid != UNKNOWN) POSITIVE_TTL_MS else NEGATIVE_TTL_MS

            synchronized(lruCache) {
                lruCache.put(cacheKey, CacheEntry(uid, now + ttl))
            }
            uid
        } catch (e: Exception) {
            Log.w(TAG, "[UIDResolver] resolveUID failed proto=$proto localPort=$localPort: ${e.message}")
            UNKNOWN
        }
    }
}
