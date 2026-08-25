package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import java.io.File
import java.net.InetSocketAddress

/**
 * gomobile 反向桥实现:Go TUN 路径按连接回问 Android 该连接属于哪个 UID,
 * 供「禁止联网」(per-app block)判定。实现 mobile.UIDResolver(Go 接口 → Java 接口),
 * 由 SmartProxyVpnService 在 establish 前注册:Mobile.setUIDResolver(this)。
 *
 * - API 29+:ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)
 *   四元组(公开 API 只有这一种重载;网上常传的 (protocol, localPort,
 *   remotePort) 端口版并不存在——compileSdk 35 编译期实测,传 int×3 会
 *   被解析到四元组报类型不匹配)。
 * - API 26-28:解析 /proc/net/{tcp,tcp6,udp,udp6}(uid 列),失败返回 -1。
 *
 * 返回 -1(未知)时 Go 侧放行(不误拦系统/自身流量);被拦应用只在明确命中时断网。
 * proto:6=TCP,17=UDP。
 */
class UIDResolver(private val context: Context) : smartproxy.mobile.UIDResolver {

    companion object {
        private const val TAG = "SmartProxyVpn"
        private const val UNKNOWN = -1
    }

    override fun resolveUID(
        proto: Int,
        localIP: String,
        localPort: Int,
        remoteIP: String,
        remotePort: Int
    ): Int {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> {
                    // API 29+ 唯一公开重载:四元组 (protocol, local, remote)。
                    // local 用 tunnel 分配给应用的 IP+端口(即内核 socket 的源地址)。
                    val local = InetSocketAddress(localIP, localPort)
                    val remote = InetSocketAddress(remoteIP, remotePort)
                    cm.getConnectionOwnerUid(proto, local, remote)
                }
                else -> resolveViaProcNet(proto, localPort)
            }
        } catch (e: Exception) {
            Log.w(TAG, "[UIDResolver] resolveUID failed proto=$proto localPort=$localPort: ${e.message}")
            UNKNOWN
        }
    }

    /** API 26-28 回退:/proc/net/{tcp,tcp6,udp,udp6} 按本地端口找 uid 列(第 8 列)。
     *  Android 7+ 对部分厂商该文件可能不可读/uid 归零,失败返回 -1(放行)。 */
    private fun resolveViaProcNet(proto: Int, localPort: Int): Int {
        val tables = when (proto) {
            6 -> listOf("tcp", "tcp6")
            17 -> listOf("udp", "udp6")
            else -> return UNKNOWN
        }
        val hexPort = localPort.toString(16).uppercase()
        for (name in tables) {
            val f = File("/proc/net/$name")
            if (!f.canRead()) continue
            try {
                // 普通 for 循环(非 lambda):return it 直接从函数返回;
                // forEachLine 的 lambda 非内联,裸 return 会被编译器拒绝。
                for (line in f.readLines()) {
                    val parts = line.trim().split(Regex("\\s+"))
                    // 列:sl local_address rem_address st ... uid ...
                    if (parts.size >= 8 && parts[1].endsWith(":$hexPort")) {
                        parts[7].toIntOrNull()?.let { return it }
                    }
                }
            } catch (_: Exception) {
                return UNKNOWN
            }
        }
        return UNKNOWN
    }
}
