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
 * - API 30+:ConnectivityManager.getConnectionOwnerUid(protocol, localPort, remote)
 *   —— 只按本地端口反查,不依赖 tun 内源 IP(内核 socket 跟踪的源 IP 与包内源 IP
 *   在 VPN 隧道下可能不一致,端口才是稳定标识)。
 * - API 29:getConnectionOwnerUid(protocol, local, remote) 四元组。
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
            val remote = InetSocketAddress(remoteIP, remotePort)
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> {
                    // API 30+:本地端口独查,避开源 IP 匹配问题。
                    cm.getConnectionOwnerUid(proto, localPort, remote)
                }
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q -> {
                    val local = InetSocketAddress(localIP, localPort)
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
                f.forEachLine { line ->
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
