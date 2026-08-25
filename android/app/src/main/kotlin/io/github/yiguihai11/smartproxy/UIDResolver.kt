package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import java.net.InetSocketAddress

/**
 * gomobile 反向桥实现:Go TUN 路径按连接回问 Android 该连接属于哪个 UID,
 * 供「禁止联网」(per-app block)判定。实现 mobile.UIDResolver(Go 接口 → Java 接口),
 * 由 SmartProxyVpnService 在 establish 前注册:Mobile.setUIDResolver(this)。
 *
 * 只支持 API 29+:ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)
 * 四元组(公开 API 只有这一种重载;网上常传的 (protocol, localPort, remotePort)
 * 端口版并不存在——compileSdk 35 编译期实测,传 int×3 会被解析到四元组报类型不匹配)。
 * API 26-28 无 UID 反查通道(/proc/net 不可读),直接返回 -1 放行,不做拦截。
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
        // 只支持 API 29+:老系统无 UID 反查通道(/proc/net 不可读),直接放行不拦。
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return UNKNOWN
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            // 唯一公开重载:四元组 (protocol, local, remote)。
            // local 用 tunnel 分配给应用的 IP+端口(即内核 socket 的源地址)。
            val local = InetSocketAddress(localIP, localPort)
            val remote = InetSocketAddress(remoteIP, remotePort)
            cm.getConnectionOwnerUid(proto, local, remote)
        } catch (e: Exception) {
            Log.w(TAG, "[UIDResolver] resolveUID failed proto=$proto localPort=$localPort: ${e.message}")
            UNKNOWN
        }
    }
}
