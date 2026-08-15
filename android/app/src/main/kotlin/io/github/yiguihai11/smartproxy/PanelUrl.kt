package io.github.yiguihai11.smartproxy

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * 管理面板入口 URL(§4.4):https://<手机局域网IP>:admin_port。
 *
 * admin 监听 0.0.0.0 + ::(Go 双栈,常开),手机局域网 IP 就是入口地址。
 * 局域网 IP 变化时首页需刷新 URL 与二维码(§4.4 注意)。
 */
object PanelUrl {

    /** 取第一个 up 且非回环的 site-local IPv4(10/8,172.16/12,192.168/16)。 */
    fun lanIpv4(): String? {
        val ifaces = NetworkInterface.getNetworkInterfaces() ?: return null
        for (iface in ifaces) {
            if (iface.isLoopback || !iface.isUp) continue
            for (addr in iface.inetAddresses) {
                val a = addr as? Inet4Address ?: continue
                if (a.isSiteLocalAddress) return a.hostAddress
            }
        }
        return null
    }

    /** https://<ip>:<port>,拿不到 IP 返回 null(如未连 Wi-Fi)。 */
    fun url(context: Context): String? {
        val ip = lanIpv4() ?: return null
        return "https://$ip:${ConfigProvider.adminPort(context)}"
    }
}
