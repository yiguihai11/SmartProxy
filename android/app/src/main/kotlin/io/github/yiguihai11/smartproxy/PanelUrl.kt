package io.github.yiguihai11.smartproxy

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * 管理面板入口 URL(§4.4):scheme 跟随 listen.admin_https(默认 https),
 * - VPN 模式: 始终使用固定域名 smartproxy.lan (VPN 接管手机 DNS 自动解析)。
 * - SOCKS5 模式: 若仅开启 IPv6(v6 单栈)则使用 loopback [::1]，其余情况使用 loopback 127.0.0.1。
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

    /**
     * 计算当前控制面板入口 URL:
     * - VPN 模式: 一律返回 <scheme>://smartproxy.lan:<port>
     * - SOCKS5 模式:
     *     - 仅开启 v6 时返回 <scheme>://[::1]:<port>
     *     - 其余情况(开启 v4 或双栈)返回 <scheme>://127.0.0.1:<port>
     */
    fun url(
        context: Context,
        serviceMode: String = AppPrefs.serviceMode(context),
        socksListen: String = AppPrefs.socksListen(context)
    ): String? {
        val port = ConfigProvider.adminPort(context)
        if (port <= 0) return null
        val scheme = if (ConfigProvider.adminHttps(context)) "https" else "http"
        return if (serviceMode == AppPrefs.MODE_SOCKS5) {
            if (socksListen == AppPrefs.SOCKS_LISTEN_V6) {
                "$scheme://[::1]:$port"
            } else {
                "$scheme://127.0.0.1:$port"
            }
        } else {
            "$scheme://smartproxy.lan:$port"
        }
    }
}
