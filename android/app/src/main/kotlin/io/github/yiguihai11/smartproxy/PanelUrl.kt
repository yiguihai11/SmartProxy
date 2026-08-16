package io.github.yiguihai11.smartproxy

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * 管理面板入口 URL(§4.4):https://smartproxy.lan:admin_port。
 *
 * 用固定域名 smartproxy.lan 而非原始局域网 IP:
 *  - 证书 admin_cert_sans 含它 → 手机浏览器打开无证书告警,换网 IP 变、域名不变;
 *  - VPN 运行时引擎接管手机 DNS,dns.static_records 把 smartproxy.lan 解析到手机
 *    自己(ConfigProvider 不变量每次启动刷新 IP),域名不依赖当前 IP。
 * 拿不到局域网 IP 返回 null(如未连 Wi-Fi)——static record 无从建立,链接不可用。
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

    /** https://smartproxy.lan:<port>;未连网/拿不到局域网 IP 返回 null。
     *  仅代理(SOCKS5)模式(§8)无 VPN DNS 接管:smartproxy.lan 手机系统 DNS 解析不了,
     *  回退 127.0.0.1(admin 绑 ":AdminPort",证书内置 SAN 127.0.0.1,本机可开面板)。 */
    fun url(context: Context): String? {
        if (AppPrefs.serviceMode(context) == AppPrefs.MODE_SOCKS5) {
            return "https://127.0.0.1:${ConfigProvider.adminPort(context)}"
        }
        if (lanIpv4() == null) return null
        return "https://smartproxy.lan:${ConfigProvider.adminPort(context)}"
    }
}
