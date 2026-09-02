package io.github.yiguihai11.smartproxy

import android.content.Context
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * 管理面板入口 URL(§4.4):scheme 跟随 listen.admin_https(默认 https),
 * https://smartproxy.lan:admin_port;admin_https=false 时是 http://。
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

    /** <scheme>://smartproxy.lan:<port>;拿不到/不该给链接时返回 null:
     *  - admin_port 空/0:引擎侧 engine.go 见 AdminPort<=0 且 admin_socket 空就不建
     *    adminServer(面板 HTTP 根本不监听),给链接是死链 → null,首页卡整块不显示;
     *  - VPN 模式未连网/拿不到局域网 IP:static record 无从建立 → null。
     *  scheme 读 admin_https(默认 https)。仅代理(SOCKS5)模式(§8)无 VPN DNS 接管:
     *  smartproxy.lan 手机系统 DNS 解析不了,改用 loopback 127.0.0.1(admin 绑
     *  ":AdminPort",证书内置 SAN 127.0.0.1,本机开面板无告警)。LAN IP 不进证书
     *  (用户取消 SAN 自动追加,§8),不再给局域网设备提供 App 链接;需要者可自行加
     *  admin_cert_sans 或放行自签告警。 */
    fun url(context: Context): String? {
        val port = ConfigProvider.adminPort(context)
        if (port <= 0) return null
        val scheme = if (ConfigProvider.adminHttps(context)) "https" else "http"
        if (AppPrefs.serviceMode(context) == AppPrefs.MODE_SOCKS5) {
            return "$scheme://127.0.0.1:$port"
        }
        if (lanIpv4() == null) return null
        return "$scheme://smartproxy.lan:$port"
    }
}
