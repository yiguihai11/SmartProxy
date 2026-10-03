package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

data class NetworkAddressStatus(
    val hasV4: Boolean,
    val hasV6: Boolean
) {
    val isAnyAvailable: Boolean get() = hasV4 || hasV6
}

/**
 * 一条底层链路的能力快照。抽成纯数据是为了让筛选规则能脱离 Android 框架单测
 * (本模块没有 Robolectric)。
 */
internal data class UnderlayCapabilities(
    val isVpn: Boolean,
    val isNotVpn: Boolean,
    val isIms: Boolean,
    val hasInternet: Boolean,
    val isCellular: Boolean,
)

/**
 * 是否是可用于承载代理流量的底层链路。
 *
 * requireInternet=true:只认有 INTERNET 能力的网络。
 * requireInternet=false:额外放行离线局域网(例如没有外网的 Wi-Fi),但蜂窝必须有 INTERNET。
 *
 * IMS/VoLTE PDN 显式排除:关掉移动数据后它仍然在线(`MOBILE[NR] ... extra: ims`),还带一个
 * 全局 IPv6 地址,但没有 INTERNET、承载不了任何业务流量。旧版兜底分支只判「非 VPN」,于是
 * WiFi + 移动数据全关时它会把 hasV6 点亮 —— v4 因 IMS 无 IPv4 而正常置灰,现象因此不对称。
 */
internal fun UnderlayCapabilities.isDataBearingUnderlay(requireInternet: Boolean): Boolean {
    if (isVpn || !isNotVpn) return false
    if (isIms) return false
    if (hasInternet) return true
    if (requireInternet) return false
    // 没有 INTERNET 的蜂窝网络就是 IMS,不能承载流量;非蜂窝(离线 Wi-Fi/以太网)放行。
    return !isCellular
}

private fun NetworkCapabilities.toUnderlayCapabilities() = UnderlayCapabilities(
    isVpn = hasTransport(NetworkCapabilities.TRANSPORT_VPN),
    isNotVpn = hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
    isIms = hasCapability(NetworkCapabilities.NET_CAPABILITY_IMS) ||
        hasCapability(NetworkCapabilities.NET_CAPABILITY_MMTEL) ||
        hasCapability(NetworkCapabilities.NET_CAPABILITY_EIMS),
    hasInternet = hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
    isCellular = hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
)

private fun InetAddress.isUsableUnicast(): Boolean =
    !isLoopbackAddress && !isLinkLocalAddress && !isAnyLocalAddress && !isMulticastAddress

object NetworkUtils {
    /**
     * 检查当前底层物理网络（排除 VPN）是否分配了有效的 IPv4 和 IPv6 地址。
     * 优先匹配具备 NET_CAPABILITY_INTERNET 且非 VPN 的活跃网络（Wi-Fi、蜂窝移动网络、以太网）。
     * 若未匹配到，再宽松扫描非蜂窝的非 VPN 链路兜底（如本地局域网无外网 Wi-Fi）。
     */
    @Suppress("DEPRECATION")
    fun checkPhysicalNetworkAddresses(context: Context): NetworkAddressStatus {
        var hasV4 = false
        var hasV6 = false
        runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return@runCatching
            val networks = cm.allNetworks

            fun scan(requireInternet: Boolean) {
                for (net in networks) {
                    val caps = cm.getNetworkCapabilities(net) ?: continue
                    if (!caps.toUnderlayCapabilities().isDataBearingUnderlay(requireInternet)) continue

                    val lp = cm.getLinkProperties(net) ?: continue
                    for (linkAddr in lp.linkAddresses) {
                        val addr = linkAddr.address
                        if (addr is Inet4Address && addr.isUsableUnicast()) {
                            hasV4 = true
                        } else if (addr is Inet6Address && addr.isUsableUnicast()) {
                            hasV6 = true
                        }
                    }
                }
            }

            // 1. 优先扫描具备 NET_CAPABILITY_INTERNET 的非 VPN 网络
            scan(requireInternet = true)
            // 2. 兜底扫描:若无互联网能力网络(例如离线局域网 Wi-Fi),允许非蜂窝物理网卡
            if (!hasV4 && !hasV6) scan(requireInternet = false)
        }
        return NetworkAddressStatus(hasV4, hasV6)
    }
}
