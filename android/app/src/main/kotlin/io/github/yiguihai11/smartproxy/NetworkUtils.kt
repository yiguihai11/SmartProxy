package io.github.yiguihai11.smartproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.Inet6Address

data class NetworkAddressStatus(
    val hasV4: Boolean,
    val hasV6: Boolean
) {
    val isAnyAvailable: Boolean get() = hasV4 || hasV6
}

object NetworkUtils {
    /**
     * 检查当前底层物理网络（排除 VPN）是否分配了有效的 IPv4 和 IPv6 地址。
     * 优先匹配具备 NET_CAPABILITY_INTERNET 且非 VPN 的活跃网络（Wi-Fi、蜂窝移动网络、以太网）。
     * 若未匹配到，再宽松扫描所有非 VPN 链路兜底（如本地局域网无外网 Wi-Fi）。
     */
    @Suppress("DEPRECATION")
    fun checkPhysicalNetworkAddresses(context: Context): NetworkAddressStatus {
        var hasV4 = false
        var hasV6 = false
        runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return@runCatching
            val networks = cm.allNetworks

            // 1. 优先扫描具备 NET_CAPABILITY_INTERNET 的非 VPN 网络
            for (net in networks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue

                val lp = cm.getLinkProperties(net) ?: continue
                for (linkAddr in lp.linkAddresses) {
                    val addr = linkAddr.address
                    if (addr is Inet4Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress && !addr.isAnyLocalAddress) {
                        hasV4 = true
                    } else if (addr is Inet6Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress && !addr.isAnyLocalAddress && !addr.isMulticastAddress) {
                        hasV6 = true
                    }
                }
            }

            // 2. 兜底扫描:若无互联网能力网络(例如离线局域网 Wi-Fi),允许任意非 VPN 物理网卡
            if (!hasV4 && !hasV6) {
                for (net in networks) {
                    val caps = cm.getNetworkCapabilities(net) ?: continue
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                    if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue

                    val lp = cm.getLinkProperties(net) ?: continue
                    for (linkAddr in lp.linkAddresses) {
                        val addr = linkAddr.address
                        if (addr is Inet4Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress && !addr.isAnyLocalAddress) {
                            hasV4 = true
                        } else if (addr is Inet6Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress && !addr.isAnyLocalAddress && !addr.isMulticastAddress) {
                            hasV6 = true
                        }
                    }
                }
            }
        }
        return NetworkAddressStatus(hasV4, hasV6)
    }
}
