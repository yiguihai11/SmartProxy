package io.github.yiguihai11.smartproxy

import org.json.JSONObject
import java.net.InetAddress

/**
 * 从 config.json 的 tun 段解析出 VpnService.Builder 需要的参数(§4.6)。
 * 单一真源:同一份 config.json 既喂 Builder 又喂 StartRouter。
 *
 * DNS 走 tun.dns_servers 固定双元素索引契约(index 0 = IPv4 / index 1 = IPv6,
 * 见 Go 侧 internal/config/config.go TUNConfig.DNSServers 注释):config.json 是唯一
 * 真源后不再族过滤 dns_servers(旧 ConfigGenerator 单族开启时过滤导致 index 布局
 * 漂移),首页 IPv4/IPv6 开关只增删 inet4/6_address,不碰 dns_servers。
 */
data class Cidr(val ip: String, val prefix: Int)

data class TunParams(
    val mtu: Int,
    val inet4: Cidr?,       // tun.inet4_address[0],如 "172.19.0.1/30"
    val inet6: Cidr?,       // tun.inet6_address[0],如 "fc00::1/64"
    val dnsV4: String?,     // tun.dns_servers[0],如 "223.5.5.5";缺省 null(调用方回退硬编码默认)
    val dnsV6: String?,     // tun.dns_servers[1],如 "2400:3200::1"
)

object TunConfig {

    /** 解析 tun 段。缺字段时回退到引擎默认值,与 internal/config 的 DefaultConfig 对齐。 */
    fun parse(json: JSONObject): TunParams {
        val tun = json.optJSONObject("tun") ?: JSONObject()
        val dns = tun.optJSONArray("dns_servers")
        return TunParams(
            mtu = tun.optInt("mtu", 1500),
            inet4 = tun.optJSONArray("inet4_address")?.let { parseCidr(it.getString(0)) },
            inet6 = tun.optJSONArray("inet6_address")?.let { parseCidr(it.getString(0)) },
            dnsV4 = dns?.takeIf { it.length() > 0 }?.getString(0),
            dnsV6 = dns?.takeIf { it.length() > 1 }?.getString(1)
        )
    }

    /** "172.19.0.1/30" → Cidr("172.19.0.1", 30)。缺 / 前缀时按地址族默认。 */
    fun parseCidr(value: String): Cidr {
        val slash = value.indexOf('/')
        val ip = if (slash >= 0) value.substring(0, slash) else value
        val prefix = (if (slash >= 0) value.substring(slash + 1).toIntOrNull() else null)
            ?: defaultPrefix(ip)
        return Cidr(ip, prefix)
    }

    private fun defaultPrefix(ip: String): Int {
        val addr = try {
            InetAddress.getByName(ip)
        } catch (e: Exception) {
            return 32
        }
        return if (addr.address.size == 4) 32 else 128
    }
}
