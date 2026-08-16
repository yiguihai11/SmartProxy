package io.github.yiguihai11.smartproxy

import org.json.JSONObject
import java.net.InetAddress

/**
 * 从 config.json 的 tun 段解析出 VpnService.Builder 需要的参数(§4.6)。
 * 单一真源:同一份 config.json 既喂 Builder 又喂 StartRouter。
 *
 * 只解析 Builder 用得到的:mtu / inet4/6_address。DNS 不在此列——tun.dns_servers
 * 引擎不消费(Go 侧只有校验和 DefaultConfig 默认值,运行时零引用),Android 的
 * addDnsServer 由 AppPrefs 自定义 DNS + 硬编码默认决定(§6,见 establishVpn),
 * 与 config.json 无关。
 */
data class Cidr(val ip: String, val prefix: Int)

data class TunParams(
    val mtu: Int,
    val inet4: Cidr?,       // tun.inet4_address[0],如 "172.19.0.1/30"
    val inet6: Cidr?,       // tun.inet6_address[0],如 "fc00::1/64"
)

object TunConfig {

    /** 解析 tun 段。缺字段时回退到引擎默认值,与 internal/config 的 DefaultConfig 对齐。 */
    fun parse(json: JSONObject): TunParams {
        val tun = json.optJSONObject("tun") ?: JSONObject()
        return TunParams(
            mtu = tun.optInt("mtu", 1500),
            inet4 = tun.optJSONArray("inet4_address")?.let { parseCidr(it.getString(0)) },
            inet6 = tun.optJSONArray("inet6_address")?.let { parseCidr(it.getString(0)) }
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
