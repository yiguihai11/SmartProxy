package io.github.yiguihai11.smartproxy

import org.json.JSONObject
import java.net.InetAddress

/**
 * 从 config.json 的 tun 段解析出 VpnService.Builder 需要的参数(§4.6)。
 * 单一真源:同一份 config.json 既喂 Builder 又喂 StartRouter。
 */
data class Cidr(val ip: String, val prefix: Int)

data class TunParams(
    val mtu: Int,
    val inet4: Cidr?,       // tun.inet4_address[0],如 "172.19.0.1/30"
    val inet6: Cidr?,       // tun.inet6_address[0],如 "fc00::1/64"
    val dnsV4: String,      // tun.dns_servers[0],默认 223.5.5.5
    val dnsV6: String,      // tun.dns_servers[1],默认 2400:3200::1
)

object TunConfig {

    /** 解析 tun 段。缺字段时回退到引擎默认值,与 internal/config 的 DefaultConfig 对齐。 */
    fun parse(json: JSONObject): TunParams {
        val tun = json.optJSONObject("tun") ?: JSONObject()
        val inet4 = tun.optJSONArray("inet4_address")?.let { parseCidr(it.getString(0)) }
        val inet6 = tun.optJSONArray("inet6_address")?.let { parseCidr(it.getString(0)) }
        val dns = tun.optJSONArray("dns_servers")
        // 注意 optString(idx) 对越界返回 ""(不是 null),所以要先过滤空串再回退默认,
        // 否则 addDnsServer("") 会让 Builder.establish() 抛异常。
        return TunParams(
            mtu = tun.optInt("mtu", 1500),
            inet4 = inet4,
            inet6 = inet6,
            dnsV4 = dns?.optString(0)?.takeIf { it.isNotEmpty() } ?: "223.5.5.5",
            dnsV6 = dns?.optString(1)?.takeIf { it.isNotEmpty() } ?: "2400:3200::1",
        )
    }

    /** "172.19.0.1/30" → Cidr("172.19.0.1", 30)。缺 / 前缀时按地址族默认。 */
    fun parseCidr(value: String): Cidr {
        val slash = value.indexOf('/')
        val ip = if (slash >= 0) value.substring(0, slash) else value
        val prefix = if (slash >= 0) value.substring(slash + 1).toIntOrNull() else null
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
