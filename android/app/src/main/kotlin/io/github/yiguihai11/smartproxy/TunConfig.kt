package io.github.yiguihai11.smartproxy

import org.json.JSONObject
import java.net.InetAddress

/**
 * 从 config.json 的 tun 段解析出 VpnService.Builder 需要的地址参数(§4.6)。
 * 单一真源:同一份 config.json 既喂 Builder 又喂 StartRouter。
 *
 * DNS(addDnsServer)不在这里解析:配置生成器对 dns_servers 做了族过滤(§4.1),单族开启时
 * index 0=v4 / index 1=v6 的定死约定(§4.6)不成立,Builder 直接读唯一偏好
 * AppPrefs.dnsV4/dnsV6(与生成器同源),不依赖 index,避免越界。
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
        val inet4 = tun.optJSONArray("inet4_address")?.let { parseCidr(it.getString(0)) }
        val inet6 = tun.optJSONArray("inet6_address")?.let { parseCidr(it.getString(0)) }
        return TunParams(
            mtu = tun.optInt("mtu", 1500),
            inet4 = inet4,
            inet6 = inet6
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
