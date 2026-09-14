package io.github.yiguihai11.smartproxy

import org.json.JSONObject
import java.net.InetAddress

/**
 * 从 config.json 的 tun 段解析出 VpnService.Builder 需要的参数(§4.6)。
 * 单一真源:同一份 config.json 既喂 Builder 又喂 StartRouter。
 *
 * 只解析 Builder 用得到的:mtu / inet4/6_address。DNS 不在此列——tun.dns_servers
 * 已删除(2026-08:死配置,Go 侧运行时零引用),Android 的 addDnsServer 由
 * AppPrefs 自定义 DNS + 硬编码默认决定(§6,见 establishVpn),与 config.json 无关。
 */
data class Cidr(val ip: String, val prefix: Int)

data class TunParams(
    val mtu: Int,
    val inet4: Cidr?,       // tun.address 中的 IPv4 条目,如 "172.19.0.1/30" (兼容旧 inet4_address)
    val inet6: Cidr?,       // tun.address 中的 IPv6 条目,如 "fc00::1/64" (兼容旧 inet6_address)
)

object TunConfig {

    /** 移动端推荐 TUN MTU 设为 1400(预留 80~100 字节代理头与蜂窝链路冗余,防 IP 分片与跳 ping)。 */
    const val DEFAULT_TUN_MTU = 1400

    /** 解析 tun 段。优先解析 address 统一字段,支持双栈;缺省时回退旧 inet4_address / inet6_address。与 internal/config 的 DefaultConfig 对齐。 */
    fun parse(json: JSONObject): TunParams {
        val tun = json.optJSONObject("tun") ?: JSONObject()
        var inet4: Cidr? = null
        var inet6: Cidr? = null

        val addressArr = tun.optJSONArray("address")
        if (addressArr != null) {
            for (i in 0 until addressArr.length()) {
                val str = addressArr.optString(i)
                if (str.isNotBlank()) {
                    val cidr = parseCidr(str)
                    if (cidr.ip.contains(':')) {
                        if (inet6 == null) inet6 = cidr
                    } else {
                        if (inet4 == null) inet4 = cidr
                    }
                }
            }
        } else {
            // 兼容旧字段:空数组([])与缺失等价 = 该族未启用
            inet4 = tun.optJSONArray("inet4_address")?.takeIf { it.length() > 0 }?.let { parseCidr(it.getString(0)) }
            inet6 = tun.optJSONArray("inet6_address")?.takeIf { it.length() > 0 }?.let { parseCidr(it.getString(0)) }
        }

        return TunParams(
            mtu = tun.optInt("mtu", DEFAULT_TUN_MTU),
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
