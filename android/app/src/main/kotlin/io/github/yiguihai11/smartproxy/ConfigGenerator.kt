package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * 配置生成器(M3,§4.1 / §4.2 / §4.4 / §4.6):
 * AppPrefs(唯一偏好,§4.4)→ 完整的 config.json 单一真源(§4.6)。
 *
 * 同一份产物同时喂 VpnService.Builder 与 StartRouter,两侧同源不可能跑偏:
 *  - §4.1 族过滤:只给开启的族配 TUN 地址(inet4_address / inet6_address)与 DNS 地址;
 *    只开 v4 就不给 engine 配 v6 地址,避免 engine 侧空转。
 *  - §4.2 必配 DNS:tun.dns_servers 取面板可配的 dnsV4/dnsV6(默认 223.5.5.5/2400:3200::1)。
 *  - §4.4 admin:维持资产默认(port 9090 / https / Basic Auth),admin_cert_sans 追加手机
 *    局域网 IP,减浏览器警告。
 *  - 桥接强制项(bridge.go 会强制,这里写实保持一致):tun.enabled=true、auto_route=false。
 *
 * 引擎侧 dns_servers 仅用于 Android addDnsServer 通告(§4.6),族过滤后 index 布局随开关
 * 变化,所以 Builder 的 DNS 直接读 AppPrefs(同源),不依赖 index 约定(见 TunConfig)。
 */
object ConfigGenerator {

    /** 引擎启动前调用:读资产基座配置,叠上 AppPrefs 偏好,返回最终 config.json 串。 */
    fun build(context: Context): String {
        val base = readAsset(context, "config.json")
        val tun = base.optJSONObject("tun") ?: JSONObject().also { base.put("tun", it) }

        val ipv4 = AppPrefs.ipv4(context)
        val ipv6 = AppPrefs.ipv6(context)

        // §4.1 族过滤 TUN 地址:关掉的族摘掉地址,不给 engine 配该族,避免空转。
        if (ipv4) {
            tun.put(
                "inet4_address",
                tun.optJSONArray("inet4_address") ?: JSONArray().put(DEFAULT_TUN_V4)
            )
        } else {
            tun.remove("inet4_address")
        }
        if (ipv6) {
            tun.put(
                "inet6_address",
                tun.optJSONArray("inet6_address") ?: JSONArray().put(DEFAULT_TUN_V6)
            )
        } else {
            tun.remove("inet6_address")
        }

        // §4.2 DNS:只给开启的族配;地址面板可改,默认阿里。
        val dns = JSONArray()
        if (ipv4) dns.put(AppPrefs.dnsV4(context))
        if (ipv6) dns.put(AppPrefs.dnsV6(context))
        tun.put("dns_servers", dns)

        // 桥接强制项写实(与 mobile/bridge.go 强制一致)。
        tun.put("enabled", true)
        tun.put("auto_route", false)
        base.put("tun", tun)

        // routing 文件绝对路径:Android 上引擎 cfgDir 为空,相对路径会解析到 CWD 而失败。
        val routing = base.optJSONObject("routing") ?: JSONObject().also { base.put("routing", it) }
        routing.put("chnroute_file", File(context.filesDir, "chnroute.txt").absolutePath)
        routing.put("acl_file", File(context.filesDir, "acl.txt").absolutePath)
        base.put("routing", routing)

        // §4.4 admin cert SAN 追加手机局域网 IP,减浏览器警告(证书随 SAN 变化重新自签)。
        val listen = base.optJSONObject("listen") ?: JSONObject().also { base.put("listen", it) }
        val sans = listen.optJSONArray("admin_cert_sans")
            ?: JSONArray().also { listen.put("admin_cert_sans", it) }
        PanelUrl.lanIpv4()?.let { ip ->
            var found = false
            for (i in 0 until sans.length()) {
                if (sans.optString(i) == ip) {
                    found = true
                    break
                }
            }
            if (!found) sans.put(ip)
        }
        base.put("listen", listen)

        return base.toString()
    }

    private fun readAsset(context: Context, name: String): JSONObject =
        JSONObject(context.assets.open(name).bufferedReader().use { it.readText() })

    private const val DEFAULT_TUN_V4 = "172.19.0.1/30"
    private const val DEFAULT_TUN_V6 = "fc00::1/64"
}
