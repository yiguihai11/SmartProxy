package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONObject

/**
 * M5 偏好读写桥(§4.4"唯一偏好"):面板 GET /api/prefs / POST /api/prefs/set 经它
 * 往返 SharedPreferences。AppPrefs 是全 App 唯一真源,首页开关与面板同写一处。
 *
 * §5 应用内化后,流量模式 + 应用列表已移出面板(仅 App 内 AppSelectionActivity
 * 读写),此桥只处理面板仍管的 DNS / v4 / v6 / 开机自启 / 管理密码。
 *
 * set() 语义:部分字段可缺省(面板每次都整份提交,但防御性支持增量);
 * 返回非空串 = 校验/存储错误(admin 回 400),空串 = 成功。
 */
object PrefsService {

    fun getJson(context: Context): String {
        return JSONObject().apply {
            put("ipv4", AppPrefs.ipv4(context))
            put("ipv6", AppPrefs.ipv6(context))
            put("boot_auto_start", AppPrefs.bootAutoStart(context))
            put("dns_v4", AppPrefs.dnsV4(context))
            put("dns_v6", AppPrefs.dnsV6(context))
            put("admin_password", AppPrefs.adminPassword(context))
        }.toString()
    }

    fun set(context: Context, json: String): String {
        val o = try {
            JSONObject(json)
        } catch (e: Exception) {
            return "JSON 解析失败: ${e.message}"
        }

        // 先全部解析校验,最后统一写:任何一步失败都不落盘,避免改一半。
        val newDnsV4 = if (o.has("dns_v4")) o.getString("dns_v4").trim() else null
        val newDnsV6 = if (o.has("dns_v6")) o.getString("dns_v6").trim() else null

        newDnsV4?.let { if (!isValidIp(it)) return "IPv4 DNS 非法: $it" }
        newDnsV6?.let { if (!isValidIp(it)) return "IPv6 DNS 非法: $it" }
        o.optString("admin_password").let { if (o.has("admin_password") && it.isBlank()) return "管理密码不能为空" }

        newDnsV4?.let { AppPrefs.setDnsV4(context, it) }
        newDnsV6?.let { AppPrefs.setDnsV6(context, it) }
        if (o.has("ipv4")) AppPrefs.setIpv4(context, o.getBoolean("ipv4"))
        if (o.has("ipv6")) AppPrefs.setIpv6(context, o.getBoolean("ipv6"))
        if (o.has("boot_auto_start")) AppPrefs.setBootAutoStart(context, o.getBoolean("boot_auto_start"))
        if (o.has("admin_password")) AppPrefs.setAdminPassword(context, o.getString("admin_password"))
        return ""
    }

    /** 面板可配的 DNS 合法性校验(不全靠浏览器端):IPv4 4 段 0-255,IPv6 含冒号、仅十六进制。 */
    fun isValidIp(s: String): Boolean {
        if (s.isEmpty() || s.any { it.isWhitespace() }) return false
        if (s.contains(":")) {
            // 兼容 v4-mapped (::ffff:1.2.3.4),允许点分四段。
            return s.all { it.isDigit() || it in "abcdefABCDEF:." }
        }
        val parts = s.split(".")
        if (parts.size != 4) return false
        return parts.all { p ->
            p.isNotEmpty() && p.all { it.isDigit() } && p.toIntOrNull()?.let { it in 0..255 } == true
        }
    }
}
