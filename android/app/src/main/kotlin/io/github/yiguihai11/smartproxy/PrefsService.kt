package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * M5 偏好读写桥(§4.4"唯一偏好"):面板 GET /api/prefs / POST /api/prefs/set 经它
 * 往返 SharedPreferences。AppPrefs 是全 App 唯一真源,首页开关与面板同写一处。
 *
 * set() 语义:部分字段可缺省(面板每次都整份提交,但防御性支持增量);
 * 返回非空串 = 校验/存储错误(admin 回 400),空串 = 成功。
 */
object PrefsService {

    fun getJson(context: Context): String {
        return JSONObject().apply {
            put("ipv4", AppPrefs.ipv4(context))
            put("ipv6", AppPrefs.ipv6(context))
            put("global_mode", AppPrefs.globalMode(context))
            put("boot_auto_start", AppPrefs.bootAutoStart(context))
            put("dns_v4", AppPrefs.dnsV4(context))
            put("dns_v6", AppPrefs.dnsV6(context))
            put("admin_password", AppPrefs.adminPassword(context))
            put(
                "selected_apps",
                JSONArray().also { arr -> AppPrefs.selectedApps(context).forEach { arr.put(it) } }
            )
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
        val newMode = if (o.has("global_mode")) o.getBoolean("global_mode") else null
        val newApps = if (o.has("selected_apps")) o.getJSONArray("selected_apps") else null

        newDnsV4?.let { if (!isValidIp(it)) return "IPv4 DNS 非法: $it" }
        newDnsV6?.let { if (!isValidIp(it)) return "IPv6 DNS 非法: $it" }
        o.optString("admin_password").let { if (o.has("admin_password") && it.isBlank()) return "管理密码不能为空" }

        if (newMode == false && (newApps?.length() ?: AppPrefs.selectedApps(context).size) == 0) {
            // §8#6:仅代理模式至少要勾 1 个应用,否则全 App 裸奔(全部直连)。
            return "仅代理模式至少勾选 1 个应用"
        }

        newDnsV4?.let { AppPrefs.setDnsV4(context, it) }
        newDnsV6?.let { AppPrefs.setDnsV6(context, it) }
        if (o.has("ipv4")) AppPrefs.setIpv4(context, o.getBoolean("ipv4"))
        if (o.has("ipv6")) AppPrefs.setIpv6(context, o.getBoolean("ipv6"))
        if (o.has("boot_auto_start")) AppPrefs.setBootAutoStart(context, o.getBoolean("boot_auto_start"))
        if (o.has("admin_password")) AppPrefs.setAdminPassword(context, o.getString("admin_password"))
        if (newMode != null) AppPrefs.setGlobalMode(context, newMode)
        if (newApps != null) {
            val set = HashSet<String>()
            for (i in 0 until newApps.length()) set.add(newApps.getString(i))
            AppPrefs.setSelectedApps(context, set)
        }
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
