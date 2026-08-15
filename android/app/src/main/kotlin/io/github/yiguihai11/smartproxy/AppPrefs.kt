package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * 首页与面板共用的偏好(§4.4"唯一偏好")。M1 只提供默认值:
 *  - IPv4/IPv6 拦截默认全开(M2 首页开关接管)
 *  - 流量模式默认"仅绕过(global)"(M5 应用内 AppSelectionActivity 接管 + 应用列表)
 *  - DNS 默认 223.5.5.5 / 2400:3200::1(M3 配置生成器读取,M5 面板可改)
 */
object AppPrefs {

    private const val NAME = "smartproxy_prefs"
    private const val KEY_IPV4 = "ipv4"
    private const val KEY_IPV6 = "ipv6"
    private const val KEY_GLOBAL_MODE = "global_mode"
    private const val KEY_SELECTED_APPS = "selected_apps"
    private const val KEY_BOOT_AUTO_START = "boot_auto_start"
    private const val KEY_DNS_V4 = "dns_v4"
    private const val KEY_DNS_V6 = "dns_v6"
    private const val KEY_ADMIN_PASSWORD = "admin_password"
    private const val DEFAULT_DNS_V4 = "223.5.5.5"
    private const val DEFAULT_DNS_V6 = "2400:3200::1"
    private const val DEFAULT_ADMIN_PASSWORD = "smartproxy"

    private fun sp(context: Context) =
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    fun ipv4(context: Context): Boolean = sp(context).getBoolean(KEY_IPV4, true)
    fun ipv6(context: Context): Boolean = sp(context).getBoolean(KEY_IPV6, true)

    /** true = 仅绕过(黑名单,默认);false = 仅代理(白名单)。 */
    fun globalMode(context: Context): Boolean = sp(context).getBoolean(KEY_GLOBAL_MODE, true)

    /** 勾选的应用包名列表(仅代理=白名单 / 仅绕过=黑名单,语义随模式翻转)。 */
    fun selectedApps(context: Context): Set<String> =
        sp(context).getStringSet(KEY_SELECTED_APPS, emptySet()) ?: emptySet()

    /** 开机自启(§4.3):默认关,用户主动开启;BootReceiver 只在开启时起服务。 */
    fun bootAutoStart(context: Context): Boolean =
        sp(context).getBoolean(KEY_BOOT_AUTO_START, false)

    fun setBootAutoStart(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_BOOT_AUTO_START, value).apply()
    }

    fun setIpv4(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_IPV4, value).apply()
    }

    fun setIpv6(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_IPV6, value).apply()
    }

    /** §4.2 DNS(面板可改,默认阿里 223.5.5.5):喂 addDnsServer 与生成器 dns_servers。 */
    fun dnsV4(context: Context): String = sp(context).getString(KEY_DNS_V4, DEFAULT_DNS_V4)!!

    /** §4.2 DNS v6(面板可改,默认阿里 2400:3200::1)。 */
    fun dnsV6(context: Context): String = sp(context).getString(KEY_DNS_V6, DEFAULT_DNS_V6)!!

    fun setDnsV4(context: Context, value: String) {
        sp(context).edit().putString(KEY_DNS_V4, value).apply()
    }

    fun setDnsV6(context: Context, value: String) {
        sp(context).edit().putString(KEY_DNS_V6, value).apply()
    }

    fun setGlobalMode(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_GLOBAL_MODE, value).apply()
    }

    fun setSelectedApps(context: Context, apps: Set<String>) {
        sp(context).edit().putStringSet(KEY_SELECTED_APPS, apps).apply()
    }

    /** M5:面板管理密码(默认 smartproxy,与资产 config 一致)。保存后随 VPN 重启生效。 */
    fun adminPassword(context: Context): String =
        sp(context).getString(KEY_ADMIN_PASSWORD, DEFAULT_ADMIN_PASSWORD)!!

    fun setAdminPassword(context: Context, value: String) {
        sp(context).edit().putString(KEY_ADMIN_PASSWORD, value).apply()
    }
}
