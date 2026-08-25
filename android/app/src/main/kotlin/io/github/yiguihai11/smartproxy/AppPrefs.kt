package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * App 级偏好(§4.4)。纯 Go 面板还原后,IPv4/IPv6 拦截、DNS、管理密码等配置字段的
 * 唯一真源是 filesDir/config.json(首页开关与 Go 面板共写,见 ConfigProvider);
 * SharedPreferences 保留「引擎/系统之外、纯 App 层」的项目:
 *  - 流量模式(仅绕过/仅代理)+ 应用列表(§5 AppSelectionActivity 读写)
 *  - 开机自启(BootReceiver 消费)
 *  - 自定义启动注入 DNS(IPv4 / IPv6)
 *  - 排除路由列表(excludeRoute, API 33+)
 *  - 服务模式(VPN 隧道 / 仅代理 SOCKS5,§8)
 */
object AppPrefs {

    const val DEFAULT_DNS_V4 = "223.5.5.5"
    const val DEFAULT_DNS_V6 = "2400:3200::1"

    private const val NAME = "smartproxy_prefs"
    private const val KEY_GLOBAL_MODE = "global_mode"
    private const val KEY_SELECTED_APPS = "selected_apps"
    private const val KEY_BLOCKED_APPS = "blocked_apps"
    private const val KEY_BOOT_AUTO_START = "boot_auto_start"
    private const val KEY_DNS_V4 = "custom_dns_v4"
    private const val KEY_DNS_V6 = "custom_dns_v6"
    private const val KEY_EXCLUDED_ROUTES = "excluded_routes"
    private const val KEY_THEME_MODE = "theme_mode"
    private const val KEY_SERVICE_MODE = "service_mode"

    private fun sp(context: Context) =
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

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

    fun setGlobalMode(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_GLOBAL_MODE, value).apply()
    }

    fun setSelectedApps(context: Context, apps: Set<String>) {
        sp(context).edit().putStringSet(KEY_SELECTED_APPS, apps).apply()
    }

    /** 「禁止联网」拦截的应用包名列表(仅仅绕过/黑名单模式可用,白名单模式 UI 禁用)。
     *  与 selectedApps 互斥(拦截优先);establish 时解析成 UID 写 tun.blocked_uids。 */
    fun blockedApps(context: Context): Set<String> =
        sp(context).getStringSet(KEY_BLOCKED_APPS, emptySet()) ?: emptySet()

    fun setBlockedApps(context: Context, apps: Set<String>) {
        sp(context).edit().putStringSet(KEY_BLOCKED_APPS, apps).apply()
    }

    /** 启动注入的 IPv4 DNS 服务器(默认 223.5.5.5)。 */
    fun dnsV4(context: Context): String =
        sp(context).getString(KEY_DNS_V4, DEFAULT_DNS_V4)?.takeIf { it.isNotBlank() } ?: DEFAULT_DNS_V4

    fun setDnsV4(context: Context, value: String) {
        sp(context).edit().putString(KEY_DNS_V4, value.trim()).apply()
    }

    /** 启动注入的 IPv6 DNS 服务器(默认 2400:3200::1)。 */
    fun dnsV6(context: Context): String =
        sp(context).getString(KEY_DNS_V6, DEFAULT_DNS_V6)?.takeIf { it.isNotBlank() } ?: DEFAULT_DNS_V6

    fun setDnsV6(context: Context, value: String) {
        sp(context).edit().putString(KEY_DNS_V6, value.trim()).apply()
    }

    /** 排除路由 CIDR 列表(API 33+ builder.excludeRoute 使用)。 */
    fun excludedRoutes(context: Context): Set<String> =
        sp(context).getStringSet(KEY_EXCLUDED_ROUTES, emptySet()) ?: emptySet()

    fun setExcludedRoutes(context: Context, routes: Set<String>) {
        sp(context).edit().putStringSet(KEY_EXCLUDED_ROUTES, routes).apply()
    }

    /** 主题模式:auto = 跟随系统(深色/浅色),light / dark = 手动锁定。默认 auto。 */
    const val THEME_AUTO = "auto"
    const val THEME_LIGHT = "light"
    const val THEME_DARK = "dark"

    fun themeMode(context: Context): String =
        sp(context).getString(KEY_THEME_MODE, THEME_AUTO) ?: THEME_AUTO

    fun setThemeMode(context: Context, mode: String) {
        sp(context).edit().putString(KEY_THEME_MODE, mode).apply()
    }

    /** 服务模式(§8):vpn = VPN 隧道(默认);socks5 = 仅代理,不启动 VPN 模式,
     *  仅跑引擎 SOCKS5(:1080,全接口双栈)。 */
    const val MODE_VPN = "vpn"
    const val MODE_SOCKS5 = "socks5"

    fun serviceMode(context: Context): String =
        sp(context).getString(KEY_SERVICE_MODE, MODE_VPN) ?: MODE_VPN

    fun setServiceMode(context: Context, mode: String) {
        sp(context).edit().putString(KEY_SERVICE_MODE, mode).apply()
    }
}

