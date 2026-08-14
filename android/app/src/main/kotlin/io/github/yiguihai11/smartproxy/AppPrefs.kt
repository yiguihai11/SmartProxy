package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * 首页与面板共用的偏好(§4.4"唯一偏好")。M1 只提供默认值:
 *  - IPv4/IPv6 拦截默认全开(M2 首页开关接管)
 *  - 流量模式默认"仅绕过(global)"(M5 面板接管 + 应用列表)
 *  - DNS 默认 223.5.5.5 / 2400:3200::1(在 config.json 资产里,M5 面板可改)
 */
object AppPrefs {

    private const val NAME = "smartproxy_prefs"
    private const val KEY_IPV4 = "ipv4"
    private const val KEY_IPV6 = "ipv6"
    private const val KEY_GLOBAL_MODE = "global_mode"
    private const val KEY_SELECTED_APPS = "selected_apps"

    private fun sp(context: Context) =
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    fun ipv4(context: Context): Boolean = sp(context).getBoolean(KEY_IPV4, true)
    fun ipv6(context: Context): Boolean = sp(context).getBoolean(KEY_IPV6, true)

    /** true = 仅绕过(黑名单,默认);false = 仅代理(白名单)。 */
    fun globalMode(context: Context): Boolean = sp(context).getBoolean(KEY_GLOBAL_MODE, true)

    /** 勾选的应用包名列表(仅代理=白名单 / 仅绕过=黑名单,语义随模式翻转)。 */
    fun selectedApps(context: Context): Set<String> =
        sp(context).getStringSet(KEY_SELECTED_APPS, emptySet()) ?: emptySet()

    fun setIpv4(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_IPV4, value).apply()
    }

    fun setIpv6(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_IPV6, value).apply()
    }

    fun setGlobalMode(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_GLOBAL_MODE, value).apply()
    }

    fun setSelectedApps(context: Context, apps: Set<String>) {
        sp(context).edit().putStringSet(KEY_SELECTED_APPS, apps).apply()
    }
}
