package io.github.yiguihai11.smartproxy

import android.content.Context

/**
 * App 级偏好(§4.4)。纯 Go 面板还原后,IPv4/IPv6 拦截、DNS、管理密码等配置字段的
 * 唯一真源是 filesDir/config.json(首页开关与 Go 面板共写,见 ConfigProvider);
 * SharedPreferences 只保留「引擎/系统之外、纯 App 层」的三项:
 *  - 流量模式(仅绕过/仅代理)+ 应用列表(§5 AppSelectionActivity 读写)
 *  - 开机自启(BootReceiver 消费)
 */
object AppPrefs {

    private const val NAME = "smartproxy_prefs"
    private const val KEY_GLOBAL_MODE = "global_mode"
    private const val KEY_SELECTED_APPS = "selected_apps"
    private const val KEY_BOOT_AUTO_START = "boot_auto_start"

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
}
