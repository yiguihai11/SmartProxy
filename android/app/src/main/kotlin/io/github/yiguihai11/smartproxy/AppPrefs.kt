package io.github.yiguihai11.smartproxy

import android.content.Context
import android.content.SharedPreferences

/**
 * App 级偏好(§4.4)。纯 Go 面板还原后,IPv4/IPv6 拦截、DNS、管理密码等配置字段的
 * 唯一真源是 filesDir/config.json(首页开关与 Go 面板共写,见 ConfigProvider);
 * SharedPreferences 保留「引擎/系统之外、纯 App 层」的项目:
 *  - 流量模式(仅绕过/仅代理)+ 应用列表(§5 AppSelectionActivity 读写)
 *  - 开机自启(BootReceiver 消费)
 *  - 自定义启动注入 DNS(IPv4 / IPv6)
 *  - 排除路由列表(excludeRoute, API 33+)
 *  - 服务模式(VPN 隧道 / 仅代理 SOCKS5,§8)
 *  - 电池优化豁免引导计数(仅代理模式后台连通性,§8)
 *  - 仅代理模式 SOCKS5 监听族(§8,listen.host 派生源)
 */
object AppPrefs {

    const val DEFAULT_DNS_V4 = "223.5.5.5"
    const val DEFAULT_DNS_V6 = "2400:3200::1"

    // 悬浮网速计外观默认(与历史硬编码一致):胶囊内边距 6dp、字号 12sp、图标 15dp、
    // 背景不透明 40%。
    const val SPEED_METER_DEFAULT_CAPSULE_SIZE = 6
    const val SPEED_METER_DEFAULT_FONT_SIZE = 12
    const val SPEED_METER_DEFAULT_ICON_SIZE = 15
    const val SPEED_METER_DEFAULT_ALPHA = 40

    // ↑/↓ 指示文字与颜色(颜色存 ARGB Color int,默认沿用历史硬编码的绿/蓝)。
    const val SPEED_METER_DEFAULT_UP_LABEL = "↑"
    const val SPEED_METER_DEFAULT_DOWN_LABEL = "↓"
    // 0xFF.. 字面量超 Int.MAX 是 Long,toInt() 得到合法负 ARGB int(与 Color.parseColor 同值)。
    val SPEED_METER_DEFAULT_UP_COLOR = 0xFF7CCB7C.toInt()
    val SPEED_METER_DEFAULT_DOWN_COLOR = 0xFF6FB7FF.toInt()

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
    private const val KEY_BATTERY_OPT_ASK = "battery_opt_ask_count"
    private const val KEY_SOCKS_LISTEN = "socks_listen"
    private const val KEY_SHIZUKU_SYNC_TOKEN = "shizuku_sync_token"
    private const val KEY_SPEED_METER = "speed_meter_enabled"
    private const val KEY_SPEED_METER_X = "speed_meter_x"
    private const val KEY_SPEED_METER_Y = "speed_meter_y"
    private const val KEY_SPEED_METER_CAPSULE_SIZE = "speed_meter_capsule_size"
    private const val KEY_SPEED_METER_FONT_SIZE = "speed_meter_font_size"
    private const val KEY_SPEED_METER_ICON_SIZE = "speed_meter_icon_size"
    private const val KEY_SPEED_METER_ALPHA = "speed_meter_alpha"
    private const val KEY_SPEED_METER_UP_LABEL = "speed_meter_up_label"
    private const val KEY_SPEED_METER_DOWN_LABEL = "speed_meter_down_label"
    private const val KEY_SPEED_METER_UP_COLOR = "speed_meter_up_color"
    private const val KEY_SPEED_METER_DOWN_COLOR = "speed_meter_down_color"
    private const val KEY_SPEED_METER_SWAP_ORDER = "speed_meter_swap_order"

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
        // HashSet 防御性拷贝:SharedPreferencesImpl 内部直接引用传入的 Set 对象,
        // 若引用未变(如同一实例改写)会导致变更不写盘。
        sp(context).edit().putStringSet(KEY_SELECTED_APPS, HashSet(apps)).apply()
    }

    /** 「禁止联网」拦截的应用包名列表(仅仅绕过/黑名单模式可用,白名单模式 UI 禁用)。
     *  与 selectedApps 互斥(拦截优先);establish 时解析成 UID 写 tun.blocked_uids。 */
    fun blockedApps(context: Context): Set<String> =
        sp(context).getStringSet(KEY_BLOCKED_APPS, emptySet()) ?: emptySet()

    fun setBlockedApps(context: Context, apps: Set<String>) {
        sp(context).edit().putStringSet(KEY_BLOCKED_APPS, HashSet(apps)).apply()
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
        sp(context).edit().putStringSet(KEY_EXCLUDED_ROUTES, HashSet(routes)).apply()
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

    /**
     * 注册 serviceMode 变化回调(UI 把 SharedPreferences 变化接成 Compose state,§8):
     * 侧边栏菜单显示条件、监听开关副标题等直接读 serviceMode 的 UI 依赖它,否则切模式后
     * Compose 不重组,隐藏菜单不恢复、副标题不刷新。返回 () -> Unit 注销函数,配 DisposableEffect。
     */
    fun observeServiceMode(context: Context, onChange: () -> Unit): () -> Unit {
        val sp = sp(context)
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == KEY_SERVICE_MODE) onChange()
        }
        sp.registerOnSharedPreferenceChangeListener(listener)
        return { sp.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    /** 电池优化豁免引导已弹次数:仅代理(SOCKS5)模式后台连通性依赖「忽略电池优化」,
     *  启动时最多引导几次(防误触无限弹);已豁免则不再引导。 */
    fun batteryOptAskCount(context: Context): Int =
        sp(context).getInt(KEY_BATTERY_OPT_ASK, 0)

    fun setBatteryOptAskCount(context: Context, count: Int) {
        sp(context).edit().putInt(KEY_BATTERY_OPT_ASK, count).apply()
    }

    const val SOCKS_LISTEN_BOTH = "both"
    const val SOCKS_LISTEN_V4 = "v4"
    const val SOCKS_LISTEN_V6 = "v6"

    /** 仅代理模式 SOCKS5 监听族(§8,首页 v4/v6 开关):both = "::" 全接口双栈、
     *  v4 = "0.0.0.0"、v6 = "::"(Go net.Listen 对 "::" 默认双栈,仍收 v4-mapped)。
     *  默认 both(保持原行为);config.json 的 listen.host 由它派生(ConfigProvider 不变量)。 */
    fun socksListen(context: Context): String =
        sp(context).getString(KEY_SOCKS_LISTEN, SOCKS_LISTEN_BOTH) ?: SOCKS_LISTEN_BOTH

    fun setSocksListen(context: Context, mode: String) {
        sp(context).edit().putString(KEY_SOCKS_LISTEN, mode).apply()
    }

    /** Shizuku 网络共享同步 Token */
    fun shizukuSyncToken(context: Context): String =
        sp(context).getString(KEY_SHIZUKU_SYNC_TOKEN, "") ?: ""

    fun setShizukuSyncToken(context: Context, token: String) {
        sp(context).edit().putString(KEY_SHIZUKU_SYNC_TOKEN, token).apply()
    }

    /** 悬浮网速计开关(塞班式角落胶囊,仅 VPN 隧道模式有按应用统计可显示)。默认关。 */
    fun speedMeterEnabled(context: Context): Boolean =
        sp(context).getBoolean(KEY_SPEED_METER, false)

    fun setSpeedMeterEnabled(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_SPEED_METER, value).apply()
    }

    /** 胶囊上次拖动后的位置(相对屏幕左上,TYPE_APPLICATION_OVERLAY + TOP|START gravity)。
     *  -1 = 未设置,首次显示放到右上角。 */
    fun speedMeterPos(context: Context): Pair<Int, Int> {
        val p = sp(context)
        return Pair(p.getInt(KEY_SPEED_METER_X, -1), p.getInt(KEY_SPEED_METER_Y, -1))
    }

    fun setSpeedMeterPos(context: Context, x: Int, y: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_X, x).putInt(KEY_SPEED_METER_Y, y).apply()
    }

    // ── 悬浮网速计外观(长按设置对话框读写,见 SpeedMeterSettingsActivity)──────
    /** 胶囊内边距(dp)。范围 2..20,默认 6。 */
    fun speedMeterCapsuleSize(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_CAPSULE_SIZE, SPEED_METER_DEFAULT_CAPSULE_SIZE)

    fun setSpeedMeterCapsuleSize(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_CAPSULE_SIZE, value).apply()
    }

    /** 上行/下行字号(sp)。范围 8..24,默认 12。 */
    fun speedMeterFontSize(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_FONT_SIZE, SPEED_METER_DEFAULT_FONT_SIZE)

    fun setSpeedMeterFontSize(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_FONT_SIZE, value).apply()
    }

    /** App 图标尺寸(dp)。范围 8..32,默认 15。 */
    fun speedMeterIconSize(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_ICON_SIZE, SPEED_METER_DEFAULT_ICON_SIZE)

    fun setSpeedMeterIconSize(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_ICON_SIZE, value).apply()
    }

    /** 胶囊背景不透明度(0..100)。默认 40(历史硬编码 0x66 = 40%)。 */
    fun speedMeterAlpha(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_ALPHA, SPEED_METER_DEFAULT_ALPHA)

    fun setSpeedMeterAlpha(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_ALPHA, value).apply()
    }

    // ── ↑/↓ 指示文字与颜色 ──────────────────────────────────────────────
    /** 上行指示文字(拼在网速前的标签前缀,如 "↑ 123K/s")。默认 "↑"。 */
    fun speedMeterUpLabel(context: Context): String =
        sp(context).getString(KEY_SPEED_METER_UP_LABEL, SPEED_METER_DEFAULT_UP_LABEL)
            ?: SPEED_METER_DEFAULT_UP_LABEL

    fun setSpeedMeterUpLabel(context: Context, value: String) {
        sp(context).edit().putString(KEY_SPEED_METER_UP_LABEL, value).apply()
    }

    /** 下行指示文字。默认 "↓"。 */
    fun speedMeterDownLabel(context: Context): String =
        sp(context).getString(KEY_SPEED_METER_DOWN_LABEL, SPEED_METER_DEFAULT_DOWN_LABEL)
            ?: SPEED_METER_DEFAULT_DOWN_LABEL

    fun setSpeedMeterDownLabel(context: Context, value: String) {
        sp(context).edit().putString(KEY_SPEED_METER_DOWN_LABEL, value).apply()
    }

    /** 上行文字颜色(ARGB Color int)。默认历史绿 #FF7CCB7C。 */
    fun speedMeterUpColor(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_UP_COLOR, SPEED_METER_DEFAULT_UP_COLOR)

    fun setSpeedMeterUpColor(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_UP_COLOR, value).apply()
    }

    /** 下行文字颜色。默认历史蓝 #FF6FB7FF。 */
    fun speedMeterDownColor(context: Context): Int =
        sp(context).getInt(KEY_SPEED_METER_DOWN_COLOR, SPEED_METER_DEFAULT_DOWN_COLOR)

    fun setSpeedMeterDownColor(context: Context, value: Int) {
        sp(context).edit().putInt(KEY_SPEED_METER_DOWN_COLOR, value).apply()
    }

    /** 调换 ↑/↓ 显示左右位:false = [icon, ↑, ↓](上行在左,历史布局);true = [icon, ↓, ↑]。默认 false。 */
    fun speedMeterSwapOrder(context: Context): Boolean =
        sp(context).getBoolean(KEY_SPEED_METER_SWAP_ORDER, false)

    fun setSpeedMeterSwapOrder(context: Context, value: Boolean) {
        sp(context).edit().putBoolean(KEY_SPEED_METER_SWAP_ORDER, value).apply()
    }
}

