package io.github.yiguihai11.smartproxy

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log

/**
 * 国内厂商定制系统（vivo/小米/华为/OPPO等）开机自启动权限管理与跳转引导工具。
 * 国内主流厂商默认对第三方应用强行拦截 BOOT_COMPLETED 广播，需引导用户在系统管家/设置中
 * 将应用加入「允许自启动」白名单。
 */
object AutostartHelper {
    private const val TAG = "AutostartHelper"

    enum class Brand {
        VIVO,
        XIAOMI,
        HUAWEI,
        OPPO,
        SAMSUNG,
        MEIZU,
        OTHER
    }

    val currentBrand: Brand by lazy {
        val m = (Build.MANUFACTURER ?: "").lowercase()
        val b = (Build.BRAND ?: "").lowercase()
        when {
            m.contains("vivo") || m.contains("iqoo") || m.contains("bbk") ||
            b.contains("vivo") || b.contains("iqoo") -> Brand.VIVO

            m.contains("xiaomi") || m.contains("redmi") || m.contains("poco") ||
            b.contains("xiaomi") || b.contains("redmi") || b.contains("poco") -> Brand.XIAOMI

            m.contains("huawei") || m.contains("honor") ||
            b.contains("huawei") || b.contains("honor") -> Brand.HUAWEI

            m.contains("oppo") || m.contains("oneplus") || m.contains("realme") ||
            b.contains("oppo") || b.contains("oneplus") || b.contains("realme") -> Brand.OPPO

            m.contains("samsung") || b.contains("samsung") -> Brand.SAMSUNG

            m.contains("meizu") || b.contains("meizu") -> Brand.MEIZU

            else -> Brand.OTHER
        }
    }

    /**
     * 判断当前机型是否具有严格的开机自启动限制策略。
     * 除了原生 AOSP / Google Pixel 以外，主流定制 ROM 均有强力自启拦截。
     */
    fun isAutostartRestricted(): Boolean = currentBrand != Brand.OTHER

    /**
     * 获取面向用户展示的机型/系统品牌友好名称。
     */
    fun getBrandName(): String {
        return when (currentBrand) {
            Brand.VIVO -> "vivo / iQOO (OriginOS)"
            Brand.XIAOMI -> "小米 / Redmi (MIUI / HyperOS)"
            Brand.HUAWEI -> "华为 / 荣耀 (HarmonyOS / MagicOS)"
            Brand.OPPO -> "OPPO / 一加 / 真我 (ColorOS)"
            Brand.SAMSUNG -> "三星 (One UI)"
            Brand.MEIZU -> "魅族 (Flyme)"
            Brand.OTHER -> Build.MANUFACTURER ?: "Android"
        }
    }

    /**
     * 针对各品牌系统，按优先级尝试拉起系统专用的「自启动管理」界面；
     * 若专用组件失效或改版，兜底拉起「应用详情设置页」。
     *
     * @return true 表示成功唤起某个设置页面；false 表示全部失败
     */
    fun openAutostartSettings(context: Context): Boolean {
        val intents = getCandidateIntents(context)
        for (intent in intents) {
            try {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
                Log.i(TAG, "Successfully started autostart activity: ${intent.component ?: intent.action}")
                return true
            } catch (e: Exception) {
                Log.d(TAG, "Intent failed: ${intent.component ?: intent.action}, trying next...")
            }
        }
        return false
    }

    private fun getCandidateIntents(context: Context): List<Intent> {
        val list = mutableListOf<Intent>()
        val pkg = context.packageName

        when (currentBrand) {
            Brand.VIVO -> {
                // vivo / iQOO: BgStartUpManagerActivity (在 OriginOS 3/4/5 上实测有效)
                list.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")))
                list.add(Intent("com.iqoo.secure.BGSTARTUPMANAGER"))
                list.add(Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")))
                list.add(Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.safeguard.PurviewTabActivity")))
                list.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.PurviewTabActivity")))
            }
            Brand.XIAOMI -> {
                // 小米 / Redmi / POCO 自启动管理
                list.add(Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")))
                list.add(Intent("miui.intent.action.OP_AUTO_START").addCategory(Intent.CATEGORY_DEFAULT))
            }
            Brand.HUAWEI -> {
                // 华为 / 荣耀 应用启动管理
                list.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")))
                list.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")))
                list.add(Intent().setComponent(ComponentName("com.hihonor.systemmanager", "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity")))
                list.add(Intent().setComponent(ComponentName("com.hihonor.systemmanager", "com.hihonor.systemmanager.appcontrol.activity.StartupAppControlActivity")))
            }
            Brand.OPPO -> {
                // OPPO / 一加 / 真我 自启动管理
                list.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")))
                list.add(Intent().setComponent(ComponentName("com.oplus.safecenter", "com.oplus.safecenter.permission.startup.StartupAppListActivity")))
                list.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")))
            }
            Brand.SAMSUNG -> {
                // 三星 电池和设备维护 / 休眠应用
                list.add(Intent().setComponent(ComponentName("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity")))
                list.add(Intent().setComponent(ComponentName("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity")))
                list.add(Intent().setComponent(ComponentName("com.samsung.android.sm", "com.samsung.android.sm.battery.ui.BatteryActivity")))
            }
            Brand.MEIZU -> {
                // 魅族 权限管理
                list.add(Intent().setComponent(ComponentName("com.meizu.safe", "com.meizu.safe.security.SHOW_APPSEC")))
            }
            Brand.OTHER -> {}
        }

        // 通用兜底:系统应用详情设置页
        list.add(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
        return list
    }
}
