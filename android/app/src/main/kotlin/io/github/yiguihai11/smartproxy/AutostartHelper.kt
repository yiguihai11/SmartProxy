package io.github.yiguihai11.smartproxy

import android.app.AppOpsManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.util.Log

/**
 * 国内厂商定制系统（vivo/小米/华为/OPPO等）开机自启动权限管理、机型检测与跳转引导工具。
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
     * 尝试根据机型检测自启动权限当前是否处于「允许」状态。
     * @return true: 已允许自启动
     *         false: 明确被禁止自启动
     *         null: 无法获取（厂商未对第三方公开只读权限，或非支持机型）
     */
    fun checkAutostartPermission(context: Context): Boolean? {
        when (currentBrand) {
            Brand.XIAOMI -> {
                // 小米 MIUI / HyperOS 私有 AppOps: OP_AUTO_START (10008)
                try {
                    val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
                    val checkOpMethod = appOps.javaClass.getMethod(
                        "checkOpNoThrow",
                        Int::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        String::class.java
                    )
                    val mode = checkOpMethod.invoke(appOps, 10008, Process.myUid(), context.packageName) as Int
                    return mode == AppOpsManager.MODE_ALLOWED
                } catch (e: Exception) {
                    Log.d(TAG, "checkXiaomiAutostart failed: ${e.message}")
                }
            }
            Brand.VIVO -> {
                // vivo OriginOS: 尝试读取系统 bg_start_up_apps 表
                try {
                    val uri = Uri.parse("content://com.vivo.permissionmanager.provider.permission/bg_start_up_apps")
                    val cursor = context.contentResolver.query(
                        uri,
                        arrayOf("currentstate"),
                        "pkgname = ?",
                        arrayOf(context.packageName),
                        null
                    )
                    cursor?.use {
                        if (it.moveToFirst()) {
                            val stateIdx = it.getColumnIndex("currentstate")
                            if (stateIdx >= 0) {
                                val state = it.getInt(stateIdx)
                                return state == 0
                            }
                        }
                    }
                } catch (e: Exception) {
                    // 若无读取权限抛出 SecurityException，安全回退
                    Log.d(TAG, "checkVivoAutostart via provider not permitted: ${e.message}")
                }
            }
            Brand.OTHER -> {
                // 原生 AOSP 只要清单声明了 RECEIVE_BOOT_COMPLETED 即可收到开机广播
                return true
            }
            else -> {}
        }
        return null
    }

    /**
     * 针对各品牌系统，按优先级尝试拉起系统专用的「自启动管理」界面；
     * 并在 Intent 中注入定位与筛选参数（如 :settings:fragment_args_key 等），
     * 使支持自动定位的厂商系统（如 vivo OriginOS、小米等）能自动滚动并高亮至本应用；
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
        val appName = runCatching {
            val appInfo = context.packageManager.getApplicationInfo(pkg, 0)
            context.packageManager.getApplicationLabel(appInfo).toString()
        }.getOrDefault("SmartProxy")

        // 给每个 Intent 注入目标包名与高亮参数，让支持的系统（如 vivo PurviewFragment、小米等）能自动滑动至本应用
        fun Intent.attachTargetExtras(): Intent {
            putExtra(":settings:fragment_args_key", pkg)
            putExtra("package_name", pkg)
            putExtra("packageName", pkg)
            putExtra("package", pkg)
            putExtra("pkgname", pkg)
            putExtra("extra_pkgname", pkg)
            putExtra("app_package", pkg)
            putExtra("app_name", appName)
            putExtra("uid", Process.myUid())
            data = Uri.parse("package:$pkg")
            return this
        }

        when (currentBrand) {
            Brand.VIVO -> {
                // vivo / iQOO: BgStartUpManagerActivity
                // OriginOS 的 PurviewFragment 内部支持读取 :settings:fragment_args_key 并执行 scrollToPosition(pos)
                list.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")).attachTargetExtras())
                list.add(Intent("com.iqoo.secure.BGSTARTUPMANAGER").attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.safeguard.PurviewTabActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.PurviewTabActivity")).attachTargetExtras())
            }
            Brand.XIAOMI -> {
                // 小米 / Redmi / POCO 自启动管理
                list.add(Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")).attachTargetExtras())
                list.add(Intent("miui.intent.action.OP_AUTO_START").addCategory(Intent.CATEGORY_DEFAULT).attachTargetExtras())
            }
            Brand.HUAWEI -> {
                // 华为 / 荣耀 应用启动管理
                list.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.hihonor.systemmanager", "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.hihonor.systemmanager", "com.hihonor.systemmanager.appcontrol.activity.StartupAppControlActivity")).attachTargetExtras())
            }
            Brand.OPPO -> {
                // OPPO / 一加 / 真我 自启动管理
                list.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.oplus.safecenter", "com.oplus.safecenter.permission.startup.StartupAppListActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")).attachTargetExtras())
            }
            Brand.SAMSUNG -> {
                // 三星 电池和设备维护 / 休眠应用
                list.add(Intent().setComponent(ComponentName("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.BatteryActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity")).attachTargetExtras())
                list.add(Intent().setComponent(ComponentName("com.samsung.android.sm", "com.samsung.android.sm.battery.ui.BatteryActivity")).attachTargetExtras())
            }
            Brand.MEIZU -> {
                // 魅族 权限管理
                list.add(Intent().setComponent(ComponentName("com.meizu.safe", "com.meizu.safe.security.SHOW_APPSEC")).attachTargetExtras())
            }
            Brand.OTHER -> {}
        }

        // 通用兜底:系统应用详情设置页（包含单应用完整权限与耗电管理）
        list.add(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
        return list
    }
}
