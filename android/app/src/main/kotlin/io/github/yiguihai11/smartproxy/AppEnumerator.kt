package io.github.yiguihai11.smartproxy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap

/**
 * 应用选择页(§5 应用内化)枚举:data class AppInfo 供 Compose 列表直接用。
 *
 * 过滤:只跳过自身,**不**按 INTERNET 权限砍。原因——① 共享 uid(sharedUserId)的
 * 应用联网能力按 uid 授予,同 uid 任一包声明 INTERNET 即整 uid 有网,只看本包
 * requestedPermissions 会把这类(多为系统/GMS 组件)误杀,造成"列表遗漏";
 * ② per-app 代理/绕过/拦截要的是完整清单让用户自己勾,对齐 v2rayNG、MT 管理器的
 * 全量枚举。系统/用户靠 FLAG_SYSTEM 区分,UI 上分 tab(全部/用户/系统)。
 * QUERY_ALL_PACKAGES(manifest)使 API 30+ 能枚举全部已装应用。
 *
 * 线程:list() 在 IO 线程执行(PackageManager 枚举慢);图标解码做了内存缓存
 * (LruCache)防列表滚动反复解码;入口页在 IO 阶段预热图标,主线程只读缓存。
 */
object AppEnumerator {

    data class AppInfo(
        val pkg: String,
        val label: String,
        val uid: Int,
        val selected: Boolean,
        val system: Boolean
    )

    /** pkg → ImageBitmap 图标。上限 64 个,超出逐出最久未用。 */
    private val iconCache = object : LruCache<String, ImageBitmap>(64) {}

    fun list(context: Context): List<AppInfo> {
        val pm = context.packageManager
        val selected = AppPrefs.selectedApps(context)
        val self = context.packageName
        return pm.getInstalledApplications(0)
            .asSequence()
            .filter { it.packageName != self }
            .map { ai ->
                AppInfo(
                    pkg = ai.packageName,
                    label = pm.getApplicationLabel(ai).toString(),
                    uid = ai.uid,
                    selected = selected.contains(ai.packageName),
                    system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .toList()
    }

    /** 应用图标(96px);解析失败返回 null(UI 显示占位)。缓存防重复解码。 */
    fun iconBitmap(context: Context, pkg: String): ImageBitmap? {
        iconCache.get(pkg)?.let { return it }
        val bmp = try {
            val icon: Drawable = context.packageManager.getApplicationIcon(pkg)
            icon.toBitmap(96, 96).asImageBitmap()
        } catch (_: Exception) {
            null
        }
        if (bmp != null) iconCache.put(pkg, bmp)
        return bmp
    }
}
