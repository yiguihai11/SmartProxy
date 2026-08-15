package io.github.yiguihai11.smartproxy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.util.LruCache
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import java.util.concurrent.ConcurrentHashMap

/**
 * 应用选择页(§5 应用内化)枚举:data class AppInfo 供 Compose 列表直接用。
 *
 * 过滤:只列声明了 INTERNET 权限的应用(没有网络能力的勾了没意义)+ 跳过自身;
 * QUERY_ALL_PACKAGES(manifest)使 API 30+ 能枚举全部已装应用。
 *
 * 线程:list() 在 IO 线程执行(PackageManager 枚举慢);图标解码做了内存缓存
 * (LruCache)防列表滚动反复解码;入口页在 IO 阶段预热图标,主线程只读缓存。
 */
object AppEnumerator {

    private const val INTERNET = "android.permission.INTERNET"

    data class AppInfo(
        val pkg: String,
        val label: String,
        val uid: Int,
        val selected: Boolean,
        val system: Boolean
    )

    /** pkg → 是否有 INTERNET 权限(枚举一次全列表会重复问,缓存避免二次查询)。 */
    private val hasInternetCache = ConcurrentHashMap<String, Boolean>()

    /** pkg → ImageBitmap 图标。上限 64 个,超出逐出最久未用。 */
    private val iconCache = object : LruCache<String, ImageBitmap>(64) {}

    fun list(context: Context): List<AppInfo> {
        val pm = context.packageManager
        val selected = AppPrefs.selectedApps(context)
        val self = context.packageName
        return pm.getInstalledApplications(0)
            .asSequence()
            .filter { it.packageName != self && hasInternet(pm, it.packageName) }
            .map { ai ->
                AppInfo(
                    pkg = ai.packageName,
                    label = pm.getApplicationLabel(ai)?.toString() ?: ai.packageName,
                    uid = ai.uid,
                    selected = selected.contains(ai.packageName),
                    system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .toList()
    }

    private fun hasInternet(pm: PackageManager, pkg: String): Boolean {
        hasInternetCache[pkg]?.let { return it }
        val has = try {
            pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
                ?.requestedPermissions?.contains(INTERNET) == true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
        hasInternetCache[pkg] = has
        return has
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
