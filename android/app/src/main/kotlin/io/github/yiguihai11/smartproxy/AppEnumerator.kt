package io.github.yiguihai11.smartproxy

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.util.LruCache
import androidx.core.graphics.drawable.toBitmap
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * M5 应用枚举(§5)。Get /api/apps → JSON:
 *   {"mode": bool, "apps":[{pkg,label,uid,selected,system}]}
 * mode = 流量模式(global_mode),供面板翻转角标语义(仅代理=绿 / 已排除=红)。
 *
 * 过滤:只列声明了 INTERNET 权限的应用(没有网络能力的勾了没意义)+ 跳过自身;
 * QUERY_ALL_PACKAGES(manifest)使 API 30+ 能枚举全部已装应用。
 *
 * 线程:方法被 Go 回调线程调用(PackageManager/SharedPreferences 读是线程安全的),
 * 权限判断与图标结果做了内存缓存(LruCache / ConcurrentHashMap)防面板刷新打爆 I/O。
 */
object AppEnumerator {

    private const val INTERNET = "android.permission.INTERNET"

    /** pkg → 是否有 INTERNET 权限(枚举一次全列表会重复问,缓存避免二次查询)。 */
    private val hasInternetCache = ConcurrentHashMap<String, Boolean>()

    /** pkg → PNG 字节。上限 2MB,超出逐出最久未用;图标尺寸小,足够存全部。 */
    private val iconCache = object : LruCache<String, ByteArray>(2 * 1024 * 1024) {
        override fun sizeOf(key: String, value: ByteArray): Int = value.size
    }

    fun listJson(context: Context): String {
        val pm = context.packageManager
        val selected = AppPrefs.selectedApps(context)
        val self = context.packageName
        val apps = pm.getInstalledApplications(0)
            .asSequence()
            .filter { it.packageName != self && hasInternet(pm, it.packageName) }
            .map { ai ->
                JSONObject().apply {
                    put("pkg", ai.packageName)
                    put("label", pm.getApplicationLabel(ai)?.toString() ?: ai.packageName)
                    put("uid", ai.uid)
                    put("selected", selected.contains(ai.packageName))
                    put("system", (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0)
                }
            }
            .toList()
        return JSONObject().apply {
            put("mode", AppPrefs.globalMode(context))
            put("apps", JSONArray().also { arr -> apps.forEach { arr.put(it) } })
        }.toString()
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

    /** 应用图标 PNG;不存在/解析失败返回空(admin 侧据此回 404,面板隐藏图标位)。 */
    fun iconPng(context: Context, pkg: String): ByteArray {
        iconCache.get(pkg)?.let { return it }
        val bytes = try {
            val icon = context.packageManager.getApplicationIcon(pkg)
            val bmp = icon.toBitmap()
            val out = ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        } catch (_: Exception) {
            ByteArray(0)
        }
        if (bytes.isNotEmpty()) iconCache.put(pkg, bytes)
        return bytes
    }
}
