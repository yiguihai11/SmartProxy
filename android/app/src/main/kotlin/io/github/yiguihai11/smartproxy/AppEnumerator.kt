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

    /** pkg → ImageBitmap 图标。上限 256 个(覆盖绝大多数已装应用,避免快速滚动抖动淘汰重解)。 */
    private val iconCache = object : LruCache<String, ImageBitmap>(256) {}

    // 进程级应用列表缓存(§5 预加载):进入 App 时后台 load() 填一次,点进应用选择页
    // cached() 直接命中、零等待。权威源永远是 PackageManager——广播收到装/卸事件后
    // invalidate() + 后台 refresh() 重拉;进程被杀缓存随之消失,冷启动重新预加载即最新。
    @Volatile
    private var listCache: List<AppInfo>? = null

    /** 现缓存快照;未预加载过/已被广播失效时为 null(调用方据此决定等不等)。 */
    fun cached(): List<AppInfo>? = listCache

    /** 取列表:有缓存直接返回(秒开),没有则现场拉取并写缓存(冷启动预加载前就点进页面的兜底)。 */
    fun load(context: Context): List<AppInfo> = listCache ?: list(context).also { listCache = it }

    /** 强制权威重拉并替换缓存(装/卸/替换广播后保新鲜)。 */
    fun refresh(context: Context): List<AppInfo> = list(context).also { listCache = it }

    /** 失效缓存(包事件后置 listCache=null;图标缓存不必清——包还在时留着,被卸的包不再查询)。 */
    fun invalidate() {
        listCache = null
    }

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

    /**
     * 后台暖图标:cache 未满时按 list 顺序 decode 至多 budget 个(默认 = 缓存上限),已在
     * 缓存直接跳过不重复解码。跑在 IO 线程、不 gate 任何渲染——首屏常见 app 命中缓存后,
     * 滚动中真正 miss 的图标才在 UI 侧按需 decode。预加载线程 load 后调它把首屏(list 头部)
     * 填进缓存;之后(进程存续 / 再次进入页面)cache 已满,整段跳过,零成本。
     */
    fun warmIcons(context: Context, apps: List<AppInfo>, budget: Int = iconCache.maxSize()) {
        // 缓存已满就整段跳过:继续扫后面的 miss 会 put+逐出最早项,把预加载填的首屏
        // (list 头部)挤掉,反而让首屏主线程 decode。冷启动 cache 空时才会真正填充。
        if (iconCache.size() >= iconCache.maxSize()) return
        var remaining = budget
        for (app in apps) {
            if (remaining <= 0) return
            if (iconCache.get(app.pkg) != null) continue
            iconBitmap(context, app.pkg)
            remaining--
        }
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
