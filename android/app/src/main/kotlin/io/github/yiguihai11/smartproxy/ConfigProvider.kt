package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * 引擎运行所需的静态基础设施。
 *
 * - ensureRuntimeFiles:Android 上引擎 cfgDir 为空(`engine.New(cfg, "")`),chnroute/acl
 *   相对路径会解析到 CWD 而找不到 → 引擎启动失败。所以把 chnroute.txt / acl.txt 从 assets
 *   拷到 **cacheDir**(可再生数据:系统可清,每次启动重拷即回;引擎已在启动时载入内存,
 *   运行中被清不影响),配置生成器再把 routing 路径绝对化(见 ConfigGenerator)。
 * - persistConfig:把最终 config.json 落 **filesDir**(持久文件),返回绝对路径。
 *   引擎按路径加载(StartRouter(configPath, fd),与桌面 config.Load 同路),不直接收 JSON 串。
 * - adminPort:面板管理端口单一真源(assets/config.json 的 listen.admin_port)。
 *
 * 整份 config 的产出已移交 ConfigGenerator(M3,§4.6 单一真源)。
 */
object ConfigProvider {

    /** 引擎启动前调用:把路由数据文件就位(拷到 cacheDir)。 */
    fun ensureRuntimeFiles(context: Context) {
        copyAsset(context, "chnroute.txt", context.cacheDir)
        copyAsset(context, "acl.txt", context.cacheDir)
    }

    /** 把最终 config.json 写到 filesDir,返回绝对路径(供 StartRouter 按路径加载)。 */
    fun persistConfig(context: Context, json: String): String {
        val f = File(context.filesDir, "config.json")
        f.writeText(json)
        return f.absolutePath
    }

    /** 面板管理端口:读 assets/config.json 的 listen.admin_port(单一真源)。 */
    fun adminPort(context: Context): Int {
        val raw = context.assets.open("config.json").bufferedReader().use { it.readText() }
        return JSONObject(raw)
            .optJSONObject("listen")
            ?.optInt("admin_port", DEFAULT_ADMIN_PORT) ?: DEFAULT_ADMIN_PORT
    }

    private const val DEFAULT_ADMIN_PORT = 9090

    private fun copyAsset(context: Context, name: String, destDir: File) {
        context.assets.open(name).use { input ->
            File(destDir, name).outputStream().use { output ->
                input.copyTo(output)
            }
        }
    }
}
