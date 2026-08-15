package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * 引擎运行所需的静态基础设施。
 *
 * - ensureRuntimeFiles:Android 上引擎 cfgDir 为空(`engine.New(cfg, "")`),chnroute/acl
 *   相对路径会解析到 CWD 而找不到 → 引擎启动失败。所以这里把 chnroute.txt / acl.txt 从
 *   assets 拷到 filesDir,配置生成器再把 routing 路径绝对化(见 ConfigGenerator)。
 * - adminPort:面板管理端口单一真源(assets/config.json 的 listen.admin_port)。
 *
 * 整份 config 的产出已移交 ConfigGenerator(M3,§4.6 单一真源)。
 */
object ConfigProvider {

    /** 引擎启动前调用:把路由数据文件就位。 */
    fun ensureRuntimeFiles(context: Context) {
        copyAsset(context, "chnroute.txt", context.filesDir)
        copyAsset(context, "acl.txt", context.filesDir)
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
