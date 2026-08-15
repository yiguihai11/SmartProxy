package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * 提供引擎运行的 config.json。
 *
 * Android 上引擎的 cfgDir 为空(`engine.New(cfg, "")`),chnroute/acl 相对路径会解析到
 * CWD 而找不到 → 引擎启动失败。所以这里把 chnroute.txt / acl.txt 从 assets 拷到
 * filesDir,并把 config.json 的 routing 路径改成绝对路径后再交给 StartRouter。
 */
object ConfigProvider {

    /** 引擎启动前调用:把路由数据文件就位。M3 配置生成器会接管整份 config 的产出。 */
    fun ensureRuntimeFiles(context: Context) {
        copyAsset(context, "chnroute.txt", context.filesDir)
        copyAsset(context, "acl.txt", context.filesDir)
    }

    /** 读取 assets/config.json,把 routing 文件路径绝对化,返回最终 JSON 串。 */
    fun loadConfig(context: Context): String {
        val raw = context.assets.open("config.json").bufferedReader().use { it.readText() }
        val json = JSONObject(raw)
        val routing = json.optJSONObject("routing") ?: JSONObject().also { json.put("routing", it) }
        routing.put("chnroute_file", File(context.filesDir, "chnroute.txt").absolutePath)
        routing.put("acl_file", File(context.filesDir, "acl.txt").absolutePath)
        return json.toString()
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
