package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * config.json 文件访问层(§4.6 单一真源)。
 *
 * 纯 Go 面板还原后,config.json 由应用与 Go 面板共同读写、引擎 fsnotify watcher 同步:
 *  - 应用:首页 IPv4/IPv6 拦截开关直接读写 filesDir/config.json(tun.inet4/6_address);
 *  - Go 面板:dashboard.html 经 /config GET/PUT 写同一份文件,watcher 热重载。
 *
 * ensureConfig:每次启动幂等应用「不变量」——routing 文件绝对化到 cacheDir、
 * tun.enabled/auto_route 按 fd 模式写死、admin_cert_sans 追加手机局域网 IP。
 * DNS 保持 assets 硬编码默认(223.5.5.5 / 2400:3200::1),应用内不再提供 DNS 配置 UI。
 */
object ConfigProvider {

    /** 引擎启动前调用:把路由数据文件就位(拷到 cacheDir)。 */
    fun ensureRuntimeFiles(context: Context) {
        copyAsset(context, "chnroute.txt", context.cacheDir)
        copyAsset(context, "acl.txt", context.cacheDir)
    }

    /** 幂等:确保 filesDir/config.json 存在且应用不变量(App 启动 + 引擎启动前都调)。 */
    fun ensureConfig(context: Context) {
        val f = File(context.filesDir, CONFIG_NAME)
        val base = if (f.exists()) {
            JSONObject(f.readText())
        } else {
            JSONObject(readAsset(context, CONFIG_NAME))
        }
        f.writeText(applyInvariants(context, base).toString())
    }

    /** filesDir/config.json 绝对路径(StartRouter 按路径加载,与桌面 config.Load 同路)。 */
    fun configPath(context: Context): String =
        File(context.filesDir, CONFIG_NAME).absolutePath

    /** 读当前 config.json(先 ensure,首页开关初始态用)。 */
    fun readConfig(context: Context): JSONObject {
        ensureConfig(context)
        return JSONObject(File(context.filesDir, CONFIG_NAME).readText())
    }

    /** 写回 config.json(首页开关改 tun 段;不变量已由 ensureConfig 应用,直写即可)。 */
    fun writeConfig(context: Context, json: JSONObject) {
        File(context.filesDir, CONFIG_NAME).writeText(json.toString())
    }

    /** IPv4 拦截 = tun.inet4_address 存在。 */
    fun ipv4(context: Context): Boolean =
        readConfig(context).optJSONObject("tun")?.has("inet4_address") == true

    /** IPv6 拦截 = tun.inet6_address 存在。 */
    fun ipv6(context: Context): Boolean =
        readConfig(context).optJSONObject("tun")?.has("inet6_address") == true

    /** 开关 IPv4 拦截:摘/补 tun.inet4_address(运行中改由调用方重启 VPN)。 */
    fun setIpv4(context: Context, on: Boolean) {
        val json = readConfig(context)
        setAddress(json, "inet4_address", on, DEFAULT_TUN_V4)
        writeConfig(context, json)
    }

    /** 开关 IPv6 拦截:摘/补 tun.inet6_address。 */
    fun setIpv6(context: Context, on: Boolean) {
        val json = readConfig(context)
        setAddress(json, "inet6_address", on, DEFAULT_TUN_V6)
        writeConfig(context, json)
    }

    /** 面板管理端口:读 assets/config.json 的 listen.admin_port(单一真源)。 */
    fun adminPort(context: Context): Int {
        val raw = context.assets.open("config.json").bufferedReader().use { it.readText() }
        return JSONObject(raw)
            .optJSONObject("listen")
            ?.optInt("admin_port", DEFAULT_ADMIN_PORT) ?: DEFAULT_ADMIN_PORT
    }

    // ── 不变量(ensureConfig 每次应用,与 ConfigGenerator 的强制项一致)──────

    private fun applyInvariants(context: Context, base: JSONObject): JSONObject {
        val tun = base.optJSONObject("tun") ?: JSONObject().also { base.put("tun", it) }
        // fd 模式写死(与 mobile/bridge.go 强制一致):引擎从 VpnService.establish 的 fd 读包。
        tun.put("enabled", true)
        tun.put("auto_route", false)
        base.put("tun", tun)

        // routing 文件绝对路径:引擎 cfgDir 为空,相对路径会解析到 CWD 而失败;
        // 路由数据可再生,放 cacheDir(ensureRuntimeFiles 每次启动重拷)。
        val routing = base.optJSONObject("routing") ?: JSONObject().also { base.put("routing", it) }
        routing.put("chnroute_file", File(context.cacheDir, "chnroute.txt").absolutePath)
        routing.put("acl_file", File(context.cacheDir, "acl.txt").absolutePath)
        base.put("routing", routing)

        // admin cert SAN 追加手机局域网 IP,减浏览器警告(证书随 SAN 变化重新自签)。
        val listen = base.optJSONObject("listen") ?: JSONObject().also { base.put("listen", it) }
        val sans = listen.optJSONArray("admin_cert_sans")
            ?: JSONArray().also { listen.put("admin_cert_sans", it) }
        PanelUrl.lanIpv4()?.let { ip ->
            var found = false
            for (i in 0 until sans.length()) {
                if (sans.optString(i) == ip) {
                    found = true
                    break
                }
            }
            if (!found) sans.put(ip)
        }
        base.put("listen", listen)
        return base
    }

    private fun setAddress(json: JSONObject, key: String, on: Boolean, default: String) {
        val tun = json.optJSONObject("tun") ?: JSONObject().also { json.put("tun", it) }
        if (on) {
            if (!tun.has(key)) tun.put(key, JSONArray().put(default))
        } else {
            tun.remove(key)
        }
        json.put("tun", tun)
    }

    private fun readAsset(context: Context, name: String): String =
        context.assets.open(name).bufferedReader().use { it.readText() }

    private fun copyAsset(context: Context, name: String, destDir: File) {
        context.assets.open(name).use { input ->
            File(destDir, name).outputStream().use { output ->
                input.copyTo(output)
            }
        }
    }

    private const val CONFIG_NAME = "config.json"
    private const val DEFAULT_ADMIN_PORT = 9090
    private const val DEFAULT_TUN_V4 = "172.19.0.1/30"
    private const val DEFAULT_TUN_V6 = "fc00::1/64"
}
