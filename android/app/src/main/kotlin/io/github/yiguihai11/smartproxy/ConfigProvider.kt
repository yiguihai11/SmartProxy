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
 *
 * 持久化规则:config.json / acl.txt / chnroute.txt 三者在 filesDir 或 cacheDir 落盘后
 * 均为真源(面板可改、watcher 监控),assets 只在目标「缺失或空」时种入,绝不覆盖已
 * 落盘内容——否则面板编辑会在下次启动/起 VPN 时被默认版冲掉。
 */
object ConfigProvider {

    /** 引擎启动前调用:把路由数据文件就位。面板可经 /acl、/chnroute 编辑(需持久化),
     *  与 config.json 同规则——仅当目标缺失或大小为 0 才从 assets 种入,已有内容不覆盖。
     *  管理员 CA 不在此列:它内嵌在 Go 引擎里(go:embed,Android AAR 与桌面共享同一张),
     *  不再需要 assets 解压。 */
    fun ensureRuntimeFiles(context: Context) {
        copyAssetIfMissing(context, "chnroute.txt", context.cacheDir)
        copyAssetIfMissing(context, "acl.txt", context.cacheDir)
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

    /** IPv4 拦截 = tun.inet4_address 非空数组(空 [] 或缺失都算关)。 */
    fun ipv4(context: Context): Boolean =
        (readConfig(context).optJSONObject("tun")?.optJSONArray("inet4_address")?.length() ?: 0) > 0

    /** IPv6 拦截 = tun.inet6_address 非空数组。 */
    fun ipv6(context: Context): Boolean =
        (readConfig(context).optJSONObject("tun")?.optJSONArray("inet6_address")?.length() ?: 0) > 0

    /** 开关 IPv4 拦截:关写空数组 []、开补默认值(运行中改由调用方重启 VPN)。 */
    fun setIpv4(context: Context, on: Boolean) {
        val json = readConfig(context)
        setAddress(json, "inet4_address", on, DEFAULT_TUN_V4)
        writeConfig(context, json)
    }

    /** 开关 IPv6 拦截:关写空数组 []、开补默认值。 */
    fun setIpv6(context: Context, on: Boolean) {
        val json = readConfig(context)
        setAddress(json, "inet6_address", on, DEFAULT_TUN_V6)
        writeConfig(context, json)
    }

    /** 上游代理节点是否已配置:upstream.proxies 非空(面板经 /config 写它)。首页开启前
     *  检查,无节点时引擎能起但所有流量报 "no default proxy available"(§8 提示去面板配置)。 */
    fun hasUpstreamProxy(context: Context): Boolean {
        val proxies = readConfig(context)
            .optJSONObject("upstream")?.optJSONArray("proxies")
        return proxies != null && proxies.length() > 0
    }

    /** 面板管理端口:读 filesDir/config.json(运行时真源,面板可改、引擎实际绑定它)。
     *  动态跟随面板编辑;首页链接 ON_RESUME 重算即取到最新值。 */
    fun adminPort(context: Context): Int =
        readConfig(context).optJSONObject("listen")
            ?.optInt("admin_port", DEFAULT_ADMIN_PORT) ?: DEFAULT_ADMIN_PORT

    /** 面板是否 HTTPS:读 filesDir/config.json 的 listen.admin_https(默认 true),
     *  首页链接据此决定 http/https 前缀。 */
    fun adminHttps(context: Context): Boolean =
        readConfig(context).optJSONObject("listen")
            ?.optBoolean("admin_https", true) ?: true

    /** 面板管理账号密码:读 listen.admin_auth。未启用 / 无用户名(引擎实际不开 Basic Auth)
     *  返回 null → 面板无需登录,首页不显示账号密码提示。 */
    fun adminAuth(context: Context): Pair<String, String>? {
        val a = readConfig(context).optJSONObject("listen")?.optJSONObject("admin_auth") ?: return null
        if (!a.optBoolean("enabled", true)) return null
        val u = a.optString("username")
        if (u.isBlank()) return null
        return u to a.optString("password")
    }

    // ── 不变量(ensureConfig 每次应用,与 ConfigGenerator 的强制项一致)──────

    private fun applyInvariants(context: Context, base: JSONObject): JSONObject {
        val tun = base.optJSONObject("tun") ?: JSONObject().also { base.put("tun", it) }
        // fd 模式写死(与 mobile/bridge.go 强制一致):引擎从 VpnService.establish 的 fd 读包。
        tun.put("enabled", true)
        tun.put("auto_route", false)
        base.put("tun", tun)

        // routing 文件绝对路径:引擎 cfgDir 为空,相对路径会解析到 CWD 而失败;
        // 放 cacheDir 作持久化(面板可改),ensureRuntimeFiles 仅缺失/空才种入,已落盘保留。
        val routing = base.optJSONObject("routing") ?: JSONObject().also { base.put("routing", it) }
        routing.put("chnroute_file", File(context.cacheDir, "chnroute.txt").absolutePath)
        routing.put("acl_file", File(context.cacheDir, "acl.txt").absolutePath)
        base.put("routing", routing)

        // smartproxy.lan → loopback + 手机局域网 IP(dns.static_records hosts-override)。
        // 首页面板链接用 https://smartproxy.lan:port:VPN 运行时引擎接管手机 DNS,static
        // record 把 smartproxy.lan 解析到手机自己(网络/系统 DNS 不认识该域名)。
        // 记录恒建且 loopback 优先(127.0.0.1/::1):本地浏览器直连 admin,loopback 不进
        // TUN,离线/仅流量也能开面板;LAN IP 排后供其它设备经手机 DNS 解析(纯 DNS 解析,
        // 与证书 SAN 无关,见上)。每次启动用当前 IP 刷新,不保留旧 IP。
        val lanIp = PanelUrl.lanIpv4()
        val dns = base.optJSONObject("dns") ?: JSONObject().also { base.put("dns", it) }
        val records = dns.optJSONArray("static_records")
            ?: JSONArray().also { dns.put("static_records", it) }
        var found = -1
        for (i in 0 until records.length()) {
            if (records.optJSONObject(i)?.optString("host") == "smartproxy.lan") {
                found = i
                break
            }
        }
        val rec = if (found >= 0) records.getJSONObject(found)
        else JSONObject().put("host", "smartproxy.lan").also { records.put(it) }
        val ips = JSONArray().put("127.0.0.1").put("::1")
        lanIp?.let { ips.put(it) }
        rec.put("ip", ips)
        base.put("dns", dns)

        // admin_cert_sans 不再自动追加 LAN IP(用户要求,§8):证书 SAN 保持配置原样
        // (assets 基础 smartproxy.lan + 引擎内置 loopback 127.0.0.1/::1)。换网不触发
        // 重签,持久化证书复用,浏览器只告警一次;局域网面板链接的免告警能力相应取消
        // (PanelUrl socks 模式回退 loopback)。
        return base
    }

    private fun setAddress(json: JSONObject, key: String, on: Boolean, default: String) {
        val tun = json.optJSONObject("tun") ?: JSONObject().also { json.put("tun", it) }
        if (on) {
            // 开:数组非空则保留(面板改过的自定义值),空/缺失才补默认。
            val arr = tun.optJSONArray(key)
            if (arr == null || arr.length() == 0) tun.put(key, JSONArray().put(default))
        } else {
            // 关:写空数组 [] 而非删 key——保留字段让 config.json 自文档化。
            // 删 key 后 Go 侧 nil slice 序列化成 null,编辑 config 的新手看不懂;
            // [] 语义明确(空 = 该族未启用),与引擎 len()==0 行为完全一致。
            tun.put(key, JSONArray())
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

    /** 仅当目标缺失或空才从 assets 拷贝(种子);已落盘内容(含面板改动)保留。 */
    private fun copyAssetIfMissing(context: Context, name: String, destDir: File) {
        val dest = File(destDir, name)
        if (dest.exists() && dest.length() > 0L) return
        copyAsset(context, name, destDir)
    }

    private const val CONFIG_NAME = "config.json"
    private const val DEFAULT_ADMIN_PORT = 9090
    private const val DEFAULT_TUN_V4 = "172.19.0.1/30"
    private const val DEFAULT_TUN_V6 = "fc00::1/64"
}
