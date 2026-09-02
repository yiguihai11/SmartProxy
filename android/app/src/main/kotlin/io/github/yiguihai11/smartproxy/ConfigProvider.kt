package io.github.yiguihai11.smartproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * config.json 文件访问层(§4.6 单一真源)。
 *
 * 纯 Go 面板还原后,config.json 由应用与 Go 面板共同读写、引擎 fsnotify watcher 同步:
 *  - 应用:首页 IPv4/IPv6 拦截开关(VPN 模式)直接读写 filesDir/config.json
 *    (tun.inet4/6_address);仅代理模式 SOCKS5 监听族是 App 层设置(socksListen),
 *    由 applyInvariants 派生 listen.host,面板不看到该开关;
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

    /**
     * 幂等:确保 filesDir/config.json 存在且应用不变量(App 启动 + 引擎启动前都调)。
     * 比较后写:内容不变则不动文件,避免每次调用都触发 fsnotify 热重载风暴
     * (报告 P0#5)。config.json 损坏时回退 assets 默认再落盘,保证不因坏配置
     * 闪退(P0#8)。
     */
    fun ensureConfig(context: Context) {
        val f = File(context.filesDir, CONFIG_NAME)
        if (!f.exists()) {
            atomicWriteText(f, freshSeed(context))
            return
        }
        val text = runCatching { f.readText() }.getOrDefault("")
        val parsed = runCatching { JSONObject(text) }.getOrNull()
        if (parsed == null) {
            // 损坏:回退 assets 默认重新落盘(同样走 freshSeed,出厂随机面板密码)。
            atomicWriteText(f, freshSeed(context))
            return
        }
        val out = applyInvariants(context, parsed).toString()
        if (out != text) atomicWriteText(f, out)
    }

    /** 从 assets 种一份全新 config:应用不变量,再把出厂写死的面板密码换成每装随机值。
     *  assets 里 admin/smartproxy 全网通用、等于没密码;首页面板卡回显真实凭据且可复制,
     *  用户在自己手机上看得到,局域网别人猜不到。只在「全新播种/损坏重建」时跑,
     *  绝不动已存在的用户配置(老升级、面板改过密码都不碰)。 */
    private fun freshSeed(context: Context): String {
        val json = applyInvariants(context, JSONObject(readAsset(context, CONFIG_NAME)))
        json.optJSONObject("listen")?.optJSONObject("admin_auth")
            ?.takeIf { it.optBoolean("enabled", false) }
            ?.put("password", randomAdminPassword())
        return json.toString()
    }

    /** 15 字节 SecureRandom → URL-safe Base64 无填充(约 20 字符,~120 bit 熵)。
     *  字母表 URL-safe 且无 +/= ,面板 Basic Auth 输入、二维码都不踩特殊字符坑。 */
    private fun randomAdminPassword(): String {
        val bytes = ByteArray(15)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(
            bytes,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING
        )
    }

    /** filesDir/config.json 绝对路径(StartRouter 按路径加载,与桌面 config.Load 同路)。 */
    fun configPath(context: Context): String =
        File(context.filesDir, CONFIG_NAME).absolutePath

    /** 只读快照,不 ensure 不写盘(getter 专用):文件缺失/损坏返回 null,由调用方回退默认。 */
    private fun readRaw(context: Context): JSONObject? {
        val f = File(context.filesDir, CONFIG_NAME)
        if (!f.exists()) return null
        return runCatching { JSONObject(f.readText()) }.getOrNull()
    }

    /** 读当前 config.json(先 ensure,首页开关写入前用——这是唯一会写盘的读取路径)。 */
    fun readConfig(context: Context): JSONObject {
        ensureConfig(context)
        return readRaw(context) ?: JSONObject(readAsset(context, CONFIG_NAME))
    }

    /** 写回 config.json(首页开关改 tun 段;不变量已由 ensureConfig 应用,直写即可)。
     *  原子写:临时文件 + rename,与 Go 面板 admin.go 的 atomicWriteFile 同一策略,
     *  避免写一半被杀/磁盘满时留下撕裂文件让下次启动闪退(P1#16/P0#8)。 */
    fun writeConfig(context: Context, json: JSONObject) {
        atomicWriteText(File(context.filesDir, CONFIG_NAME), json.toString())
    }

    /** IPv4 拦截 = tun.inet4_address 非空数组(空 [] 或缺失都算关)。只读,不触发写盘。 */
    fun ipv4(context: Context): Boolean =
        (readRaw(context)?.optJSONObject("tun")?.optJSONArray("inet4_address")?.length() ?: 0) > 0

    /** IPv6 拦截 = tun.inet6_address 非空数组。只读,不触发写盘。 */
    fun ipv6(context: Context): Boolean =
        (readRaw(context)?.optJSONObject("tun")?.optJSONArray("inet6_address")?.length() ?: 0) > 0

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
        val proxies = readRaw(context)
            ?.optJSONObject("upstream")?.optJSONArray("proxies")
        return proxies != null && proxies.length() > 0
    }

    /** 面板管理端口:读 filesDir/config.json(运行时真源,面板可改、引擎实际绑定它)。
     *  动态跟随面板编辑;首页链接 ON_RESUME 重算即取到最新值。只读,不触发写盘。 */
    fun adminPort(context: Context): Int =
        readRaw(context)?.optJSONObject("listen")
            ?.optInt("admin_port", DEFAULT_ADMIN_PORT) ?: DEFAULT_ADMIN_PORT

    /** 写 tun.blocked_uids(「禁止联网」应用 UID,仅绕过/黑名单模式):establish 前写入,
     *  引擎 StartRouter 读同一份 config.json(经 engine.SetUIDResolver 反查连接 UID,命中即拦)。
     *  空列表写 [] 自文档化(与 setIpv4 的 [] 语义一致);watch 未启动时写入不触发热重载,
     *  运行中的变更随下次连接生效。 */
    fun setBlockedUids(context: Context, uids: List<Int>) {
        val json = readConfig(context)
        val tun = json.optJSONObject("tun") ?: JSONObject().also { json.put("tun", it) }
        tun.put("blocked_uids", JSONArray(uids))
        json.put("tun", tun)
        writeConfig(context, json)
    }

    /** 面板是否 HTTPS:读 filesDir/config.json 的 listen.admin_https(默认 true),
     *  首页链接据此决定 http/https 前缀。只读,不触发写盘。 */
    fun adminHttps(context: Context): Boolean =
        readRaw(context)?.optJSONObject("listen")
            ?.optBoolean("admin_https", true) ?: true

    /** 面板管理账号密码:读 listen.admin_auth。未启用 / 无用户名(引擎实际不开 Basic Auth)
     *  返回 null → 面板无需登录,首页不显示账号密码提示。只读,不触发写盘。 */
    fun adminAuth(context: Context): Pair<String, String>? {
        val a = readRaw(context)?.optJSONObject("listen")?.optJSONObject("admin_auth") ?: return null
        if (!a.optBoolean("enabled", true)) return null
        val u = a.optString("username")
        if (u.isBlank()) return null
        return u to a.optString("password")
    }

    // ── 不变量(ensureConfig 每次应用,与 ConfigGenerator 的强制项一致)──────

    private fun applyInvariants(context: Context, base: JSONObject): JSONObject {
        val tun = base.optJSONObject("tun") ?: JSONObject().also { base.put("tun", it) }
        // tun.enabled 如实反映服务模式(与 mobile/bridge.go 的 tunEnabled 入参一致):
        // VPN 隧道=true;仅代理(SOCKS5)=false。bridge StartRouter 入参会再覆盖一次,
        // 但 config.json 应说真话 —— 否则仅代理模式下文件里躺着 true,watcher 热重载后
        // eng.Config.TUN.Enabled 撒谎(ReloadConfig 只 Store 不读,暂时无害,但是脏的)。
        tun.put("enabled", AppPrefs.serviceMode(context) == AppPrefs.MODE_VPN)
        tun.put("auto_route", false)
        base.put("tun", tun)

        // 仅代理(SOCKS5)模式:listen.host 由 AppPrefs.socksListen 派生(首页 v4/v6
        // 监听开关,§8)——双开/只 v6 = "::"、只 v4 = "0.0.0.0"。VPN 模式不动:
        // 隧道走 fd,listen.port 由 bridge 归零,SOCKS 不暴露,host 无意义。
        if (AppPrefs.serviceMode(context) == AppPrefs.MODE_SOCKS5) {
            val listen = base.optJSONObject("listen") ?: JSONObject().also { base.put("listen", it) }
            listen.put("host", if (AppPrefs.socksListen(context) == AppPrefs.SOCKS_LISTEN_V4) "0.0.0.0" else "::")
            base.put("listen", listen)
        }

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

    /** 原子写:写同目录临时文件再 rename(同文件系统原子替换)。rename 极端失败时退回
     *  直写兜底,并清掉残留临时文件,避免下次读到半截文件。 */
    private fun atomicWriteText(f: File, text: String) {
        val tmp = File(f.parentFile, f.name + ".tmp")
        try {
            tmp.writeText(text)
            if (tmp.renameTo(f)) return
            // rename 失败(跨挂载点/被占用等):退回直写,尽力保证可用
            f.writeText(text)
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private const val CONFIG_NAME = "config.json"
    private const val DEFAULT_ADMIN_PORT = 9090
    private const val DEFAULT_TUN_V4 = "172.19.0.1/30"
    private const val DEFAULT_TUN_V6 = "fc00::1/64"
}
