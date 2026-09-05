package admin

// Panel i18n — dashboard.html. English is the canonical source language; the zh
// variant is pre-built once at init by flipping <html lang> and injecting a boot
// <script> into <head> that installs:
//
//	SP_LANG      "zh"
//	SP_I18N      exact whole-text-node / placeholder / title / aria-label dict
//	             (both lookup key and node text are whitespace-normalised)
//	SP_I18N_PRE  leading-label prefix dict for "Error: <backend msg>" style
//	             concatenated text nodes (longest prefix first)
//	SP_I18N_HTML whole-subtree innerHTML swaps for <p data-i18n="marker"> whose
//	             Chinese word order would be mangled by per-text-node translation
//
// Front-end translation is runtime-only over the DOM (never touches source text);
// native alert()/confirm() are intercepted in zh mode and run the same three
// lookups. Templates with placeholders are wrapped at their call site as
// tf('k {0} …', [..]) where t()/tf() live in a small static <head> boot script
// (identity when no dict is installed, i.e. on English requests).

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"golang.org/x/text/language"
)

// zhStrings — exact English -> Simplified Chinese. Keys with "{n}" are tf()
// templates resolved in JS; they need not appear verbatim in dashboard.html.
var zhStrings = map[string]string{
	// nav sections + view titles
	"Monitoring": "监控", "Overview": "总览", "Traffic": "流量",
	"Network": "网络", "Proxies": "代理", "Security": "安全",
	"Blacklist": "黑名单", "System": "系统", "Logs": "日志",
	"DNS Cache": "DNS 缓存", "TLS Cert": "TLS 证书", "Config": "配置",
	"DNS": "DNS", "Configuration": "配置", "TLS Certificate": "TLS 证书",
	"Live": "实时",

	// header buttons / status words
	"Auto": "自动", "Paused": "已暂停", "Auto Refresh": "自动刷新",
	"Auto-scroll: ON": "自动滚动：开", "Auto-scroll: OFF": "自动滚动：关",
	"Clear": "清空", "Clear Terminal": "清空终端", "Export": "导出",
	"Apply": "应用", "Delete": "删除", "Edit": "编辑", "Reset": "重置",
	"Upload": "上传", "Save": "保存", "Saved": "已保存",
	"Saving...": "保存中…", "Adding...": "添加中…", "Pinning...": "固定中…",
	"Cancel": "取消", "Close": "关闭", "Add": "添加", "Add Proxy": "添加代理",
	"+ Add Proxy": "+ 添加代理", "+ Add": "+ 添加", "Edit Proxy": "编辑代理", "Prev": "上一页",
	"Next": "下一页", "Loading...": "加载中…", "Confirm": "确认",
	"Copy": "复制", "Copied!": "已复制！", "Copy failed": "复制失败",
	"Show": "显示", "Hide": "隐藏", "Parse": "解析", "Scan QR": "扫描二维码",
	"Share link": "分享链接", "QR code": "二维码", "Save QR": "保存二维码",
	"Select File": "选择文件", "New File": "新建文件",
	"Download admin.crt": "下载 admin.crt",

	// empty / info states / filter values
	"No entries": "无记录", "No static records": "暂无静态记录",
	"No logs available": "暂无日志",
	"0 selected":        "已选 0 项", "0 entries": "0 条",
	"All": "全部", "Block": "屏蔽", "Allow": "放行", "Proxy": "代理",
	"Direct": "直连",

	// health banner
	"All proxy nodes are unavailable — proxied internet is down": "所有代理节点不可用，经代理的联网已中断",
	"Click to view node status →":                                "点击查看节点状态 →",
	"Restore nodes":                                              "一键恢复节点",

	// dashboard cards + traffic table + chart
	"Uptime": "运行时长", "Goroutines": "协程数", "Memory": "内存",
	"CPU": "CPU", "GC": "GC", "Pause": "GC 停顿", "Count": "次数",
	"Total Traffic": "总流量", "Route Table": "路由表",
	"Direction": "方向", "Up": "上行", "Down": "下行", "Total": "合计",
	"TCP Proxy": "TCP 代理", "TCP Direct": "TCP 直连",
	"UDP Proxy": "UDP 代理", "UDP Direct": "UDP 直连",

	// table headers / dialog labels
	"Type": "类型", "Host": "主机", "Port": "端口", "Reason": "原因",
	"Expires": "到期", "Domain": "域名", "Answers": "应答（当前）",
	"Addresses": "地址", "Action": "动作", "Upstream": "上游",

	// section meta / config hint
	"Edits upstream.proxies in config": "修改的是 config 中的 upstream.proxies",
	"Cache":                            "缓存", "Static Records": "静态记录",

	// proxy card mode / capability / circuit-state labels (values t()'d at render)
	"off": "关闭", "tcp_and_udp": "TCP+UDP", "tcp_only": "仅 TCP",
	"udp_only": "仅 UDP", "raw": "原生", "standard": "标准",
	"manual": "手动", "unknown": "未知",
	"up": "连通", "down": "断开", "half": "恢复中", "n/a": "不支持",

	// proxy cards — buttons / tooltips / badges
	"Disable": "停用", "Enable": "启用",
	"Click to toggle TCP":                           "点击切换 TCP",
	"Click to toggle UDP":                           "点击切换 UDP",
	"TCP manually up — click to restore auto":       "TCP 手动开启 — 点击恢复自动",
	"TCP manually down — click to force up":         "TCP 手动关闭 — 点击强制开启",
	"UDP manually up — click to restore auto":       "UDP 手动开启 — 点击恢复自动",
	"UDP manually down — click to force up":         "UDP 手动关闭 — 点击强制开启",
	"Copy the ss:// share link or show its QR code": "复制 ss:// 分享链接或查看二维码",

	// theme
	"Light": "浅色", "Dark": "深色",
	"Follow system theme — click to switch": "跟随系统深浅色，点击切换",
	"Click to switch theme":                 "点击切换主题",
	"Toggle theme":                          "切换主题",
	"Switch panel language":                 "切换面板语言",
	"Toggle menu":                           "切换菜单",
	"Close menu":                            "关闭菜单",
	"Go to Proxies":                         "前往代理",
	"Built-in root CA & CA-signed leaf":     "内置根 CA 与 CA 签发的叶子证书",
	"Download the current filtered host list as a gfwlist (one host per line)": "将当前过滤后的主机列表导出为 gfwlist（每行一个主机）",

	// dialogs
	"Pin DNS Answer":                "固定 DNS 应答",
	"Answers (current)":             "应答（当前）",
	"New Address(es)":               "新地址",
	"Pin as static record":          "固定为静态记录",
	"Add Static Record":             "添加静态记录",
	"Edit Static Record":            "编辑静态记录",
	"Add ACL Rule":                  "添加 ACL 规则",
	"IP Address(es)":                "IP 地址",
	"Click to pin as static record": "点击固定为静态记录",
	"Pin a hostname to fixed address(es). IP accepts a single address or a comma-separated list.":                 "将主机名固定到指定地址。IP 可填单个地址，或以逗号分隔的多个地址。",
	"Replace this hostname's record. Addresses are replaced wholesale — use a comma-separated list for multiple.": "替换该主机名的整条记录。地址为整体替换 — 多个地址请用逗号分隔。",

	// proxy dialog
	"Alias": "别名", "Server (host:port)": "服务器 (host:port)",
	"Encryption Method": "加密方式", "Username": "用户名", "Password": "密码",
	"(optional)":                       "（可选）",
	"none — plaintext (unencrypted) ⚠": "none — 明文（不加密）⚠",
	"Plugin (SIP003)":                  "插件 (SIP003)",
	"(simple-obfs / v2ray-plugin built in, no external binary)": "（内置 simple-obfs / v2ray-plugin，无需外部程序）",
	"None":                            "无",
	"simple-obfs — HTTP/TLS disguise": "simple-obfs — HTTP/TLS 伪装",
	"v2ray-plugin — websocket / gRPC / QUIC": "v2ray-plugin — websocket / gRPC / QUIC",
	"HTTP disguise": "HTTP 伪装", "TLS disguise": "TLS 伪装",
	"WebSocket (HTTP)": "WebSocket (HTTP)", "WebSocket (TLS)": "WebSocket (TLS)",
	"QUIC (TLS)": "QUIC (TLS)", "gRPC (HTTP/2)": "gRPC (HTTP/2)", "gRPC (TLS)": "gRPC (TLS)",
	"Obfuscation wrapper": "混淆封装", "Transport mode": "传输模式",
	"(obfs-host / v2ray host, defaults to server host)": "（obfs-host / v2ray host，默认取服务器主机）",
	"URI": "URI", "(obfs-uri, http mode)": "（obfs-uri，http 模式）",
	"Plugin Binary": "插件程序", "(bin)": "（bin）", "Path": "Path",
	"(path, websocket only)": "（path，仅 websocket）",
	"Mux (Connection Reuse)": "Mux（连接复用）", "(mux, websocket only)": "（mux，仅 websocket）",
	"gRPC Service Name": "gRPC Service Name", "(serviceName)": "（serviceName）",
	"Certificate (certRaw)":                      "证书 (certRaw)",
	"(PEM or base64, leave empty for system CA)": "（PEM 或 base64，留空使用系统 CA）",
	"UDP in TCP": "UDP over TCP", "(hev-socks5-server CMD=5)": "（hev-socks5-server CMD=5）",
	"Show / hide password": "显示 / 隐藏密码", "Hide password": "隐藏密码",
	"Show password":     "显示密码",
	"Import ss:// Link": "导入 ss:// 链接",
	"(paste, then Parse — auto-fills server/method/password/plugin)":      "（粘贴后点“解析”，自动填充服务器/加密方式/密码/插件）",
	"Username and password are optional and embedded into the proxy URL.": "用户名和密码为可选，会嵌入到代理 URL 中。",
	"Carries this node's UDP datagrams framed over its TCP connection, so the node needs no UDP listener. Because the carrier is plaintext (GFW-fingerprintable), this node's TCP defaults to manually disabled; enable its TCP circuit on the node card to proxy TCP too. Only meaningful for SOCKS5/SOCKS5H servers running hev-socks5-server.": "通过该节点的 TCP 连接承载其 UDP 数据报，因此该节点无需监听 UDP。承载通道为明文（易被 GFW 识别），故该节点的 TCP 默认手动停用；如需同时代理 TCP，请在节点卡片上启用其 TCP 电路。仅对运行 hev-socks5-server 的 SOCKS5/SOCKS5H 服务器有意义。",
	"Scan an ss:// QR code (camera when the browser allows it; image upload/paste always works)": "扫描 ss:// 二维码（浏览器允许时使用摄像头；图片上传/粘贴始终可用）",

	// QR scanner
	"Scan QR Code": "扫描二维码", "Upload a QR image": "上传二维码图片",
	"Requesting camera…":               "请求摄像头…",
	"Point the camera at the QR code…": "将摄像头对准二维码…",
	"Camera is not available in this browser — use image upload or Ctrl+V paste below.": "当前浏览器无法使用摄像头 — 请使用下方图片上传或 Ctrl+V 粘贴。",
	"Camera unavailable ({0}) — use image upload or Ctrl+V paste below.":                "摄像头不可用（{0}）— 请使用下方图片上传或 Ctrl+V 粘贴。",
	"No QR found — try a sharper screenshot.":                                           "未识别到二维码 — 请尝试更清晰的截图。",

	// export dialog / toasts
	"Export SS Link":                           "导出 SS 链接",
	"Copy the ss:// link to clipboard":         "复制 ss:// 链接到剪贴板",
	"Download the QR code as a PNG image":      "将二维码保存为 PNG 图片",
	"Link copied":                              "链接已复制",
	"Config copied":                            "配置已复制",
	"chnroute uploaded & reloaded":             "chnroute 已上传并重新加载",
	"Go to Config tab and click Save to apply": "前往 Config 页签并点击“保存”以生效",
	"Created: {0}":                             "已创建：{0}",
	"Selected: {0}":                            "已选择：{0}",
	"Export — {0}":                             "导出 — {0}",

	// file browser
	"Filename is empty": "文件名为空",
	"Invalid filename: \"/\" \"\\\\\" and \"..\" are not allowed": "非法文件名：不允许 “/” “\\” 和 “..”",
	"Create an empty file in":                                     "在以下目录创建空文件",

	// DNS
	"{0} — {1} record": "{0} — {1} 记录",

	// config page
	"Clear the editor content": "清空编辑器内容",
	"ACL":                      "ACL", "Chnroute": "Chnroute",

	// validation / feedback (whole strings or tf templates)
	"Alias is required":                                        "别名不能为空",
	"Server (host:port) is required":                           "服务器 (host:port) 不能为空",
	"Encryption method is required for SS":                     "SS 必须选择加密方式",
	"Invalid ss:// link":                                       "无效的 ss:// 链接",
	"Invalid server address: {0}":                              "无效的服务器地址：{0}",
	"Alias \"{0}\" already exists":                             "别名 “{0}” 已存在",
	"Delete proxy \"{0}\" ?":                                   "删除代理 “{0}” ？",
	"No entries to export":                                     "没有可导出的记录",
	"No valid entries selected (may have expired)":             "没有选中有效记录（可能已过期）",
	"Enter a hostname":                                         "请输入主机名",
	"Enter an IP address":                                      "请输入一个 IP 地址",
	"Enter at least one IP address":                            "请至少输入一个 IP 地址",
	"Export failed":                                            "导出失败",
	"Log area not found":                                       "未找到日志区域",
	"No logs to export":                                        "没有可导出的日志",
	"Scanned QR is not a valid ss:// link":                     "扫描到的二维码不是有效的 ss:// 链接",
	"Error":                                                    "错误",
	"Error: bad response":                                      "错误：无效响应",
	"{0} added, {1} skipped (duplicates)":                      "已添加 {0} 条，跳过 {1} 条（重复）",
	"Pinned: {0} → {1}\nPersistent static record, hot-applied": "已固定：{0} → {1}\n持久静态记录，即时生效",
	"Restored {0} circuit(s) (temporary; a failed re-check will close them again)": "已恢复 {0} 个电路（临时；再次检测失败将重新关闭）",
	"No circuits were auto-closed due to failed checks":                            "当前没有因检测异常而自动关闭的电路",

	// delete confirmations
	"Delete {0} selected blacklist entr{1}?": "删除选中的 {0} 条黑名单条目？",
	"Delete {0} selected DNS cache entr{1}?": "删除选中的 {0} 条 DNS 缓存条目？",
	"Delete static record for \"{0}\"?":      "删除静态记录 “{0}”？",

	// filter triggers (re-composed in JS via tf with a localised value)
	"Type: {0} ▾":  "类型：{0} ▾",
	"Level: {0} ▾": "级别：{0} ▾",

	// count templates
	"{0} entries":                "{0} 条",
	"{0} / {1} entries":          "{0} / {1} 条",
	"{0} records":                "{0} 条记录",
	"{0} selected":               "已选 {0} 项",
	"Add ACL Rule ({0} entries)": "添加 ACL 规则（{0} 条）",
	"Save {0}":                    "保存 {0}",

	// placeholders (English-meaningful; example IPs stay as-is, handled by attr dict entry below)
	"Search host, reason...":                 "搜索主机、原因…",
	"Filter log content...":                  "过滤日志内容…",
	"Search domain, answer...":               "搜索域名、应答…",
	"Search host...":                         "搜索主机…",
	"hostname":                               "主机名",
	"username":                               "用户名",
	"password":                               "密码",
	"file name":                              "文件名",
	"my-proxy":                               "my-proxy",
	"1.2.3.4, 2001:db8::1 (comma-separated)": "1.2.3.4, 2001:db8::1（逗号分隔）",
	"1.2.3.4 or 1.2.3.4, ::1":                "1.2.3.4 或 1.2.3.4, ::1",
	"1.2.3.4, ::1":                           "1.2.3.4, ::1",
	"Click to edit":                          "点击编辑",
}

// zhDynamicKeys are keys reachable ONLY at runtime: they are composed via
// t()/textContent from data or string concatenation and never appear verbatim in
// dashboard.html. They are exempt from the source-reachability test (a dynamic
// model token like tcp_only has no static English text to match).
var zhDynamicKeys = map[string]bool{
	"tcp_only":         true, // p.mode token fed to t()
	"Auto-scroll: ON":  true, // updateLogsScrollBtn composes 'Auto-scroll: '+…
	"Auto-scroll: OFF": true,
}

// zhPrefixes — applied to a text node that starts with the prefix (longest
// first); only the prefix is replaced, the remainder is kept verbatim. The order
// given here is cosmetic: zhBoot sorts it longest-first before serialising, which
// is what JS relies on.
var zhPrefixes = []struct{ Pre, Zh string }{
	{"Failed to update config: ", "更新配置失败："},
	{"Validation failed: ", "校验失败："},
	{"Create failed: ", "创建失败："},
	{"File not usable: ", "文件不可用："},
	{"Save failed: ", "保存失败："},
	{"Delete failed: ", "删除失败："},
	{"QR render failed: ", "二维码渲染失败："},
	{"udp failures: ", "UDP 失败："},
	{"tcp failures: ", "TCP 失败："},
	{"Auto-scroll: ", "自动滚动："},
	{"latency: ", "延迟："},
	{"Error: ", "错误："},
	{"Type: ", "类型："},
	{"Level: ", "级别："},
	{"Proxy: ", "代理："},
	{"Direct: ", "直连："},
}

// zhHTML — whole-subtree swaps for [data-i18n=marker] elements. The value is the
// new innerHTML of the marked element (markers sit on existing <p>/<div>).
var zhHTML = map[string]string{
	"qr-hint": `…或在任意位置按 <b>Ctrl+V</b> 粘贴截图。`,
	"tls1":    `<b>面板以 HTTPS 提供服务，使用内置根 CA（<code>admin.crt</code>）签发的短期 <b>叶子证书</b>。请在打开面板的每台设备上，将该 CA 安装为<b>受信任的证书颁发机构</b>——之后叶子证书会被自动信任，“不受信任”警告随之消失。CA 是稳定的信任锚：在应用重装或面板地址变化时<b>不会</b>改变，因此每台设备只需安装一次。Android 7.0+ 安装 CA 需要先设置锁屏 PIN；iOS 需先安装描述文件，再在“设置 &gt; 通用 &gt; VPN 与设备管理”中信任。`,
	"tls2":    `叶子证书覆盖 <code>localhost</code>、<code>127.0.0.1</code>、<code>::1</code> 以及 <code>admin_cert_sans</code>（config 的 <code>listen</code> 块）中的每个名称/IP。若局域网地址缺失，请在其中补充并重启——只会重新签发叶子证书，CA 保持不变，因此已信任它的设备仍可继续使用。用户提供的 <code>admin_ca.{crt,key}</code>（置于配置旁）会覆盖内置 CA；未内置 CA 的构建则会回退为单个自签名证书。`,
}

// ---- language negotiation -------------------------------------------------

var uiMatcher = language.NewMatcher([]language.Tag{language.English, language.Chinese})

func matchUILang(accept string) string {
	tags, _, err := language.ParseAcceptLanguage(accept)
	if err != nil || len(tags) == 0 {
		return "en"
	}
	_, i, conf := uiMatcher.Match(tags...)
	if conf == language.No {
		return "en"
	}
	if i == 1 { // index into [en, zh]; zh-TW maps here too (Simplified is fine)
		return "zh"
	}
	return "en"
}

func (s *Server) uiLang(r *http.Request) string {
	if c, err := r.Cookie("sp_lang"); err == nil {
		if c.Value == "zh" || c.Value == "en" {
			return c.Value
		}
	}
	return matchUILang(r.Header.Get("Accept-Language"))
}

// ---- zh document pre-build ------------------------------------------------

func mustJSON(v any) string {
	buf, err := json.Marshal(v)
	if err != nil {
		panic("admin i18n: " + err.Error())
	}
	return string(buf)
}

// zhBoot is injected right before the real closing </head> on zh requests (runs
// after the static boot script at the top of <head>, so it can override SP_LANG
// and install dicts).
var zhBoot = func() string {
	// Serialise prefixes longest-first: JS picks the first startswith match.
	sorted := append([]struct{ Pre, Zh string }(nil), zhPrefixes...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].Pre) > len(sorted[j].Pre) })
	pe := make([]string, 0, len(sorted))
	pz := make([]string, 0, len(sorted))
	for _, p := range sorted {
		pe = append(pe, p.Pre)
		pz = append(pz, p.Zh)
	}
	return `<script>
window.SP_LANG='zh';
window.SP_I18N=` + mustJSON(zhStrings) + `;
window.SP_I18N_PRE={k:` + mustJSON(pe) + `,v:` + mustJSON(pz) + `};
window.SP_I18N_HTML=` + mustJSON(zhHTML) + `;
</script>`
}()

// zhDashboardHTML is the pre-built zh variant of dashboardHTML.
var zhDashboardHTML string

func init() {
	zhDashboardHTML = strings.Replace(dashboardHTML, `<html lang="en">`, `<html lang="zh-CN">`, 1)
	// 注入点必须落在真正闭合 <head> 的那个 </head> 上 —— 即首个 <body> 之前的最后一个
	// "</head>"。绝不能按"第一处字面 </head>"替换:dashboard.html 里 JS 注释中若出现
	// "</head>" 字样(曾有过),会把 zhBoot 整段塞进注释中间、由其自带 </script> 提前终结
	// 外层 <script>,剩余 boot 源码便以纯文本喷到页面(表现为"乱码")。
	body := strings.Index(zhDashboardHTML, "<body")
	if body < 0 {
		panic("dashboard.html: <body> not found")
	}
	closeHead := strings.LastIndex(zhDashboardHTML[:body], "</head>")
	if closeHead < 0 {
		panic("dashboard.html: closing </head> not found before <body>")
	}
	// 插到 </head> 起始之前,zhBoot 因此仍在 <head> 内(紧随静态 boot script)。
	zhDashboardHTML = zhDashboardHTML[:closeHead] + zhBoot + "\n" + zhDashboardHTML[closeHead:]
}
