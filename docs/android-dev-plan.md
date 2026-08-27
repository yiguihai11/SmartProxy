# SmartProxy Android 版开发计划

> 状态:设计讨论稿,待确认后进入开发
> ⚠️ **已实现(功能已全部落地),本文为历史设计快照**——文档描述的桥接口、`tun.dns_servers`、`/api/vpn` 等已随实现改动;实际行为以 README / `docs/config.md` / `docs/android-cli.md` / 各模块文档为准,勿按本文反推代码。
> 参考:老项目 [sockstun](https://github.com/yiguihai11/sockstun)(Java + VpnService + JNI/C 隧道)
> 相关:`docs/android-cli.md`(构建通道)、`mobile/bridge.go`(gomobile 桥)

## 1. 目标

把 SmartProxy 的 Go 引擎(SS + obfs、智能路由、规则引擎、DNS 拦截、黑名单)封装成 Android app,
UI 用 **Kotlin + Jetpack Compose + Material 3**。流量模式设计沿袭 sockstun 的三大哲学:

- **仅代理** (proxy only)
- **仅绕过** (bypass only)
- **放行自身** (allow own traffic)

## 2. 现状盘点

已经具备的:

| 部分 | 位置 | 说明 |
|---|---|---|
| gomobile 桥 | `mobile/bridge.go` | `StartRouter(configPath, tunFd)`(引擎按路径加载 config 文件,与桌面 `config.Load` 同路)/ `StopRouter` / `IsRunning` / `GetStatus`(回传 IP/域名黑名单命中) |
| 引擎 TUN fd 模式 | `mobile/bridge.go:39-41` | 强制 `TUN.Enabled=true`、`FileDescriptor=tunFd`、`AutoRoute=false`(路由交给 Android) |
| AAR 构建 | `Makefile: android` | `gomobile bind -tags with_gvisor -target=android -o build/smartproxy.aar ./mobile` |
| CI 构建通道 | `.github/workflows/android-build.yml` | 已跑通"脚手架 → R8 → 临时签名 → assembleRelease → 上传 APK" |

还缺的(本次要开发的):

- Android app 壳:VpnService + 前台服务 + Compose UI
- 配置生成:UI 状态 → Go engine 的 JSON 配置
- App 选择页:查询 / 排序 / 提示
- 真实 AAR 接入 Gradle + CI 改造(runner 上先 gomobile bind 再 gradle)

## 3. 总体架构:两层正交

sockstun 的设计核心是:**流量模式全部实现在 Android `VpnService.Builder` 层,原生隧道是"哑转发"**。
SmartProxy 与它的区别在于 Go 引擎自带目标维度的智能路由,所以两层各管各的,正交叠加:

```
┌─ Android 层(VpnService.Builder)────────── 决定"谁进隧道"(sockstun 哲学)
│    仅代理 / 仅绕过 / 放行自身 / IPv4·IPv6 拦截开关
│
└─ Go engine(SmartProxy 核心)────────────── 决定"进了隧道后往哪走"(SmartProxy 特色)
     智能路由 / 规则引擎 / 黑名单 / chnroutes / 健康检查 / DNS 拦截
```

- **App 维度**(Android 层):按应用分流,`addAllowedApplication` / `addDisallowedApplication`。
- **目标维度**(Go engine):按目的地分流,规则/黑名单命中 → 直连或走代理。

两层互不知晓:Android 只决定把哪些 app 的包送进 TUN;进 TUN 后 Go engine 自行决定出口。

## 4. 流量模式设计(学自 sockstun)

实现位置:**全部在 VpnService.Builder**,原生层不感知。参照 `sockstun/TProxyService.java` 的建隧道逻辑:

| 模式 | Builder 调用 | 语义 |
|---|---|---|
| **仅代理** (per-app,默认) | `addAllowedApplication(选中包)` | 只有勾选的 app 进 TUN 走代理,其余全部直连 |
| **仅绕过** (global) | `addDisallowedApplication(选中包)` | 全局进 TUN,勾选的 app 直连绕过 |
| **放行自身** | `addDisallowedApplication(本包名)` **无条件强制** | app 自己的流量(上游握手、engine 出站 DNS)永不回环进 TUN |

> **不做 bypass_lan(内网直连)**:内网/局域网段(LAN)的直连分流交给 Go 引擎的目标维度规则
> (chnroute / 私有网段直接放行)处理,Android 层不需要 `excludeRoute`,保持两层职责干净。

**放行自身是防回环的保命逻辑,不是可选项**。**无条件调用** `addDisallowedApplication(本包名)`
(每次建隧道都调,无 UI 开关、不进配置)。但它的真实效力**依模式而定**——源码依据
`Vpn.java:addUserToRanges()`:`if (allowed != null) … else if (disallowed != null) …`,
allowed 与 disallowed **二选一**:

| 场景 | allowed | disallowed(self) 效力 |
|---|---|---|
| 仅代理 + 白名单非空 | 非 null | **no-op**(Android 忽略 disallowed);防回环真正靠"self 不在白名单",自身流量自然走底层网络 |
| 仅代理 + 白名单为空 | null | **必要防线**(走 else if,除 self 外全部进 TUN) |
| 仅绕过(黑名单) | null | **必要防线**(黑名单本应含 self) |

所以"无条件调用"策略成立且无害:白名单非空时是 no-op,空白名单/黑名单时是唯一防线。

> **边缘语义**:仅代理 + 空白名单(没勾任何 app)时 `allowed == null` → 退化为"**除 self 外
> 全局代理**",不是直觉的"全直连"(sockstun 同此)。UI 需约束:仅代理模式至少勾选 1 个 app,
> 空名单禁止启动或给提示(见 §8)。

- **无法取消 / 不可配置**:不提供 UI 开关,不进配置文件,硬编码在服务里。
- 原因:app 到上游代理的握手包、Go engine 自己发起的 DNS 查询,一旦被路由回 TUN 就是
  无限循环;正确做法不是动 fd,而是在 Builder 层把本包名 disallowed,让控制面流量从真实
  网络直出。若将来想让 app 自身业务流量走代理,只能走 app 内 SOCKS 入口(连本地端口),
  TUN 模式一律放行自身。

骨架(伪码):

```kotlin
val builder = VpnService.Builder().setMtu(...)

if (ipv4) {                             // 首页开关:拦截 IPv4
  builder.addAddress(v4addr, v4prefix).addRoute("0.0.0.0", 0)
  builder.addDnsServer(dnsV4)           // v4 DNS,默认 223.5.5.5,面板可改
}
if (ipv6) {                             // 首页开关:拦截 IPv6
  builder.addAddress(v6addr, v6prefix).addRoute("::", 0)
  builder.addDnsServer(dnsV6)           // v6 DNS,默认 2400:3200::1,面板可改
}
// ↑ 所有占位变量(v4addr/v4prefix/dnsV4…)均从 config.json 的 tun 段解析,见 §4.6

if (globalMode) {                       // 仅绕过
  selectedApps.forEach { builder.addDisallowedApplication(it) }
} else {                                // 仅代理
  selectedApps.forEach { builder.addAllowedApplication(it) }
}
builder.addDisallowedApplication(packageName)  // 放行自身:无条件强制,防回环

val fd = builder.establish()!!.getFd()
StartRouter(configPath, fd)   // config 落盘 filesDir/config.json 后按路径传(§4.6)
```

> AppListActivity 中同一个勾选列表的语义随模式翻转:global 模式勾选=已排除(红),
> per-app 模式勾选=仅代理(绿)。

### 4.1 IPv4 / IPv6 拦截开关(首页)

首页(主设置页)提供 **IPv4 / IPv6** 两个独立开关,控制拦截哪一族流量。

**每族开关与 `addRoute`、`addDnsServer` 严格对应**(参照 sockstun 的 `getIpv4()` / `getIpv6()`
块,route 和 dnsServer 在同一族开关下一起加):

| 族开关 | addRoute | addDnsServer |
|---|---|---|
| IPv4 开 | `addRoute("0.0.0.0", 0)`(v4 全进 TUN) | `addDnsServer(dnsV4)`(默认 223.5.5.5,面板可改) |
| IPv6 开 | `addRoute("::", 0)`(v6 全进 TUN) | `addDnsServer(dnsV6)`(默认 2400:3200::1,面板可改) |
| 某族关 | 不加该族默认路由 | 不加该族 DNS |

- 族关闭 = 该族流量完全走真实网络、不进 TUN(不加默认路由),同时该族 DNS 也不配置。
- 开关在**启动服务时读取**,改动需重启 VPN 生效(与模式开关一样是启动期参数)。
- **配置生成器要同步**:只给开启的族配 TUN 地址(`inet4_address` / `inet6_address`,如
  198.18.0.1 / fc00::1)与 DNS 地址进 Go engine 的 JSON;只开 v4 就不给 engine 配 v6
  地址,避免 engine 侧空转。engine 的 DNS 转发目标同取这份 `dnsV4`/`dnsV6` 设置。
- 与流量模式(仅代理/仅绕过/放行自身)**正交**:模式管"谁进隧道",开关管"进哪一族流量"。

### 4.2 DNS 拦截:必须显式配置

**关键坑**:不调用 `addDnsServer()` 时,系统解析器(netd dnsproxy)仍用底层网络
(运营商/路由器)的 DNS,查询沿底层网络直接发出、**不进 TUN**,引擎拦截不到——
域名黑名单 / 智能分流 / 污染检测 / IP 优选对走系统解析器的 app 全部失效。

**必配**:VPN 起来时 `addDnsServer(地址)`,地址**面板可配、默认阿里 DNS**:v4 `223.5.5.5`,
v6 `2400:3200::1`。系统解析器被指到该地址 → 查询被 `0.0.0.0/0`
默认路由带进 TUN → Go engine DNS 模块拦截、按规则解析。

> **为什么真实公网 IP 也可以**:引擎拦的是**全部 UDP:53,不看目标地址**
> (`internal/tun/handler.go`:`if port == 53 { handleDNS }`)。`223.5.5.5:53` 不是接口地址、
> 不在内核 `local` 表,被 `0.0.0.0/0` 路由照常收进 TUN → 引擎按端口拦下,与硬编码 DNS 的
> app(直连 `8.8.8.8` / `223.5.5.5`)走同一条路,语义统一。

> **注意:地址不能用 TUN 网关 IP 本身**。`addAddress` 分配的地址(如 198.18.0.1)是 tun0
> 的本地地址,内核 `local` 表(规则优先级 0)优先命中 → 目标是它的包走 RTN_LOCAL / loopback,
> **不进 tun0 设备**,引擎从 TUN fd 读不到。要用"同一 TUN 子网内另一个 IP"当 DNS 时即为此意
> (sockstun 的 `TUNNEL_IPV4=198.18.0.1` / `MAPDNS=198.18.0.2`);用真实公网 IP 则天然满足。
> 若执意用网关 IP,则需引擎另开本地 UDP 监听 `网关:53`,是另一条代码路径,不推荐。

**例外(不靠 addDnsServer 也能拦)**:app 自带硬编码 DNS(绕过系统解析器,直连 UDP:53 到
`8.8.8.8` / `223.5.5.5` 等,很多国内 app 如此)——这类包被 `0.0.0.0/0` 照常收进 TUN,引擎能拦。

**结论**:`addDnsServer()` 交接是**必配项**,不是"不配置就运营商 DNS 兜底"的可选项。是否启用引擎
的 DNS 模块是另一回事(`dns.enabled`,配置生成器按 UI 决定);但无论启用与否,Android 层
都必须 `addDnsServer()`,否则系统解析器 DNS 完全脱管。地址取 UI 的 `dnsV4` / `dnsV6`
(默认 `223.5.5.5` / `2400:3200::1`),面板可改。

**源码依据**(已核对 AOSP main):
- `Vpn.java:makeLinkProperties()`:只有 `mConfig.dnsServers != null` 才 `lp.addDnsServer()`,
  没调 `addDnsServer()` 时 VPN 网络 LinkProperties 无任何 DNS。
- `netd server/NetworkController.cpp:getNetworkForDnsLocked()`:
  `fwmark.protectedFromVpn = true`(DNS socket 标记绕过 VPN),且当
  `resolv_has_nameservers(VPN)` 为假(即没 addDnsServer)时 `*netId = defaultNetId`,
  查询走默认/底层网络。
- 因此不配置 DNS = 系统解析器查询发往运营商 DNS + 被 fwmark 保护绕过 VPN,双保险不进 TUN。
- 配置 DNS(任意非网关地址,含真实公网 IP)后 `resolv_has_nameservers(VPN)` 变真 →
  `netId = VPN` → DNS 只在 TUN 路由可达 → 查询进 TUN 被引擎拦截(Clash/Shadowsocks 等
  客户端通用做法)。

### 4.3 通知栏保活 + 开机自启

**前台服务 + 常驻通知(VPN 保活)**:

- FGS 声明(API 34+ 强制类型):`android:foregroundServiceType="specialUse"` +
  `FOREGROUND_SERVICE_SPECIAL_USE`(normal 权限,免运行时授权)+
  `<property PROPERTY_SPECIAL_USE_FGS_SUBTYPE value="vpn">` +
  `android:permission="android.permission.BIND_VPN_SERVICE"`(仅系统可 bind)。
  **注意**:manifest 的 `foregroundServiceType` 属性**没有 `vpn` flag**(AOSP 全版本如此,
  `FOREGROUND_SERVICE_TYPE_VPN` 只是运行期 `ServiceInfo` 常量,manifest 声明不了),
  v2rayNG 等 VPN 应用一律用 specialUse;运行期传参必须与 manifest 一致,否则
  Android 14+ 的 startForeground 类型校验抛异常。
- `startForegroundService()` 启动,5s 内 `startForeground()`(`ServiceCompat.startForeground(…,
  FOREGROUND_SERVICE_TYPE_SPECIAL_USE)`);`onStartCommand` 返回 `START_STICKY`。
- 通知:`setOngoing(true)` **不可滑动清除**、无清除按钮、免"全部清除";渠道 `IMPORTANCE_LOW`
  (不响铃);Android 13+ 申请 `POST_NOTIFICATIONS` 运行时权限。
- 通知内容:**极简**——标题(app 名)+ 一行"正在运行",不显示模式 / 已选数量 / 黑名单 / 流量
  等任何状态信息。通知 action:停止按钮(PendingIntent)(唯一的功能按钮,如需更极简可去掉);
  通知正文 `contentIntent` → 打开主界面(零视觉成本,与极简原则不冲突)。
- **保活强化(目标:不被清掉)**:
  - `android:stopWithTask="false"` + `onTaskRemoved` 不 `stopSelf()`(从最近任务划掉不杀服务);
  - `START_STICKY`(系统回收 / 崩溃后系统尝试重启);
  - **OEM 电池白名单**:沿用 sockstun 的 `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` 引导,并
    引导用户把本 app 加入 OEM 的"自启动 / 受保护应用"列表(小米 / 华为等各厂商设置页深链);
  - 前台服务本身优先级最高,LMK 一般不杀。
- **现实上限**:Settings 里"强行停止"(force-stop)会杀死服务且无法自动恢复(Android 硬行为,
  任何手段都无法阻止),重启后需用户手动再开。文档按"尽力而为"承诺,不承诺 100%。

**开机自启(首页开关)**:

- 首页 `Switch"开机自启"`:**默认关**,用户主动开启;开启写偏好,关闭不启动。
- 静态注册 `BOOT_COMPLETED` + `MY_PACKAGE_REPLACED` 接收器(升级后重注册);开机读偏好,开启才继续。
- 先 `VpnService.prepare()`:`null` = 授权仍在(VPN 授权持久化,重启后有效)→ 直接起服务;
  非 `null` = 授权丢失 → 跳过并提示用户重新授权。
- **Android 15 已确认**:`specialUse`(VPN)不在 BOOT_COMPLETED 受限 FGS 类型列表
  (`dataSync`/`camera`/`mediaPlayback` 等才受限),开机广播启动 VPN 合法 ✓。
- 启动走同一套 `startForegroundService` → 通知栏保活接管。

### 4.4 管理控制面板(外链浏览器 + 局域网)

**形态**:外链浏览器。首页"管理面板"入口:
- 显示 `https://<手机IP>:port`,带**复制按钮**(`ClipboardManager`,复制 URL 到剪贴板)。
- 点击用 `Intent.createChooser` **弹浏览器选择器**让用户选浏览器,不锁系统默认浏览器
  (`ACTION_VIEW` 只走默认,改走 chooser)。
- 附二维码(扫码同 URL);二维码太占版面,**默认折叠**,卡片底部居中下拉箭头点开/收起
  (URL 与复制/打开按钮常驻,只折二维码;二维码在卡内居中)。

**绑定**:admin TCP 监听 `:port` = **0.0.0.0 + ::(Go 双栈,自动覆盖 v4/v6),常开无开关**。
管理面板监听与隧道 v4/v6 拦截开关无关——`net.Listen("tcp", ":port")` 天然双栈,无需按 v6
开关控制。

**安全底线(必配,不可省)**:
- `admin_auth` 启用 Basic Auth,用户名/密码**用户自行设置**(非随机;面板内可改,
  PUT `/config` 热重载即生效)。
- ⚠ 0.0.0.0 常开 + 弱密码 = 局域网内任意设备可读上游代理密码、改配置;凭据勿设过弱。
- `admin_https`(默认 true):自签证书自动生成,HTTP→HTTPS 301;`AdminCertSANs` 加手机
  局域网 IP 减浏览器警告;自签证书首次访问有"不安全"提示,点继续(局域网场景可接受)。

**架构**:

```
┌─ Android app ─────────────────────────────────┐
│  首页:面板 URL(复制/选浏览器/二维码)          │
│  VpnService ─ fd ─ Go engine(AAR)              │
│                    └ Admin Server 0.0.0.0:port │
│                      ├ 静态 Web UI(go:embed)   │
│                      └ /stats /config /acl …(纯 Go 端点 + fsnotify watcher)│
└────────────────────────────────────────────────┘
     LAN 浏览器 → https://<手机IP>:port/(Basic Auth)
```

**产品形态:安卓 = 主管理,面板 = 纯 Go 完整配置编辑器**:
- 安卓首页:VPN 启停按钮、IPv4/IPv6 拦截开关、开机自启、**Apps(应用选择入口,§5)**、
  面板入口(URL+复制+二维码)。流量模式 + 应用选择**已应用内化**进 AppSelectionActivity。
- 手机精简面板 panel.html **已删除**:DNS 应用内硬编码(223.5.5.5 / 2400:3200::1,无 UI)、
  IPv4/IPv6/开机自启开关首页已有、管理密码在 dashboard 配置文件 tab 里改。
- `/` 与 `/dashboard` 都服务**完整纯 Go 面板 dashboard.html**。

**Web UI(SPA)规格**:
- 嵌入 Go 二进制(`go:embed`),admin server 静态服务 `/` = **完整桌面面板 dashboard.html**
  (纯 Go 端点 /config /acl /chnroute /dns/static 等)。
- 流量模式 + 应用选择不含在面板(§5 应用内化,App 内 AppSelectionActivity)。

**Android 桥接端点已全部删除(纯 Go 还原)**:dashboard.html 走纯 Go `/config` PUT 写
filesDir/config.json,引擎 watcher 热重载。桥只保留 gomobile 接口 `Vpn(action)`——
configReload 检测到隧道参数变更时触发 Android 侧 VPN 重启。应用枚举/图标从不过桥
(§5 应用内,AppEnumerator 直供 Compose 列表)。

**配置生成**:ConfigProvider.ensureConfig 每次启动幂等应用不变量——routing 路径绝对化到
cacheDir、`tun.enabled=true`/`auto_route=false`(fd 模式写死)、`AdminCertSANs` 追加手机 IP。
`admin_auth` / DNS 由 dashboard 在配置文件 tab 里改(写 config.json,引擎 watcher 热重载)。

**生效方式**:面板改配置 → `PUT /config` 写 filesDir/config.json → fsnotify watcher →
configReload 热重载(admin_auth、dns.foreign、smart_proxy 等即时生效,不断连);TUN 隧道参数
(mtu / inet4|6_address / dns_servers / admin 端口证书)变 → `needsRestart` 自动经桥重启
VPN(2-3s 断连)。

**注意**:手机局域网 IP 变化时首页 URL/二维码需刷新,`AdminCertSANs` 同步更新(证书 SAN
变化会重新触发一次浏览器警告)。

### 4.5 VPN 断连检测与状态同步

**核心场景**:开启后被**其它 VPN 抢占**、或用户在系统设置断开 → 隧道失效,**必须检测并
把状态同步到首页与 Web 面板**。

**检测信号(按优先级)**:

1. **`onRevoke()`(主信号,免轮询)**:系统在"另一个 VPN 成功 `establish()` 抢占"
   或"用户在系统设置里断开 VPN"时**主动回调本服务的 onRevoke**,隧道即刻失效。
   无需任何探测逻辑,系统保证回调。处理(必做,不可省):统一走 `shutdown()`
   (fullTeardown=true:停 Go 引擎 → `stopSelf()` 先拆网络 → 100ms 留白 → 关 TUN fd →
   `stopForeground(STOP_FOREGROUND_REMOVE)`),共享状态 `isRunning=false`(见下)。
2. **`onDestroy()`(兜底)**:任何原因服务被销毁都走这里,统一清理 + 状态落 `false`。
3. **引擎侧(不依赖,只说明)**:TUN fd 失效时引擎读循环报错自停,但 `mobile.IsRunning()`
   看的是 `globalEngine != nil`,**不会自动归零**——所以第 1 步的 `StopRouter()` 是唯一
   清理路径,**必调**,不能指望引擎自检。引擎自停而不调 StopRouter 时,`/health` 仍可能
   短暂显示 running(靠 `/api/vpn` 轮询兜底)。

**状态同步(首页 + 面板)**:

- **唯一真实状态源 = VpnService 生命周期**(`onCreate` / `onRevoke` / `onDestroy`)。
  Kotlin 侧维护 `StateFlow<Boolean> isRunning`,Compose 首页 collect:
  启动/停止按钮、面板入口状态随它翻转(被挤掉后按钮自动回到"启动")。
- **Web 面板**:SPA 每 N 秒轮询 `/api/vpn`(或复用 `/health`);`StopRouter()` 后引擎
  返回未运行 → 面板自动置"未运行"。无需推送,轮询即可(本地/局域网延迟可忽略)。
- **区分主动/被动停止**:`userInitiatedStop` 标志。用户点停止 → 静默;`onRevoke` 被动
  断开 → 可选弹一次性通知"VPN 已被系统断开"(仅提示,不违背"正在运行"通知的极简原则)。

**抢占方向(双向都由系统保证,无需应用逻辑)**:
- 我们启动时:`prepare()` 检测到已有其它 VPN 运行 → 系统弹授权框,用户确认 → **旧 VPN 被
  revoke,我们接管**。
- 别人启动时:他人 `establish()` 成功 → 系统 revoke 我们 → 走上面的 `onRevoke`。

### 4.6 启停联动 + 配置单一真源

**启停 VPN = 开关核心引擎(成对,不独立)**:

- 启动:`onStartCommand` → 读配置 → 建 Builder → `establish()` → fd + configPath
  (config 已落盘 filesDir/config.json)→ `StartRouter`。引擎随 VPN 起而启动;**没有
  "只开引擎不开 VPN"或反之的状态**。
- 停止:用户点停 / `onRevoke` / `onDestroy` → `shutdown()`,顺序对齐 v2rayNG
  `stopAllService`(2026-08 图标赖着不掉排查,见下方「停止顺序」):引擎随 VPN 停而停;
  fd 是引擎唯一输入,引擎停 = VPN 失效(§4.5)。

**停止顺序(关 fd 之前必须先让系统拆 VPN 网络)**:`SmartProxyVpnService.shutdown()`
四步——`Mobile.stopRouter()`(关 dup 出的 goFd)→ `stopSelf()`(触发系统注销
NetworkAgent / 移除路由)→ `Thread.sleep(TEARDOWN_SETTLE_MS=100ms)` → `tunPfd.close()`
(关原始 PFD,最后一个 fd)。**为什么不能先关 fd**:两个 fd 都关掉、内核开始删 tun0 时,
若 VPN 网络还挂着(路由仍指向 tun0),曾经走过流量的应用 TCP 连接会 hold 住 tun0 的
dev refcount(连接 socket 的 dst 持有 dev 引用),内核 `netdev_wait_allrefs` 一直等这些
连接自然超时(数十秒)才真正删 tun0,`interfaceRemoved` 不触发,状态栏钥匙图标赖着
不掉;**没流量 = 没活跃连接 = 秒删**。v2rayNG 用「stopSelf 先行 + 100ms 留白再关 fd」
解决同一问题。重启路径(`ACTION_RESTART`)服务需存活,`shutdown(fullTeardown=false)`
跳过 stopSelf / 留白,直接关 fd 后重建。

**Builder 参数直接读 config.json 的 `tun` 段(单一真源)**:安卓启动 VPN 时解析**同一份
落盘到 filesDir/config.json、按路径交给 `StartRouter` 的 config**,逐字段喂 Builder,
**不硬编码**。config.json 的 tun 段形态:

```json
"tun": {
  "mtu": 1500,
  "inet4_address": ["172.19.0.1/30"],
  "inet6_address": ["fc00::1/64"],
  "dns_servers": ["223.5.5.5", "2400:3200::1"]
}
```

| Builder | 配置来源(逐字段解析) |
|---|---|
| `setMtu()` | `tun.mtu` |
| `addAddress()` | `tun.inet4_address` / `tun.inet6_address` —— **CIDR 拆解**:`"172.19.0.1/30"` → `addAddress("172.19.0.1", 30)` |
| `addRoute()` | 各族开关(§4.1:族开才加该族默认路由 `0.0.0.0/0` / `::/0`) |
| `addDnsServer()` | `tun.dns_servers`(v4/v6,默认 `223.5.5.5` / `2400:3200::1`,面板可改) |

```kotlin
// 同一份 config.json 同时喂 Builder 和 StartRouter
val cfg = parseConfig(configJson)
builder.setMtu(cfg.tun.mtu)
if (ipv4) {
  val (ip, prefix) = parseCidr(cfg.tun.inet4_address[0])   // "172.19.0.1/30" → (172.19.0.1, 30)
  builder.addAddress(ip, prefix).addRoute("0.0.0.0", 0)
  builder.addDnsServer(cfg.tun.dns_servers[0])             // 223.5.5.5
}
if (ipv6) {
  val (ip, prefix) = parseCidr(cfg.tun.inet6_address[0])   // "fc00::1/64" → (fc00::1, 64)
  builder.addAddress(ip, prefix).addRoute("::", 0)
  builder.addDnsServer(cfg.tun.dns_servers[1])             // 2400:3200::1
}
val fd = builder.establish()!!.getFd()
// config.json 是唯一真源(filesDir,Go 面板与首页开关共写),引擎按路径加载(§4.6)
StartRouter(configPath, fd)
```

- **`tun.dns_servers []string` 已入核心配置**(`internal/config/config.go` 的 `TUNConfig`):
  TUN 通告给系统解析器的 DNS 地址,顺序定死 index 0 = IPv4、index 1 = IPv6;默认
  `["223.5.5.5","2400:3200::1"]`(DefaultConfig 注入),`Validate()` 校验每项是合法 IP。
  桌面端不读,无害。
- **面板改配置 = 纯 Go 机制(mobile/bridge.go StartRouter 已装配)**:复制桌面
  cmd/smartproxy/main.go L138-233——config.NewWatcher 监听 config/acl/chnroute,
  SetReloadFn + SetConfigPath + watcher.Start,`/config` GET/PUT 在 Android 端可用。
  面板写 filesDir/config.json → fsnotify 触发 configReload 热重载(admin_auth、dns.foreign、
  smart_proxy、upstream、acl/chnroute 路径变更即时生效);`needsRestart()` 检测到 TUN
  隧道参数(mtu / inet4|6_address / dns_servers / stack)或 admin 端口/证书变更 → 经桥
  `currentBridge().Vpn("restart")` 触发 Android 侧 VPN 重启。
- **首页开关与面板共写同一份 config.json**:IPv4/IPv6 拦截 = tun.inet4/6_address 存在性
  (首页开关直接增删该数组,§4.1);DNS 走 `tun.dns_servers` 固定双元素 index 契约
  (index 0 = v4 / 1 = v6,ConfigGenerator 删除后不再族过滤),Builder 缺省回退硬编码默认。
  config.json 单一真源,无 AppPrefs 生成器(§4.4)。
- **文件分布**:chnroute.txt / acl.txt 每次启动从 assets 拷到 **cacheDir**(可再生数据,
  系统可清、重拷即回,引擎启动时已载入内存),config 里 routing 路径指向 cacheDir;
  config.json 落 **filesDir** 持久文件,引擎按路径读。
- 引擎侧 DNS 拦截仍按"拦全部 UDP:53"(`internal/tun/handler.go` `port == 53`),
  `dns_servers` 仅用于 Android `addDnsServer` 通告;引擎转发目标取配置的 DNS 设置(§4.2)。

## 5. App 选择页设计(查询 / 排序 / 提示)

**定位:应用内原生页(§4.4 应用内化),不再在 Web 面板**。首页「Apps」卡 →
`AppSelectionActivity`(Kotlin + Compose)。安卓端 AppEnumerator 枚举已装 app + 缓存图标
直供 Compose 列表;勾选结果 onDestroy 批写 SharedPreferences(返回自动保存,sockstun 式),
首页/引擎启动时只读。设计沿用 `sockstun/AppListActivity.java` 的布局:

```
AppSelectionActivity(Compose,单 Activity)
├─ 流量模式:仅代理 / 仅绕过(SegmentedButton 横向;随列表滚动收起,回顶展开)
├─ 搜索框 —— 按 label / pkg 实时过滤(label.contains,大小写不敏感)
├─ tab [全部 | 用户 | 系统](SegmentedButton 行内,固定)
├─ 列表(LazyColumn,key = packageName)
│   └─ 行
│       ├─ 方形图标(AppEnumerator.iconBitmap 96px,缓存) / 标题 label
│       ├─ 副标题 packageName + uid
│       ├─ 状态角标:随 mode 翻转 —— 仅代理=绿"仅代理" / 仅绕过=红"已排除"
│       └─ Checkbox(整行可点翻转)
└─ 底部 stats bar:共 X · 显示 Y · 已选 Z(仅代理/仅绕过)
```

### 5.1 查询

- 搜索框实时过滤,`label.contains(query)`,大小写不敏感(兼查 pkg)。
- 与类型 tab(全部/用户/系统)叠加过滤。

### 5.2 排序

- **已选优先**,其次按名称排序;`Collator.getInstance(Locale.CHINA)` 拼音(§8#1)。
- **勾选后不实时重排**(§8#2,sockstun):排序基准 = 进入页面时的勾选态,避免列表跳动
  打断连续勾选。

### 5.3 提示

| 位置 | 内容 |
|---|---|
| 底部统计条 | 共 X 个应用 / 显示 Y 个 / 已选 Z 个,过滤和勾选时刷新 |
| 每行状态角标 | 仅代理模式:勾选=**仅代理**(绿 `#4CAF50`);仅绕过模式:勾选=**已排除**(红 `#FF6B6B`) |
| 底部保存提示 | 「退出即保存 · 改动在下次连接时生效」(返回自动保存,不自动重启) |
| 滚动行为 | 滚离顶部 >48px 时流量模式卡收起(AnimatedVisibility,搜索/tab/统计固定);回顶部自动展开 |
| 筛选 tab | 全部 / 用户应用 / 系统应用(`FLAG_SYSTEM` 区分) |

### 5.4 细节约束

- 列表只收录**声明了 INTERNET 权限**的 app,并跳过本包名(AppEnumerator)。
- **返回自动保存**:onDestroy 批写模式 + 应用列表(§4.4 唯一偏好),不自动重启;
  改动在下次连接时生效(与面板"保存并重启"语义区分)。
- **§8#6 空名单校验在应用内**:切到仅代理时空名单、或仅代理下取消最后一个 → 阻止 + Toast
  「仅代理模式至少勾选 1 个应用」。

## 6. 需要开发的模块清单

1. **Android app 工程脚手架**(Kotlin + Compose + Material 3,minSdk ≥ 26)
2. **VpnService + 前台服务**:`prepare()` → `establish()` → fd → `StartRouter`;含放行自身防回环、`onRevoke`/`onDestroy` 断连检测与状态同步(§4.5)
3. **ConfigProvider(config.json 文件访问层)**:ensureConfig 幂等应用不变量(routing 绝对化 / tun.enabled / SAN 追加);`cfg.TUN.*` 由 bridge 强制;admin 配置(`admin_port`/`admin_auth`/`admin_https`/`AdminCertSANs`,§4.4)在 dashboard 配置 tab 里改
4. **首页**:VPN 启停按钮(§4.5 状态机)+ IPv4/IPv6 拦截开关(读写 config.json tun.inet4/6_address,§4.1)+ 开机自启(§4.3)+ **Apps 应用选择入口(§5)**+ 面板入口 URL+复制+二维码(§4.4)。DNS 应用内硬编码(§6)
5. **通知栏 / 保活**:前台服务保活强化(§4.3:ongoing 通知、`stopWithTask=false`、OEM 电池白名单引导);通知**极简只显"正在运行"**;`GetStatus()` 黑名单命中可喂主界面状态(可选)
6. **AAR 集成 + CI 改造**(见 §7)
7. **纯 Go 控制面板还原**(§4.4):手机精简面板 panel.html 已删除,`/` 服务完整 dashboard.html;mobile/bridge.go 装配 watcher + configReload + needsRestart(自动重启);桥只留 `Vpn(action)`;流量模式 / 应用选择已应用内化(§5,AppSelectionActivity);首页入口与二维码

## 7. 构建与 CI 策略

- 本机不跑 Gradle(内存太小,见 `docs/android-cli.md`),构建一律走 GitHub Actions。
- 现有 `android-build.yml` 是**脚手架 demo-app** 通道;改造为**真实工程**:
  1. checkout + 装 Go / gomobile → `make android` 出 `build/smartproxy.aar`
  2. Gradle 工程引用该 AAR(`compileOnly` / `implementation files(...)` 或 maven local)
  3. `assembleRelease`(开 R8)+ 临时签名 → 上传 APK
- 签名沿用**临时 debug 签名**(每次构建不同,装新版前先卸载),正式发布再配持久 keystore + secrets。

## 8. 待定决策

| # | 问题 | 建议 | 备注 |
|---|---|---|---|
| 1 | App 中文名排序 | **拼音 Collator**(`Collator.getInstance(Locale.CHINA)`),已选优先 ✓已实现 | sockstun 按码点,中文乱序 |
| 2 | 勾选后是否实时置顶 | **否**,沿用 sockstun(避免列表跳动打断连续勾选) | 可做开关,默认关 |
| 3 | 包名 / 应用名 | 待定(如 `io.github.yiguihai11.smartproxy`) | 正式名需查包占用 |
| 4 | minSdk / targetSdk | minSdk 26,targetSdk 最新 | — |
| 5 | 签名 | 临时 debug 签名(现状),正式版再定 | — |
| 6 | 仅代理空白名单语义 | 仅代理模式**至少勾选 1 个 app**,空名单禁止启动/给提示 ✓应用内校验 | 否则 `allowed==null` 退化为"除 self 外全局代理" |
| 7 | 开机自启默认值 | **默认关**,用户主动开启 | 避免装完被系统托管,突兀 |
| 8 | 管理面板监听地址 | **常开 0.0.0.0 + ::(Go 双栈)**,无局域网开关 | `net.Listen("tcp", ":port")` 天然双栈;安全靠 admin_auth |
| 9 | 管理面板凭据 | **用户自行设置**(非随机),面板内可改 | 0.0.0.0 常开下别用弱密码;改后热重载 |
| 10 | 首页定位 | **主管理**:启停 + IPv4/IPv6 + 开机自启 + **Apps(应用选择入口)**+ 面板入口;模式 / 应用选择已应用内化(§5),DNS 只在面板 | 用户已定;§4.4「产品形态」 |

### 8.1 未来方向(暂缓):Shizuku 免 root 热点 / 网络共享

> 来源:[v2rayNG PR #5903](https://github.com/2dust/v2rayNG/pull/5903)(作者 eliotcougar,OPEN,41 文件 / 4037 行)。**现状:只记录思路,不做。** 与 §4.5/4.6 的图标拆除问题无关,不解决也不依赖它。

**它解决什么**:不 root,让 v2rayNG 作为**系统热点 / USB 网络共享**的上游,旁路设备流量也走代理。给 SmartProxy 的启示在「净权限」:`untrusted_app` 域禁 netlink(见记忆 android-netlink-banned-monitor),shell UID 恰好绕开。

**核心机制**(五步):
1. **shell UID 的 Shizuku UserService**:`ShizukuTetheringService.kt` 跑在 Shizuku shell 进程,持有 shell UID,才够格调隐藏 API。
2. **造 TUN 用测试网络而非 VpnService**:反射 `TestNetworkManager.createTunInterface(192.0.2.2/24)` 建内核 TUN + `setupTestNetwork(LinkProperties, …, IBinder)` 发布成测试网络,`NetworkCallback` 等 publish(`CountDownLatch` 超时)。
3. **双进程共享 fd**:UserService 持 TUN 一份,`ParcelFileDescriptor.dup()` 复制一份经 AIDL(`ICoreTetheringLease.holdTestNetwork`)交给主核心,主核心把 fd 当自身 tun 的 `fd` 吃进第二实例(`startLoop(config, fd)`)。一 TUN 两 dup fd,各管一边。
4. **`TetheringManager.setPreferTestNetworks(true)`**:让系统 tethering 上游优先选测试网络 → 热点流量自动进内核 TUN → 主核心代理出去,不碰 iptables/netd。
5. **兜底引擎**:主核心不可用时 UserService 自己起 HEV(临时 yaml 到 `/data/local/tmp`)或原生 Xray(`Libv2ray.newCoreController`)。

**工程亮点(可抄)**:双域保活(app 死则 UserService 持网络,Shizuku 死则主核心持 dup fd,`IBinder.DeathRecipient` 监听对端死亡);`RoutingSession.token` 会话隔离;`cleanupRouting()` fail-closed 有序清理(停引擎 → 还 fd → teardown → 关 TUN → `setPreferTestNetworks(false)`),防系统把下游悄悄迁回物理网卡;UserService 版本号 `20_260_755` 防跨 APK 升级 AIDL 失配。

**前置 / 风险**:
- Shizuku **v11+**;Android **API 33+**(隐藏 API 全反射);MIUI/HyperOS/ColorOS 等 tethering 魔改 ROM 不保证。
- 复杂度高(双进程 AIDL + 状态机 + 反射),Hotspot 客户端是整机流量,**做不了 per-app 路由**。
- 若日后要做「接管热点 / 需要 netlink / privileged 操作」,整套架构(server-UID UserService + AIDL 桥 + dup fd)直接可移植;否则维持 VpnService 现状。

## 9. 里程碑

- **M1**:真实工程骨架 + VpnService 起隧道 + Go 引擎跑通(DNS 走拦截,基本连通)+ 前台服务保活通知
- **M2**:首页(纯启动器:VPN 启停 + IPv4/IPv6 拦截开关 + 开机自启开关 + 面板入口 URL/复制/二维码折叠)
- **M3**:配置生成器完整 + 通知栏/状态联动
- **M4**:CI 改造(真实 AAR + gradle + 签名)+ 出签名 APK
- **M5**:管理控制面板(§4.4):Web UI SPA(`go:embed`)+ Android 桥接端点 + **流量模式 + 应用选择页(§5)+ DNS v4/v6** + LAN 访问(0.0.0.0/::)+ Basic Auth
