# 联网状态(按应用流量监控)+ 应用页加载体验 —— 开发计划

> 状态:设计定稿(决策已确认),待进入开发
> ⚠️ **已实现(功能已全部落地),本文为历史设计快照**——文中「30 秒淡出 / onPause 立即关采集」等已按实现调整(实际:5 秒淡出 / onPause 延迟 5 秒);实际行为以 README / 各模块文档 / 代码为准。
> 相关:`docs/android-dev-plan.md`(Android 版总计划)、`docs/tun.md`(TUN handler)、`mobile/bridge.go`(gomobile 桥)
> 基线:main@b64f661,备份 tag `backup-before-network-status`;计划文档提交 `52ec11f`

## 1. 目标

两个改动:

1. **联网状态**(本期主功能):仅绕过模式、VPN 运行中,侧边栏出现「联网状态」入口。打开后是按应用分组的树形列表,实时显示每秒上下行网速;点击某应用展开 → 该应用的访问目标明细(域名/SNI、IP、端口、TCP/UDP);**没有联网的应用不显示**。
2. **应用选择页加载提示**(小改进):进入「代理应用」页要拉全量应用列表 + 图标,耗时较长;现有只有转圈、无任何文案,补加载等待动画 + 信息提示。

## 2. 已确认的设计决策(定稿)

| 决策点 | 结论 |
|---|---|
| 域名提取范围 | **仅限 TCP 智能代理端口**(smart 路径 `handleSmartConnect` 现有提取,免费拿);**非 smart TCP 与 UDP 一律显示 IP**,任何路径不新增首包 peek |
| UDP | **不做域名解析 / 不做 QUIC 解析** —— UDP 数据面零新增开销 |
| 采集开关 | **懒开启**:联网状态页打开才采集,关闭页面即停;不开页面 = 引擎现状的零开销原样保留 |
| 联网状态页首开 | 有 loading 动画 + 信息提示 |
| 应用选择页 | 加载动画 + 信息提示文案 |
| 监控记录保留 | 连接 30s 无新流量 → 从明细消失(默认) |
| 轮询间隔 | 1s(默认) |

## 3. 现状盘点

**已具备(复用,不重写):**

| 能力 | 位置 | 说明 |
|---|---|---|
| 首包 peek + 域名提取 | `internal/tun/handler.go:871` `ReadClientHello` + `handler.go:920` `ExtractDomain` | 同时解析 TLS SNI 与 HTTP Host/CONNECT,测试齐全;**只在 smart 路径用** —— 正是我们要的"仅限智能代理端口" |
| UID 反查 | `handler.go:158` `isUIDBlocked` + `mobile/bridge.go:114` `SetUIDResolver` | per-app「禁止联网」的整套回调链;名单空时短路、零回调 |
| 应用枚举/图标 | AppSelectionActivity + `AppEnumerator` | UID→包名/图标加载逻辑,联网状态页直接复用 |
| 轮询刷新 UI | `LogcatActivity`(2s dump) | 联网状态页 1s 轮询同一模式 |
| 抽屉入口 + 门控 | `MainActivity` `AppDrawerContent` | 现有入口门控写法可对齐 |

**缺口(本次新增):**

1. 无条件 UID 解析(监控开启时,不受 blocked_uids 名单短路影响)
2. 字节计数(TCP `net.Conn` / UDP `N.PacketConn` 包计数 wrapper)
3. 有界连接表 + JSON 快照 API(`getConnectionStats`)
4. 联网状态 UI 页 + 抽屉入口(懒开关)
5. 应用页加载文案
6. smart 路径已提取的 domain **登记进监控记录**(不重新解析,只回填)

## 4. 引擎采集层(internal/tun)

### 4.1 UID 解析改造:拆两步,互不污染

把 `isUIDBlocked`(handler.go:158-177)拆开:

- `resolveUID(proto, src, dst) int32`:调 `uidResolverFn` 回调拿 UID,失败 -1(沿用现有 fail-open 语义)
- `isUIDBlocked`:**保持"名单空短路、不回调"不变**(per-app 禁止联网的零开销哲学不能破);名单非空才 `resolveUID` + 匹配

新增监控开关 `connStats atomic.Bool`(默认 off):

- **on**(联网状态页打开):`NewConnectionEx` / `NewPacketConnectionEx` **无条件 `resolveUID` 一次**(连接建立频率低,一次 Binder 往返可接受),并登记进监控表
- **off**:一切如现状,零开销

### 4.2 域名提取:不新增任何解析,只回填现状

- **smart TCP(智能代理端口)**:`handleSmartConnect` 已做 `ReadClientHello + ExtractDomain`(handler.go:268/276),把 `domain` 结果**回填进该连接的监控记录**即可(不重复解析;domain 为空即非 TLS/HTTP,host 落 IP)
- **非 smart TCP / UDP**:**不 peek、不解析**,host 直接用目标 IP —— 引擎零新增解析路径,数据面延迟完全不受影响

### 4.3 字节计数

- TCP:`conn net.Conn` 包 `countingConn`(Read/Write 各累计 up/down,atomic)
- UDP:`conn N.PacketConn` 包 `countingPacketConn`(ReadPacket/WritePacket 计数,每包一次 atomic 自增,O(1),不构成 UDP 数据面延迟)
- 计数归属 4.1 解析出的 UID

### 4.4 有界连接表 + 淘汰

```
map[uid] → []connRecord{ proto, host, ip, port, upBytes, downBytes, lastSeen }
```

- `host` = smart TCP 的 domain(仅该路径非空);其余为 IP
- 全局上限 ~2000 条,满时按 `lastSeen` 淘汰最旧
- 连接 30s 无新流量 → 从明细移除(速度自然归零);per-app 累计可继续被轮询到
- 线程安全:atomic + 短临界区互斥

### 4.5 快照输出

- `Mobile.getConnectionStats() string` → JSON:`{ apps: [ { uid, up, down, conns: [ { proto, host, port, up, down } ] } ] }`
- UI 每秒拉一次,`delta(当前 - 上次) = 该秒网速`;运行总量同时提供(明细行显示累计)

## 5. gomobile 桥(mobile/bridge.go)

- `Mobile.setConnStatsEnabled(enable bool)` → 注入 handler 原子标志(接线对齐现有 `SetUIDResolver`,bridge.go:114-122)
- `Mobile.getConnectionStats() string` → 读快照,序列化 JSON(K 级,有界)
- Go error 仍走"抛 Java 异常"约定(`[[gomobile-error-throws]]`),两方法本身无 error 返回

## 6. Kotlin UI

### 6.1 联网状态页(新 `NetworkStatusActivity`)

- **抽屉入口「联网状态」**:`AppDrawerContent` 加一项,门控 = `Mobile.isRunning() && 模式 == 仅绕过`(对齐现有入口门控写法)
- **onResume**:`Mobile.setConnStatsEnabled(true)` + loading(转圈 + "正在采集连接数据…")
- **每秒轮询** `getConnectionStats`(复用 LogcatActivity 轮询模式,1s;`LaunchedEffect(active)` 门控,`active=false` 即取消)
- **首个数据到 → loading 消失**,渲染 app 分组树
- **onPause**(返回上个页 / 切后台 / 被覆盖):`Mobile.setConnStatsEnabled(false)` + 停轮询,引擎零开销;onResume 恢复
- **onDestroy**:兜底 `Mobile.setConnStatsEnabled(false)`(正常 onPause 已关)
- 组头:应用图标 + 名 + ↑/↓ 实时速度(KB/s,δ)
- 点击展开:连接明细行 —— host(域名或 IP):端口 + TCP/UDP 徽标 + 累计上下行
- 空态:"暂无联网应用"(无联网 app 天然不进表)
- UID→包名/图标:复用 `AppEnumerator`

### 6.2 应用选择页加载提示(AppSelectionActivity)

- `!loaded` 分支(360 行,现仅转圈):转圈旁加文案 "正在加载应用列表… 首次可能较慢"
- 保持简单,不引入分阶段渲染;文案即满足"信息提示"

## 7. 测试与 CI

**Go 单测(新增):**
- UID 拆分:名单空短路不回调;监控开启时无条件 resolve(用 fake resolver)
- smart 路径 domain 回填:ExtractDomain 结果进记录;domain 空 → host 落 IP
- 字节计数:TCP/UDP up/down 正确
- 连接表:满上限淘汰、idle 30s 移除、并发读写不 panic

**e2e 约束:**联网状态**不进断言**(遵循既有方法论:双引擎只能做单引擎正断言;全局计数器 TCP 关闭才结算需轮询)——只保证引擎跑通、监控代码不 panic。

**Android 构建走 CI**(`android-build.yml`,`android/**` 触发),本机不跑 gradle。

**验证:**CI 绿 + 真机手测(打开出列表、速度跳动、展开见域名、关闭页面后引擎恢复零开销)。

## 8. 提交拆分

1. `chore: dist 构建产物进 .gitignore`(已含本计划文档,`52ec11f`)
2. `feat(engine): 连接监控 —— UID 拆分 + smart 路径 domain 回填 + 字节计数 + 有界表 + getConnectionStats`(含单测)
3. `feat(mobile): setConnStatsEnabled / getConnectionStats 桥`
4. `feat(android): 联网状态页 + 抽屉入口(懒开关 + loading)`
5. `fix(android): 应用选择页加载提示`

## 9. 风险与开放点

| 风险 / 开放点 | 对策 |
|---|---|
| 非 smart TCP / UDP 无域名 | 用户拍板:一律显示 IP,零新增解析开销 |
| 引擎常开开销 | 懒开关保证不开页面零成本 |
| 字节计数并发 | atomic |
| gomobile JSON 体积 | 有界 2000 条,K 级 |
| 每连接一次 getConnectionOwnerUid Binder | 连接建立频率低,可接受;若耗电明显再上本地端口→UID 缓存 |

## 10. 待确认点(已定 + 剩余默认)

1. ~~UDP 域名 / QUIC 解析~~ → **已定:不做**,UDP 一律显示 IP,零 UDP 开销
2. ~~非 smart TCP 域名~~ → **已定:不提取**,仅 smart 智能代理端口有域名,其余显示 IP
3. **连接 30s 无新流量从明细消失**(默认)—— 时长要调吗?
4. **轮询 1s**(默认)—— 要调吗?

无其余开放项,确认后可开工。
