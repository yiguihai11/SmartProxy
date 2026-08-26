# 联网状态(按应用流量监控)+ 应用页加载体验 —— 开发计划

> 状态:设计稿,待确认后进入开发
> 相关:`docs/android-dev-plan.md`(Android 版总计划)、`docs/tun.md`(TUN handler)、`mobile/bridge.go`(gomobile 桥)
> 基线:main@b64f661,备份 tag `backup-before-network-status`

## 1. 目标

两个改动:

1. **联网状态**(本期主功能):仅绕过模式、VPN 运行中,侧边栏出现「联网状态」入口。打开后是按应用分组的树形列表,实时显示每秒上下行网速;点击某应用展开 → 该应用的访问目标明细(域名/SNI、IP、端口、TCP/UDP);**没有联网的应用不显示**。
2. **应用选择页加载提示**(小改进):进入「代理应用」页要拉全量应用列表 + 图标,耗时较长;现有只有转圈、无任何文案,补加载等待动画 + 信息提示。

## 2. 已确认的设计决策

| 决策点 | 结论 |
|---|---|
| 域名提取范围 | **所有连接都要域名**:非 smart 端口 TCP、UDP 也提取(不只 80/443) |
| 采集开关 | **懒开启**:联网状态页打开才采集,关闭页面即停;不开页面 = 引擎现状的零开销原样保留 |
| 联网状态页首开 | 有 loading 动画 + 信息提示 |
| 应用选择页 | 加载动画 + 信息提示文案 |

## 3. 现状盘点

**已具备(复用,不重写):**

| 能力 | 位置 | 说明 |
|---|---|---|
| 首包 peek | `internal/tun/handler.go:871` `ReadClientHello(conn, timeout)` | 带 deadline 读首包,回灌不丢数据(带 pool 复用) |
| 域名提取 | `handler.go:920` `ExtractDomain(firstPkt)` | **同时解析 TLS SNI 和 HTTP Host/CONNECT**,测试齐全(`handler_test.go` TestExtractDomain_* / TestReadClientHello_*)—— 但目前只在 smart 路径用 |
| UID 反查 | `handler.go:158` `isUIDBlocked` + `mobile/bridge.go:114` `SetUIDResolver` | per-app「禁止联网」的整套回调链;名单空时短路、零回调 |
| 应用枚举/图标 | AppSelectionActivity + `AppEnumerator` | UID→包名/图标加载逻辑,联网状态页直接复用 |
| 轮询刷新 UI | `LogcatActivity`(2s dump) | 联网状态页 1s 轮询同一模式 |
| 抽屉入口 + 门控 | `MainActivity` `AppDrawerContent` | 现有入口门控写法(`Build.VERSION.SDK_INT >= ...`)可对齐 |

**缺口(本次新增):**

1. 非 smart TCP / UDP 的域名提取 —— UDP 的主域名来源是 **QUIC**(TLS 1.3 握手首包带 SNI),需新增 QUIC ClientHello 解析
2. 无条件的 UID 解析(监控开启时,不受 blocked_uids 名单短路影响)
3. 字节计数(TCP `net.Conn` / UDP `N.PacketConn` 包计数 wrapper)
4. 有界连接表 + JSON 快照 API(`getConnectionStats`)
5. 联网状态 UI 页 + 抽屉入口(懒开关)
6. 应用页加载文案

## 4. 引擎采集层(internal/tun)

### 4.1 UID 解析改造:拆两步,互不污染

把 `isUIDBlocked`(handler.go:158-177)拆开:

- `resolveUID(proto, src, dst) int32`:调 `uidResolverFn` 回调拿 UID,失败 -1(沿用现有 fail-open 语义)
- `isUIDBlocked`:**保持"名单空短路、不回调"不变**(per-app 禁止联网的零开销哲学不能破);名单非空才 `resolveUID` + 匹配

新增监控开关 `connStats atomic.Bool`(默认 off):

- **on**(联网状态页打开):`NewConnectionEx` / `NewPacketConnectionEx` **无条件 `resolveUID` 一次**(连接建立频率低,一次 Binder 往返可接受),并登记进监控表
- **off**:一切如现状,零开销

### 4.2 首包域名提取:扩展到全连接

- **smart TCP(80/443)**:`handleSmartConnect` 已做 `ReadClientHello + ExtractDomain`(handler.go:268/276),把结果登记进监控记录即可,不重复解析
- **非 smart TCP**:新增同款 peek(复用 `ReadClientHello`,约 300B / 短 deadline,失败回灌放行)—— 这是非 smart 路径新增延迟的唯一来源,靠 deadline 兜底、绝不让连接卡住
- **UDP**:
  - **QUIC(典型 443)**:UDP 最主要携带域名信息的协议。新增 QUIC ClientHello SNI 提取:解 long header → Initial 包 CRYPTO frame → 复用现有 TLS extension 解析找 `server_name`。**尽力而为**:解析失败显示目标 IP。
  - 其他 UDP(游戏 / RTP / 自定义):无域名,显示目标 IP + 端口(诚实标注)。

### 4.3 字节计数

- TCP:`conn net.Conn` 包 `countingConn`(Read/Write 各累计 up/down,atomic)
- UDP:`conn N.PacketConn` 包 `countingPacketConn`(ReadPacket/WritePacket 计数)
- 计数归属 4.1 解析出的 UID;peek 读走的首包字节也在 wrapper 内,不漏记

### 4.4 有界连接表 + 淘汰

```
map[uid] → []connRecord{ proto, domain, ip, port, upBytes, downBytes, lastSeen }
```

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
- **onCreate**:`Mobile.setConnStatsEnabled(true)` + loading(转圈 + "正在采集连接数据…")
- **每秒轮询** `getConnectionStats`(复用 LogcatActivity 轮询模式,1s)
- **首个数据到 → loading 消失**,渲染 app 分组树
- **onDestroy**:`Mobile.setConnStatsEnabled(false)`
- 组头:应用图标 + 名 + ↑/↓ 实时速度(KB/s,δ)
- 点击展开:连接明细行 —— 域名/SNI(无则 IP):端口 + TCP/UDP 徽标 + 累计上下行
- 空态:"暂无联网应用"(无联网 app 天然不进表)
- UID→包名/图标:复用 `AppEnumerator`

### 6.2 应用选择页加载提示(AppSelectionActivity)

- `!loaded` 分支(360 行,现仅转圈):转圈旁加文案 "正在加载应用列表… 首次可能较慢"
- 保持简单,不引入分阶段渲染;文案即满足"信息提示"

## 7. 测试与 CI

**Go 单测(新增):**
- QUIC SNI 提取:正常首包 / 畸形包 / 非 QUIC(UDP 其它)→ 空不 panic
- 非 smart TCP peek:回灌不丢数据、超时即放行
- 连接表:满上限淘汰、idle 30s 移除、并发读写不 panic
- 字节计数:up/down 正确

**e2e 约束:**联网状态**不进断言**(遵循既有方法论:双引擎只能做单引擎正断言;全局计数器 TCP 关闭才结算需轮询)——只保证引擎跑通、监控代码不 panic。

**Android 构建走 CI**(`android-build.yml`,`android/**` 触发),本机不跑 gradle。

**验证:**CI 绿 + 真机手测(打开出列表、速度跳动、展开见域名、关闭页面后引擎恢复零开销)。

## 8. 提交拆分

1. `chore: dist 构建产物进 .gitignore`(含本计划文档)
2. `feat(engine): 连接监控 —— UID 拆分 + 全连接域名提取(含 QUIC SNI)+ 字节计数 + 有界表 + getConnectionStats`(含单测)
3. `feat(mobile): setConnStatsEnabled / getConnectionStats 桥`
4. `feat(android): 联网状态页 + 抽屉入口(懒开关 + loading)`
5. `fix(android): 应用选择页加载提示`

## 9. 风险与开放点

| 风险 / 开放点 | 对策 |
|---|---|
| 非 smart TCP 新增首包 peek 延迟 | 短 deadline + 失败回灌,绝不让连接卡住 |
| UDP 域名覆盖有限 | QUIC 尽力而为;非 QUIC UDP 诚实显示 IP |
| 引擎常开开销 | 懒开关保证不开页面零成本 |
| 字节计数并发 | atomic |
| gomobile JSON 体积 | 有界 2000 条,K 级 |
| 每连接一次 getConnectionOwnerUid Binder | 连接建立频率低,可接受;若耗电明显再上本地端口→UID 缓存 |

## 10. 待确认点(审核重点)

1. **UDP 域名只覆盖 QUIC**,其余 UDP(游戏 / RTP 等)显示 IP —— 接受?
2. **连接 30s 无新流量从明细消失**(速度自然归零,app 仍显示但展开无行)—— 接受?时长要不要调?
3. **轮询 1s** —— 接受?要更密(实时感强但耗电/开销升)还是更疏?
4. **QUIC SNI 解析**(新增 ~100-150 行,尽力而为)列入本期 —— 接受?若嫌重可降级为 UDP 一律显示 IP,后续再补。
