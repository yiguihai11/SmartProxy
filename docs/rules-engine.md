# 规则引擎（ACL）

规则引擎负责解析 ACL 规则文件（默认 `acl.txt`），并提供精确/前缀级别的匹配查询，是智能路由的第一道判断。实现位于 `internal/rules/`（`engine.go`、`suffix_trie.go`）。

## §1 规则模型

规则文件为纯文本，每行一条，格式：

```
<action> <type> <value> [alias]
```

- 空行与以 `#` 开头的行被跳过。
- 整行先 `strings.ToLower` 再 `strings.Fields` 切分，因此规则大小写不敏感。
- 字段不足 2 个的行忽略；`proxy` 规则要求至少 4 个字段（action、type、value、alias）。

| action | 含义 | alias 是否必须 |
| --- | --- | --- |
| `allow` | 放行（直连），优先级最高 | 无 |
| `block` | 阻断 | 无 |
| `proxy` | 走指定上游代理 | 必须（第 4 字段） |

| type | value 示例 | 说明 |
| --- | --- | --- |
| `port` | `443` | 精确端口 |
| `ip` | `1.2.3.4` 或 `10.0.0.0/8` | 精确 IP；含 `/` 时按 CIDR 解析 |
| `cidr` | `10.0.0.0/8` | 强制按 CIDR 解析，裸地址退化为 /32 或 /128 |
| `domain` | `example.com`、`*.example.com` 或 `*ads*-*.domain.com` | 精确域名、子域通配符后缀或 Glob 泛通配符 |

示例（`internal/rules/engine_test.go` 中大量用例）：

```
# 注释
block port 25
allow port 53
block ip 192.168.1.100
block cidr 10.0.0.0/8
block domain *.tracker.com
block domain *ads*-*.zijieapi.com
proxy port 22 ssh_proxy
proxy cidr 10.0.0.0/8 internal
proxy domain google.com direct
```

## §2 优先级语义

allow 严格优先于 block；匹配 proxy 规则前先做 allow 判定，命中即直接放行、不再走代理。具体顺序：

- `IsPortBlocked(port)`：`allowedPorts` → false；否则查 `blockedPorts`。
- `IsIPBlocked(ip)`：`allowedIPs` → false；`allowedCIDR.Contains` → false；否则 `blockedIPs` → true / `blockedCIDR.Contains`。
- `IsDomainBlocked(domain)`：`allowedDomains` → false；`allowedSuffixes.match` → false；`allowedGlobs`（`path.Match`）→ false；否则 `blockedDomains` → true / `blockedSuffixes.match` / `blockedGlobs`（`path.Match`）。
- `MatchProxyRule(ip, port, domain)` 的检查顺序为 **allow（port→ip→cidr→domain/suffix/glob）→ proxy（port→ip→domain→suffix→glob→cidr）**；allow 命中直接返回 `("", false)`。

`*.example.com` 走高性能前缀树（Trie），匹配其全部子域（`www.example.com`）**以及 apex 本身（`example.com`）**（见 `TestSuffixTrie_MatchApexDomain`）。多条后缀规则同时命中时取最深的一条（`*.api.example.com` 优先于 `*.example.com`）。含 `*` 或 `?` 的非纯子域规则（如 `*ads*-*.zijieapi.com`）自动进入 Glob 匹配器。

## §3 数据结构

| 数据结构 | 用途 |
| --- | --- |
| `map[int]bool` / `map[string]bool` | 精确 port / ip / domain 的 allow 与 block |
| `map[int]string` / `map[string]string` | 精确 port / ip / domain 的 proxy（value→alias） |
| `suffixTrie` | 纯通配符域名后缀（`*.x.com`）的 allow/block 匹配 |
| `proxySuffixTrie` | 带 alias 的纯域名后缀 trie |
| `[]string` / `[]proxyGlobRule` | 泛通配符（Glob）域名规则，支持任意位置的 `*` 和 `?` 通配 |
| `chnroute.Trie` | CIDR（`allowedCIDR` / `blockedCIDR`），支持前缀包含查询 |
| `proxyCidrTrie` | 带 alias 的 CIDR 二分 trie（IPv4 偏移 96 bit，IPv6 从 0 bit） |

`suffixTrie` 按标签从右到左（逆序）插入，`match` 返回是否存在任意子域命中。`proxyCidrTrie.lookup` 在遍历过程中记录最近一次 alias（最长前缀命中），`size()` 返回唯一 prefix 数量。

## §4 Copy-on-Write 快照设计（核心）

早期实现用单个 `sync.RWMutex` 保护全部 ACL 字段：热重载（`Reload`）触发写锁时，所有新建连接都要等待，造成 CPU 抖动与延迟毛刺。

现在重构为 Copy-on-Write 快照：

1. **16 个 ACL 字段全部封装进 `ruleSet` 结构体**（`allowedPorts`、`allowedIPs`、`allowedCIDR`、`allowedDomains`、`allowedSuffixes` 5 个，`blocked*` 同 5 个，`proxyPorts`、`proxyIPs`、`proxyCIDRTrie`、`proxyDomains`、`proxySuffixes`、`proxyRules` 6 个）。`ruleSet` 一经发布即为不可变快照。
2. `Engine` 只持有一个字段：`rules atomic.Pointer[ruleSet]`。
3. **读取路径**（`IsPortBlocked` / `IsIPBlocked` / `IsDomainBlocked` / `MatchProxyRule`）：`rs := e.rules.Load()`，对 nil 做防护后直接取值，**完全无锁**。
4. **写入路径**（`Load` / `Reload`）：`newRuleSet()` 构建全新快照 → `rs.load(path)` 逐行解析 → 成功后才 `e.rules.Store(rs)` 原子交换。读者要么持旧快照、要么持新快照，绝无中间态；解析失败旧快照继续生效。
5. **零值 Engine 防护**：`e.rules.Load()` 返回 nil（未 Load 过的 `Engine{}`）时各查询方法返回 false / 空值，不 panic。
6. **`ProxyRules()` 访问器**：返回当前快照的 `proxyRules` 切片（注释明确"必须不可修改"），供 admin / 统计读取。

并发验证（`internal/rules/engine_test.go`）：

- `TestEngine_ConcurrentReadDuringReload`：8 个并发读者 + 3 个写者各重载 50 次，读者始终看到一致快照，`-race` 通过。
- `TestEngine_ConcurrentMatchProxy`：4 协程 × 100 轮对多种 proxy 规则并发匹配，结果确定。

**设计权衡**：每次重载全量重建快照（O(规则数)），但重载频率远低于查询频率，且消除了所有读路径锁竞争，值得。

## §5 开发注意事项

1. proxy 规则的重复 value 采用"先到先得"（如两条 `proxy port 80 x`，保留第一条 alias）；allow/block 的 map 天然幂等。
2. 无效行被跳过但不报错（如 `block port abc`），见 `TestEngine_InvalidRulesIgnored`。
3. 解析用 `net/netip`；`parseCIDRInto` 对裸地址做 `/bitlen` 退化，IPv6 单地址同理（`TestEngine_ProxyRuleCIDR_IPv6_SingleHost`）。
4. 域名匹配统一走 `normalizeDomain`（去尾点 + 转小写）。
5. 广告过滤规则属于独立订阅功能（详见 [DNS AdBlock](adblock.md)），仅在 DNS 层生效。ACL 引擎 `internal/rules` 不参与广告过滤，ACL 的 `allow domain` 亦不豁免广告过滤。

## §6 默认池区域过滤（default 排除与限定）

当规则指定走 `default`（由低延迟优先/轮询自动选路）时，支持通过后缀操作符对候选代理池进行**国家与区域过滤**，兼顾自动化负载均衡与特定业务的区域合规/内容解锁需求。

### 语法格式

| 语法格式 | 模式 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `default!<regions>` | **排除模式** | 从默认池中选路，但**排除**指定的区域或国家 | `proxy domain *.x.com default!eu,au,cn` |
| `default@<regions>` | **限定模式** | **仅在**指定的国家/区域节点中按延迟优选 | `proxy domain *.openai.com default@us,jp,sg` |
| `default` | **全量模式** | 默认池全量优选（无过滤） | `proxy domain *.github.com default` |

### 规则特性

1. **大小写不敏感**：区域代码支持全大写（`EU,AU`）、全小写（`eu,au`）或混写（`Eu,Au`），解析时自动规范化。
2. **多区域逗号分隔**：支持逗号分隔多个区域，允许带空格（如 `default!eu, au, cn`）。
3. **内置区域宏（Region Macros）**：
   - `EU`：自动展开为欧盟 27 个成员国（`AT`, `BE`, `BG`, `HR`, `CY`, `CZ`, `DK`, `EE`, `FI`, `FR`, `DE`, `GR`, `HU`, `IE`, `IT`, `LV`, `LT`, `LU`, `MT`, `NL`, `PL`, `PT`, `RO`, `SK`, `SI`, `ES`, `SE`）。
   - `UK`：英国（`GB`）。
   - `AU`：澳大利亚（`AU`）。
   - `CN`：中国（`CN`）。
   - `NA`：北美（`US`, `CA`, `MX`）。
   - `AP`：亚太（`HK`, `TW`, `JP`, `KR`, `SG`）。
   - 以及任何标准 ISO 3166-1 两位国家代码（如 `US`, `JP`, `HK`, `DE` 等）。
4. **真实出口国家码精准匹配**：严格基于 Cloudflare Anycast trace / Cymru DNS 真实探测得到的出口 IP 国家码（`p.CountryCode()`），不依赖任何易被虚标伪造的节点名称硬编码推测。未完成实测探测的节点在排除模式下默认不误杀，确保网络平滑过渡。
5. **容灾兜底（Resilience Fallback）**：若订阅池中所有节点均被过滤排除，系统会自动回退至未过滤的健康节点并记录 Warn 日志，避免发生完全断网。
