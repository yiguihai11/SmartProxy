# Admin API 文档

通过 Unix domain socket 暴露的管理接口。配置 `listen.admin_socket` 启用。

## 通用说明

### 连接方式

```bash
curl --unix-socket /path/to/admin.sock http://localhost/{endpoint}
```

Python：

```python
import socket, http.client

conn = http.client.HTTPConnection("localhost")
conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
conn.sock.connect("/path/to/admin.sock")
conn.request("GET", "/stats")
resp = conn.getresponse()
```

### 返回格式

所有响应均为 `application/json`。成功时 HTTP 状态码为 200/204，失败时返回 400/404/405 等。

---

## 端点列表

| 端点 | 方法 | 说明 |
|---|---|---|
| [`/stats`](#stats) | GET | 流量统计、进程资源 |
| [`/route`](#route) | GET | 路由表信息 |
| [`/health`](#health) | GET | 上游代理健康状态 |
| [`/health/proxy`](#health-proxy) | POST | 手动禁用/启用/释放代理电路 |
| [`/health/reset-auto`](#health-reset-auto) | POST | 一键恢复因检测异常而自动关闭的电路 |
| [`/cache`](#cache) | GET | DNS 缓存统计 |
| [`/cache`](#cache-delete) | DELETE | 删除单条 DNS 缓存 |
| [`/cache/flush`](#cache-flush) | POST | 清空全部 DNS 缓存 |
| [`/blacklist`](#blacklist) | GET | 动态黑名单列表 |
| [`/blacklist`](#blacklist-delete) | DELETE | 删除黑名单条目 |
| [`/config`](#config) | GET / PUT | 读取 / 写入并重载配置文件 |
| [`/acl`](#acl) | GET / PUT | 读取 / 写入 ACL 规则文件 |
| [`/chnroute`](#chnroute) | GET / PUT | 读取 / 写入 chnroute 文件（PUT 先解析校验） |
| [`/acl/add`](#acl-add) | POST | 追加 ACL 规则（去重） |
| [`/config/reload`](#config-reload) | POST | 重载配置文件 |
| [`/logs`](#logs) | GET | 程序日志列表（内存环形缓冲区最多 500 条） |

---

## `/stats` {#stats}

**GET** — 流量统计 + 进程资源。

### 请求

```bash
curl --unix-socket /tmp/admin.sock http://localhost/stats
```

### 响应

```json
{
  "tcp": {
    "proxy_bytes_up": 12345678,
    "proxy_bytes_down": 87654321,
    "direct_bytes_up": 0,
    "direct_bytes_down": 0,
    "active_conns": 3
  },
  "udp": {
    "proxy_bytes_up": 4096,
    "proxy_bytes_down": 2048,
    "direct_bytes_up": 0,
    "direct_bytes_down": 0,
    "active_sessions": 1
  },
  "process": {
    "goroutines": 10,
    "gomaxprocs": 8,
    "alloc_mb": "2.1",
    "total_alloc_mb": "15.3",
    "num_gc": 42,
    "last_gc_pause": "1.23ms",
    "cpu_percent": 0.5,
    "uptime": "1h23m"
  }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `tcp.proxy_bytes_up/down` | int64 | TCP 代理上下行字节数 |
| `tcp.direct_bytes_up/down` | int64 | TCP 直连上下行字节数 |
| `tcp.active_conns` | int32 | 当前活跃 TCP 连接数 |
| `udp.proxy_bytes_up/down` | int64 | UDP 代理上下行字节数 |
| `udp.direct_bytes_up/down` | int64 | UDP 直连上下行字节数 |
| `udp.active_sessions` | int32 | 当前活跃 UDP 会话数 |
| `process.goroutines` | int | 当前 goroutine 数（排查泄漏用） |
| `process.gomaxprocs` | int | Go 运行时使用的 CPU 数 |
| `process.alloc_mb` | string | 当前堆分配内存 |
| `process.total_alloc_mb` | string | 累计分配内存（GC 压力指标） |
| `process.num_gc` | uint32 | GC 次数 |
| `process.last_gc_pause` | string | 最近一次 GC STW 耗时 |
| `process.cpu_percent` | float64 | 进程启动以来平均 CPU 使用率 |
| `process.uptime` | string | 运行时长 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

---

## `/route` {#route}

**GET** — chnroute 路由表信息。

### 请求

```bash
curl --unix-socket /tmp/admin.sock http://localhost/route
```

### 响应

```json
{
  "loaded": true,
  "entries": 10729,
  "v4": 8684,
  "v6": 2039
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `loaded` | bool | chnroute 是否已加载 |
| `entries` | int | 路由表总节点数 |
| `v4` | int | IPv4 前缀数量 |
| `v6` | int | IPv6 前缀数量 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

---

## `/health` {#health}

**GET** — 上游代理健康状态。

### 请求

```bash
curl --unix-socket /tmp/admin.sock http://localhost/health
```

### 响应

```json
{
  "strategy": "failover",
  "proxies": [
    {
      "alias": "ss-local",
      "url": "socks5://127.0.0.1:1081",
      "host": "127.0.0.1",
      "port": 1081,
      "scheme": "socks5",
      "health": {
        "state": "closed",
        "available": true,
        "latency": 12500000,
        "consecutive_failures": 0,
        "consecutive_successes": 5,
        "last_attempt": "2026-07-23T12:00:00+08:00",
        "open_since": ""
      }
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `strategy` | string | 当前路由策略（failover/round_robin/random/latency） |
| `proxies[].alias` | string | 代理别名 |
| `proxies[].url` | string | 代理 URL |
| `proxies[].scheme` | string | 协议类型（socks5/http） |
| `proxies[].health.state` | string | 断路器状态：`closed`（正常）/ `open`（断开）/ `half_open`（探测中） |
| `proxies[].health.available` | bool | 是否可用（state 不为 open） |
| `proxies[].health.latency` | int64 | 最近一次健康检查延迟（纳秒） |
| `proxies[].health.consecutive_failures` | int | 连续失败次数（超阈值触发断路器 open） |
| `proxies[].health.consecutive_successes` | int | 连续成功次数 |
| `proxies[].health.last_attempt` | string | 最近一次检查时间（RFC3339） |
| `proxies[].health.open_since` | string | 断路器 open 起始时间 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

---

## `/health/proxy` {#health-proxy}

**POST** — 手动禁用或启用某个上游代理。

### 请求

```bash
curl -X POST --unix-socket /tmp/admin.sock \
  'http://localhost/health/proxy?alias=ss-local&action=disable'
```

| 参数 | 必填 | 说明 |
|---|---|---|
| `alias` | 是 | 代理别名 |
| `circuit` | 否 | `tcp` / `udp` / `both`（默认 `both`） |
| `action` | 是 | `disable`、`enable` 或 `auto` |

`circuit` 指定操作哪条电路（TCP / UDP / 两条），`action`：
- `disable` — 手动钉死为不可用（探测也不再拨号，直到 `enable`/`auto`）；
- `enable` — 手动钉死为可用（立即生效）；
- `auto` — 释放手动 pin，交回健康检查自动控制。

### 响应

```json
{"status": "ok"}
```

### 错误

| 状态码 | 说明 |
|---|---|
| 400 | 缺少 `alias` 或 `action` 参数，或 `action` 不是 `disable/enable/auto` |
| 404 | `alias` 不存在 |
| 405 | 只接受 POST |

---

## `/health/reset-auto` {#health-reset-auto}

**POST** — 一键恢复节点：把所有因健康检查探测失败而**自动 open** 的电路（TCP/UDP）回到 `closed`（立即可用，并由下一次探测重新验证）。**不动任何手动 pin**（用户手动 disable / enable 的电路保持原状），恢复是临时的——再次探测失败仍走正常流程重新 open。

### 请求

```bash
curl -X POST --unix-socket /tmp/admin.sock http://localhost/health/reset-auto
```

### 响应

```json
{"status": "ok", "reset": 2}
```

`reset` 为本次恢复的电路数（无自动关闭电路时为 0）。

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 POST |

---

## `/cache` {#cache}

**GET** — DNS 缓存统计。

### 请求

```bash
curl --unix-socket /tmp/admin.sock http://localhost/cache
```

### 响应

```json
{"entries": 42}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `entries` | int | 当前缓存条目数 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

---

## `/cache`（DELETE）{#cache-delete}

**DELETE** — 删除单条 DNS 缓存。

### 请求

```bash
curl -X DELETE --unix-socket /tmp/admin.sock \
  'http://localhost/cache?qname=example.com&qtype=1'
```

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `qname` | 是 | — | 域名（如 `example.com`） |
| `qtype` | 否 | `1` | DNS 记录类型（1=A, 28=AAAA, 65=HTTPS） |

### 响应

HTTP 204 No Content，无响应体。

### 错误

| 状态码 | 说明 |
|---|---|
| 400 | 缺少 `qname` |
| 405 | 只接受 DELETE |

---

## `/cache/flush` {#cache-flush}

**POST** — 清空全部 DNS 缓存。

### 请求

```bash
curl -X POST --unix-socket /tmp/admin.sock http://localhost/cache/flush
```

### 响应

```json
{"status": "ok"}
```

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 POST |

---

## `/blacklist` {#blacklist}

**GET** — 动态黑名单列表。

### 请求

```bash
curl --unix-socket /tmp/admin.sock http://localhost/blacklist
```

### 响应

```json
[
  {
    "type": "ip",
    "host": "10.0.0.1",
    "port": 443,
    "last_reason": "i/o timeout",
    "expires_at": "2026-07-23 15:30:00"
  },
  {
    "type": "domain",
    "host": "evil.com",
    "port": 443,
    "last_reason": "connection reset by peer",
    "expires_at": "2026-07-23 15:28:00"
  }
]
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `type` | string | `ip` 或 `domain` |
| `host` | string | 被拉黑的 IP 或域名 |
| `port` | int | 端口 |
| `last_reason` | string | 拉黑原因 |
| `expires_at` | string | 过期时间 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

---

## `/blacklist`（DELETE）{#blacklist-delete}

**DELETE** — 删除黑名单条目。

### 请求

```bash
# 只删 IP 黑名单
curl -X DELETE --unix-socket /tmp/admin.sock \
  'http://localhost/blacklist?host=10.0.0.1&type=ip'

# 只删域名黑名单
curl -X DELETE --unix-socket /tmp/admin.sock \
  'http://localhost/blacklist?host=evil.com&type=domain'

# 两个表都删（不传 type）
curl -X DELETE --unix-socket /tmp/admin.sock \
  'http://localhost/blacklist?host=test.com'
```

| 参数 | 必填 | 说明 |
|---|---|---|
| `host` | 是 | IP 或域名 |
| `type` | 否 | 限定范围：`ip` / `domain`；不传则两个表都删 |

### 响应

HTTP 204 No Content，无响应体。

### 错误

| 状态码 | 说明 |
|---|---|
| 400 | 缺少 `host` |
| 405 | 只接受 DELETE |

---

## `/config/reload` {#config-reload}

**POST** — 从磁盘重新加载配置文件。与文件变化触发的 reload 走同一逻辑。

### 请求

```bash
curl -X POST --unix-socket /tmp/admin.sock http://localhost/config/reload
```

### 响应

```json
{"status": "ok"}
```

### 错误

| 状态码 | 说明 |
|---|---|
| 503 | 程序未配置 reload 回调（启动时未设置） |
| 405 | 只接受 POST |

---

## `/config` {#config}

**GET / PUT** — 读取或写入配置文件（Configuration 标签页的编辑/复制功能依赖）。

### GET

返回当前生效配置的 JSON。

```bash
curl --unix-socket /tmp/admin.sock http://localhost/config
```

### PUT

用请求体覆盖写盘 `config.json` 并立即重载。

```bash
curl -X PUT --unix-socket /tmp/admin.sock -d @config.json http://localhost/config
```

| 状态码 | 说明 |
|---|---|
| 400 | 请求体不是合法 JSON，或 `Validate()` 校验失败（不写盘） |
| 503 | 未配置 `configPath` / reload 回调 |
| 405 | 只接受 GET/PUT |

---

## `/acl` {#acl}

**GET / PUT** — 读取或写入 ACL 规则文件（`routing.acl_file`）。

### GET

返回 ACL 文件原始文本（`text/plain`）。

```bash
curl --unix-socket /tmp/admin.sock http://localhost/acl
```

### PUT

用请求体覆盖写盘 ACL 文件。写盘后由 fsnotify watcher 检测到变更并自动重载引擎。

| 状态码 | 说明 |
|---|---|
| 503 | 未配置 ACL 路径 / config 源 |
| 405 | 只接受 GET/PUT |

---

## `/chnroute` {#chnroute}

**GET / PUT** — 读取或写入 chnroute 文件（`routing.chnroute_file`），并支持**直接解析写入**（上传功能）。

### GET

返回 chnroute 文件原始文本（`text/plain`）。

```bash
curl --unix-socket /tmp/admin.sock http://localhost/chnroute
```

### PUT

用请求体覆盖写盘 chnroute 文件，**写盘前先解析校验**（`chnroute.Parse`）：内容中无任何有效 CIDR 前缀时拒绝写入，返回 400。写盘后由 fsnotify watcher 自动重载引擎。

```bash
curl -X PUT --unix-socket /tmp/admin.sock \
  --data-binary @chnroute.txt http://localhost/chnroute
```

| 状态码 | 说明 |
|---|---|
| 400 | 内容解析失败或**无有效 CIDR 前缀**（不写盘） |
| 503 | 未配置 chnroute 路径 / config 源 |
| 405 | 只接受 GET/PUT |

---

## `/acl/add` {#acl-add}

**POST** — 向 ACL 文件追加规则条目（去重）。

### 请求

```json
{
  "entries": [
    {"type": "domain", "value": "evil.com", "action": "block"},
    {"type": "ip", "value": "8.8.8.8", "action": "proxy", "upstream": "ss-local"}
  ]
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `entries[].type` | 是 | `domain` 或 `ip` |
| `entries[].value` | 是 | 规则值 |
| `entries[].action` | 是 | `allow` / `block` / `proxy` |
| `entries[].upstream` | `proxy` 时必填 | 上游别名 |

单次最多 200 条。已存在的规则自动跳过。写入后触发 reload。

| 状态码 | 说明 |
|---|---|
| 400 | 参数非法 / 超 200 条 / 上游缺失 |
| 503 | 未配置 ACL 路径 |
| 405 | 只接受 POST |

---

## `/logs` {#logs}

**GET** — 获取程序日志列表。存储于 500 条固定容量内存环形缓冲区，重启后清空，不写磁盘。

### 请求

```bash
curl --unix-socket /tmp/admin.sock 'http://localhost/logs?level=INFO'
```

| 参数 | 必填 | 说明 |
|---|---|---|
| `level` | 否 | 过滤级别：`ALL` / `INFO` / `WARN` / `ERROR` / `DEBUG` (不区分大小写，不传则返回全部) |

### 响应

```json
[
  {
    "id": 1,
    "time": "2026-07-28 01:12:30",
    "level": "INFO",
    "message": "admin server started socket=/tmp/admin.sock"
  },
  {
    "id": 2,
    "time": "2026-07-28 01:12:31",
    "level": "WARN",
    "message": "admin TCP listen failed port=8080 error=listen tcp :8080: bind: address already in use"
  }
]
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | uint64 | 日志递增序号 |
| `time` | string | 日志时间戳 (`YYYY-MM-DD HH:MM:SS`) |
| `level` | string | 日志级别 (`INFO`/`WARN`/`ERROR`/`DEBUG`) |
| `message` | string | 日志消息体及附加属性 |

### 错误

| 状态码 | 说明 |
|---|---|
| 405 | 只接受 GET |

