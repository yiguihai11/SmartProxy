# SmartProxy - 智能 SOCKS5 代理服务器

一个基于 Go 语言实现的高性能 SOCKS5 代理服务器，支持智能路由、访问控制、实时内存监控和 UDP Full Cone NAT 穿透等功能。

## 🎯 核心特性

### ✅ 代理功能
- **完整的 SOCKS5 协议支持** - 标准 RFC 1928 实现，支持 TCP 和 UDP
- **IPv4/IPv6 双栈支持** - 完整的 IPv4 和 IPv6 支持
- **UDP Full Cone NAT** - 支持 UDP 中继和 NAT 穿透
- **多用户认证** - 支持用户名/密码认证，PBKDF2 密码哈希

### ✅ 智能路由
- **基于规则的流量路由** - 国内直连、国外代理、自定义屏蔽
- **中国路由表支持** - 基于 chnroutes.txt 的智能分流
- **SmartProxy 智能检测** - 自动检测 GFW 干扰并切换到代理
- **动态黑名单管理** - 自动屏蔽被干扰的地址，可配置过期时间

### ✅ 性能优化
- **基数树路由引擎** - O(32) 时间复杂度的高效 IP 网段匹配
- **连接池优化** - 使用 sync.Pool 重用连接和缓冲区对象
- **内存监控** - 实时监控系统内存使用情况
  - GC 效率监控
  - 对象池命中率统计
  - 连接数和会话数追踪
- **零外部依赖** - 仅使用 Go 标准库

### ✅ 访问控制
- **用户组管理** - 支持多用户组和权限控制
- **连接限制** - 最大连接数、IP 白名单/黑名单
- **时间限制** - 支持按时间段控制访问
- **限速功能** - 上传/下载速度限制

### ✅ Web 管理界面
- **实时监控** - HTTP API 提供系统状态监控
- **内存统计** - 详细的内存使用情况
  - `/api/memory/stats` - 基础内存统计
  - `/api/memory/usage` - 内存使用详情
  - `/api/memory/efficiency` - 内存效率分析
  - `/api/memory/pools` - 对象池统计

## 📁 项目结构

```
smartproxy/
├── main.go                      # 程序入口点
├── go.mod/go.sum                # Go 模块配置
├── smartproxy                   # 编译生成的可执行文件
├── Makefile                     # 构建脚本
├── README.md                    # 本文件
├── config/                      # 配置管理
│   └── manager.go               # 配置文件管理器
├── conf/                        # 配置文件目录
│   ├── config.json              # 主配置文件
│   ├── chnroutes.txt            # 中国大陆 IP 段数据
│   └── config.example.json      # 配置文件示例
├── dns/                         # DNS 服务模块
│   └── dns.go                   # DNS 服务器实现
├── socks5/                      # SOCKS5 核心模块
│   ├── socks5.go                # SOCKS5 协议实现
│   ├── router.go                # 基数树路由器
│   ├── pool.go                  # 连接池和缓冲区池
│   ├── memory_monitor.go        # 内存监控器
│   ├── nat_traversal.go         # NAT 穿透功能
│   ├── ratelimit.go             # 限速功能
│   ├── auth.go                  # 认证管理
│   ├── detection.go             # 流量检测
│   └── blocked_items_manager.go # 黑名单管理
├── web/                         # Web 管理界面
│   ├── server.go                # Web 服务器
│   └── static/                  # 静态资源
├── logger/                      # 日志模块
│   └── logger.go                # 结构化日志
└── examples/                    # 示例代码
    └── test_proxy.go            # SOCKS5 代理测试示例
```

## 🚀 快速开始

### 编译

```bash
# 使用 Makefile（推荐）
make build

# 或手动编译
export CGO_ENABLED=0
go build -o smartproxy .

# 强制重新编译
make build-force
```

### 运行

```bash
# 使用默认配置
./smartproxy

# 使用自定义配置文件
./smartproxy --config conf/config.json

# 后台运行
nohup ./smartproxy --config conf/config.json > smartproxy.log 2>&1 &
```

### 设置代理

在你的应用程序中设置代理为：
- **SOCKS5 代理**: 127.0.0.1:1080
- **Web 管理**: http://127.0.0.1:8080

### 测试功能

```bash
# 测试 SOCKS5 代理功能
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# 测试 UDP（需要支持 SOCKS5 UDP 的客户端）
# 可以使用提供的测试脚本
python test_udp_fullcone.py

# 查看内存监控数据
curl http://127.0.0.1:8080/api/memory/stats
```

## ⚙️ 配置文件

配置文件位于 `conf/config.json`，主要包含以下部分：

### 1. 监听器配置
```json
{
  "listener": {
    "socks5_port": 1080,        // SOCKS5 代理端口
    "web_port": 8080,            // Web 管理端口
    "dns_port": 1053,            // DNS 服务端口
    "ipv6_enabled": false        // 是否启用 IPv6
  }
}
```

### 2. SmartProxy 智能检测
```json
{
  "smart_proxy": {
    "enabled": true,                         // 启用智能检测
    "timeout_ms": 1500,                      // 连接超时时间
    "blacklist_expiry_minutes": 360,         // 黑名单过期时间（分钟）
    "probing_ports": [80, 8080, 443, 8443]  // 检测端口
  }
}
```

### 3. 用户认证和限速
```json
{
  "socks5": {
    "enable_auth": true,
    "auth_users": [
      {
        "username": "admin",
        "password": "AdminPass123!",
        "enabled": true,
        "user_groups": ["admin"],
        "rate_limit": {
          "upload_bps": 10485760,    // 10MB/s 上传限速
          "download_bps": 10485760   // 10MB/s 下载限速
        },
        "connection_limit": {
          "max_connections": 10,
          "expires_after_minutes": 60,
          "allow_from_ips": ["192.168.0.0/16"],
          "block_from_ips": ["10.0.0.1"],
          "time_restriction": {
            "allowed_hours": ["09:00-18:00"],
            "allowed_days": ["monday-friday"],
            "timezone": "Asia/Shanghai"
          }
        }
      }
    ]
  }
}
```

### 4. 路由规则
```json
{
  "router": {
    "chnroutes": {
      "enable": true,
      "path": "conf/chnroutes.txt"
    },
    "rules": [
      {
        "action": "allow",
        "patterns": ["*.cn", "baidu.com", "qq.com"],
        "description": "中国网站直连"
      },
      {
        "action": "deny",
        "patterns": ["*.google.com", "*.youtube.com"],
        "description": "国外网站走代理"
      },
      {
        "action": "block",
        "patterns": ["*.adsystem.com"],
        "description": "屏蔽广告"
      }
    ]
  }
}
```

## 📊 内存监控 API

### 获取内存统计
```bash
# 基础内存统计
curl http://127.0.0.1:8080/api/memory/stats

# 内存使用详情
curl http://127.0.0.1:8080/api/memory/usage

# 内存效率分析
curl http://127.0.0.1:8080/api/memory/efficiency

# 对象池统计
curl http://127.0.0.1:8080/api/memory/pools
```

### 返回数据示例
```json
{
  "system_memory": {
    "allocated_bytes": 5408272,
    "system_bytes": 17063952,
    "gc_count": 3,
    "gc_pause_ms": 2
  },
  "application_memory": {
    "active_connections": 1,
    "active_udp_sessions": 2,
    "dns_cache_entries": 0
  },
  "pool_stats": {
    "buffer_pool": {
      "hit_rate_percent": 100,
      "active_objects": 2,
      "total_memory_mb": 0.13
    },
    "connection_pool": {
      "hit_rate_percent": 0,
      "reuse_rate_percent": 0,
      "created_connections": 2
    }
  }
}
```

## 🔧 运行日志示例

启动时的日志输出：
```
=== SmartProxy运行日志 ===
Using SOCKS5 port from config: 1080
[SOCKS5] SOCKS5 server listening on IPv4 only
[SOCKS5] SmartProxy is enabled.
[SOCKS5] Blacklist manager initialized with 251 shards and 6h0m0s expiry duration.
[SOCKS5] PasswordHasher initialized: pbkdf2-sha256, iterations=100000, salt_length=32
[Router DEBUG] China IP matched: 125.88.253.199 -> action=allow
Web server initialized successfully
Config file: conf/config.json

服务已启动:
  SOCKS5代理: 127.0.0.1:1080
  Web管理: http://127.0.0.1:8080
```

## 🛠️ 开发和测试

### 系统要求
- **Go 版本**: 1.21+
- **平台**: Linux、macOS、Windows、Android(Termux)
- **内存**: 最小 64MB RAM
- **权限**: 网络连接权限

### 性能特性
- **基数树路由**: O(32) 时间复杂度的 IP 网段匹配
- **连接池优化**: 100% 命中率的缓冲区池
- **内存效率**: 实时监控，GC 效率 > 70%
- **高并发**: 支持数千并发连接

### 故障排除

1. **连接池命中率为 0%**
   - 这是正常的，每个 TCP 连接需要独立的 Connection 对象
   - 关键是对象复用减少了 GC 压力

2. **UDP 会话数显示 0**
   - 已修复，使用 Full Cone NAT 模式的会话统计

3. **端口被占用**
   - 修改配置文件中的端口号

4. **SmartProxy 检测频繁**
   - 调整 `blacklist_expiry_minutes` 增加黑名单缓存时间
   - 调整 `timeout_ms` 优化检测超时

## 📄 许可证

本项目采用 MIT 许可证。

## 🙏 致谢

- 中国 IP 段数据 contributors
- Go 语言社区