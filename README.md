# SmartProxy - 智能 SOCKS5 代理服务器

一个基于 Go 语言实现的高性能 SOCKS5 代理服务器，支持智能路由、访问控制、DNS 劫持和 NAT 穿透等功能。

## 🎯 核心特性

- ✅ **完整的 SOCKS5 协议支持** - 标准 RFC 1928 实现
- ✅ **基数树路由引擎** - 高效的 IP 网段匹配，支持大规模规则集
- ✅ **IPv4/IPv6 双栈支持** - 完整的 IPv4 和 IPv6 支持
- ✅ **智能路由系统** - 国内直连、国外代理、自定义屏蔽
- ✅ **GFW 干扰检测** - 自动检测连接重置并切换到代理
- ✅ **智能 DNS 服务** - 支持国内/国外 DNS 分流、DNS 劫持
- ✅ **访问控制** - 基于用户组、IP、时间的访问控制
- ✅ **黑名单管理** - 动态黑名单，自动屏蔽被干扰的地址
- ✅ **限速功能** - 支持用户级、IP 级、全局限速
- ✅ **Web 管理界面** - 实时监控和配置管理
- ✅ **NAT 穿透支持** - STUN/TURN、UDP 打洞、Full Cone NAT
- ✅ **连接池优化** - 使用对象池提升性能
- ✅ **详细日志记录** - 连接状态、路由决策、错误追踪

## 📁 项目结构

```
smartproxy/
├── main.go                      # 程序入口点
├── go.mod                       # Go 模块配置
├── smartproxy                  # 编译生成的可执行文件
├── README.md                    # 本文件
├── Makefile                     # 构建脚本
├── config/                      # 配置管理
│   └── manager.go               # 配置文件管理器
├── conf/                        # 配置文件
│   ├── config.json              # 默认配置文件
│   ├── chnroutes.txt            # 中国大陆 IP 段数据
│   └── config.example.json      # 配置文件示例
├── dns/                         # DNS 服务
│   ├── dns.go                   # 智能 DNS 服务器
│   └── dns_cache.go             # DNS 缓存系统
├── socks5/                      # SOCKS5 核心模块
│   ├── socks5.go                # SOCKS5 协议实现
│   ├── router.go                # 基数树路由器
│   ├── nat_traversal.go         # NAT 穿透功能
│   ├── udp_relay.go             # UDP 中继（已删除）
│   ├── ratelimit.go             # 限速功能
│   └── auth.go                  # 认证管理
├── web/                         # Web 管理界面
│   └── web.go                   # Web 服务器
├── examples/                    # 示例代码
│   └── test_proxy.go            # SOCKS5 代理测试示例
├── docs/                        # 文档目录
└── test*.py                     # 各种测试脚本
```

## 🚀 快速开始

### 编译

```bash
# 禁用 CGO 编译
export CGO_ENABLED=0
go build -o smartproxy .

# 或使用 Makefile
make
```

### 运行

```bash
# 使用默认配置（端口从配置文件读取）
./smartproxy

# 使用自定义配置文件
./smartproxy --config conf/config.json
```

### 设置代理

在你的应用程序中设置代理为：
- **SOCKS5 代理**: 127.0.0.1:1080
- **DNS 服务器**: 127.0.0.1:1053
- **Web 管理**: http://127.0.0.1:8080

### 测试功能

```bash
# 测试 SOCKS5 代理功能
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# 测试 DNS 服务
nslookup google.com 127.0.0.1:1053

# 测试 HTTPS
curl --socks5 127.0.0.1:1080 https://httpbin.org/ip
```

## ⚙️ 配置文件

配置文件位于 `conf/config.json`，主要包含以下部分：

### 1. 监听器配置
```json
{
  "listener": {
    "socks5_port": 1080,    // SOCKS5 代理端口
    "web_port": 8080,        // Web 管理端口
    "dns_port": 1053,        // DNS 服务端口
    "ipv6_enabled": false,   // 是否启用 IPv6
    "ipv6_only": false       // 是否仅使用 IPv6
  }
}
```

### 2. 路由规则配置
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
        "patterns": ["*.adsystem.com", "ad.*"],
        "description": "屏蔽广告域名"
      }
    ]
  }
}
```

### 3. DNS 配置
```json
{
  "dns": {
    "enabled": true,
    "groups": {
      "cn": ["119.29.29.29:53", "223.5.5.5:53"],
      "foreign": ["8.8.8.8:53", "1.1.1.1:53"]
    },
    "hijack_rules": [
      {
        "pattern": "ad.google.com",
        "target": "0.0.0.0",
        "description": "屏蔽Google广告"
      },
      {
        "pattern": "pixiv.net",
        "target": "8.8.8.8",
        "description": "Pixiv使用Google DNS"
      }
    ]
  }
}
```

### 4. 用户认证和限速
```json
{
  "socks5": {
    "enable_auth": true,
    "auth_users": [
      {
        "username": "admin",
        "password": "admin123",
        "enabled": true,
        "user_groups": ["admin"],
        "rate_limit": {
          "upload_bps": 10485760,   // 10MB/s 上传限速
          "download_bps": 10485760  // 10MB/s 下载限速
        }
      }
    ]
  }
}
```

### 5. NAT 穿透配置
```json
{
  "nat_traversal": {
    "enabled": false,
    "mode": "auto",
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun1.l.google.com:19302"
    ],
    "upnp_enabled": false,
    "hole_punch_count": 3,
    "hole_punch_delay": 100
  }
}
```

## 📊 运行日志示例

启动时的日志输出：
```
=== SmartProxy运行日志 ===
Using SOCKS5 port from config: 1080
[SOCKS5] SOCKS5 server listening on IPv4 only
[SOCKS5] SmartProxy is enabled.
[SOCKS5] Blacklist manager initialized with 251 shards and 6h0m0s expiry duration.
[ProxyNodes] Loaded 3 proxy nodes
[SOCKS5] PasswordHasher initialized: pbkdf2-sha256, iterations=100000, salt_length=32
[SOCKS5] NAT穿透模式: auto
[SOCKS5] STUN服务器数量: 3
[SOCKS5] UPnP: 禁用
[SOCKS5] 检测NAT类型...
[Router DEBUG] China IP matched: 125.88.253.199 -> action=allow
[DNS] DNS Server configuration loaded successfully
Web server initialized successfully
Config file: conf/config.json
使用方法: 设置代理为 127.0.0.1:1080
DNS服务器: 127.0.0.1:1053

服务已启动:
  SOCKS5代理: 127.0.0.1:1080
  DNS服务: 127.0.0.1:1053
  Web管理: http://127.0.0.1:8080
```

## 📊 性能优化特性

### 基数树路由优化
- **高效查找**: O(32) 时间复杂度的 IPv4 网段匹配
- **IPv6 支持**: O(128) 时间复杂度的 IPv6 网段匹配
- **内存优化**: 共享前缀，减少内存占用
- **大规模支持**: 轻松处理 10,000+ 条 IP 网段规则

### 连接池优化
- **对象池**: 使用 sync.Pool 重用连接对象
- **减少 GC**: 降低垃圾回收压力
- **高并发**: 支持数千并发连接

### 智能 DNS 缓存
- **缓存大小**: 默认 2000 条记录
- **TTL 管理**: 自动过期清理
- **污染检测**: 智能 DNS 污染识别

## 🛠️ 开发和测试

### 编译要求
- Go 1.25+ (推荐)
- CGO_ENABLED=0 (编译时禁用 CGO)
- Linux/macOS/Windows
- 网络权限

### 测试脚本
项目提供了多个测试脚本：

```bash
# 基础测试
python test_simple.py

# IPv6 测试
python test_ipv6.py

# NAT 类型检测
python test_nat_types.py

# UDP Full Cone 测试
python test_udp_fullcone.py

# 信号处理测试
python test_signal_handling.py

# 无阻塞 I/O 测试
python test_splice.py
```

### 项目特点
- **零外部依赖**: 仅使用 Go 标准库
- **跨平台**: 支持 Linux、macOS、Windows、Android(Termux)
- **高性能**: 基数树 + 对象池优化
- **模块化**: 清晰的代码结构，易于扩展
- **安全性**: PBKDF2 密码哈希，支持多种认证方式

## 📋 系统要求

- **最低要求**: Go 1.21+
- **推荐版本**: Go 1.25+
- **平台**: Linux、macOS、Windows、Android(Termux)
- **权限**: 网络连接权限
- **内存**: 最小 64MB RAM

## 🔧 故障排除

### 常见问题

1. **端口被占用**
   ```
   解决方法：修改配置文件中的端口号
   ```

2. **无法访问某些网站**
   ```
   检查路由规则配置，确认代理节点是否正常
   ```

3. **DNS 解析失败**
   ```
   检查 DNS 服务器配置，确认网络连通性
   ```

4. **连接重置**
   ```
   日志会显示 "🚫 Added to blacklist"，表示自动切换到代理
   ```

### 调试模式

启用详细日志：
```json
{
  "logging": {
    "level": "debug",
    "enable_access_logs": true
  }
}
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献指南
1. Fork 本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [miekg/dns](https://github.com/miekg/dns) - DNS 库
- 中国 IP 段数据 contributors
- 所有贡献者和使用者