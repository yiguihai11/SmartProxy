# Go SOCKS5 智能代理服务器

一个基于 Go 语言实现的高性能 SOCKS5 代理服务器，支持智能路由、访问控制和基数树优化的 IPv4/IPv6 双栈支持。

## 🎯 核心特性

- ✅ **完整的 SOCKS5 协议支持** - 标准 RFC 1928 实现
- ✅ **基数树路由引擎** - 高效的 IP 网段匹配，支持大规模规则集
- ✅ **双栈 IP 支持** - 完整的 IPv4 和 IPv6 支持
- ✅ **智能路由系统** - 国内直连、国外代理、自定义屏蔽
- ✅ **访问控制列表 (ACL)** - 支持域名、IP、端口、CIDR 网段
- ✅ **中国 IP 段识别** - 自动识别中国大陆 IP 并直连（10,000+ 网段）
- ✅ **多配置文件支持** - 灵活的配置文件管理
- ✅ **并发连接处理** - 高性能 goroutine 处理
- ✅ **详细日志记录** - 连接状态和路由决策日志
- ✅ **零外部依赖** - 仅使用 Go 标准库

## 📁 项目结构

```
go/
├── main.go                    # 程序入口点
├── go.mod                     # Go 模块配置
├── socks5proxy               # 编译生成的可执行文件
├── README.md                 # 本文件
├── enhanced-config.json      # 增强配置文件示例
├── socks5-config.json        # 基础配置文件示例
├── socks5/                   # SOCKS5 核心库
│   ├── socks5.go            # SOCKS5 协议实现
│   ├── router.go            # 基数树路由器
│   └── trie.go              # 基数树数据结构
├── examples/                # 示例代码
│   └── test_proxy.go        # SOCKS5 代理测试示例
└── conf/                    # 配置文件
    ├── config.json          # 默认配置文件
    ├── chnroutes.txt        # 中国大陆 IP 段数据
    └── config-documentation.md
```

## 🚀 快速开始

### 编译

```bash
cd go/
go build -o socks5proxy .
```

### 运行

```bash
# 使用默认配置和端口 1080
./socks5proxy

# 指定端口
./socks5proxy 8080

# 使用自定义配置文件
./socks5proxy --config enhanced-config.json 1080
```

### 设置代理

在你的应用程序中设置代理为：
- 地址：127.0.0.1
- 端口：1080（或你指定的端口）
- 类型：SOCKS5

### 测试功能

```bash
# 测试 SOCKS5 代理功能
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# 测试 HTTPS
curl --socks5 127.0.0.1:1080 https://httpbin.org/ip
```

## ⚙️ 配置文件

### ACL 规则配置（支持 IPv4/IPv6）

```json
{
  "acl_rules": [
    {
      "action": "block",
      "pattern": "*.facebook.com",
      "description": "屏蔽Facebook域名"
    },
    {
      "action": "allow",
      "pattern": "*.cn",
      "description": "中国域名直连"
    },
    {
      "action": "allow",
      "pattern": "192.168.0.0/16",
      "description": "内网IPv4网段直连"
    },
    {
      "action": "allow",
      "pattern": "2001:db8::/32",
      "description": "测试IPv6网段直连"
    },
    {
      "action": "allow",
      "pattern": "fe80::/10",
      "description": "链路本地IPv6直连"
    }
  ],
  "china_routes_enable": true,
  "china_routes_path": "conf/chnroutes.txt"
}
```

#### 动作类型说明
- **allow**: 直连（不经过代理）
- **deny**: 走代理（转发到上游代理）
- **block**: 屏蔽（拒绝连接）

#### 模式匹配支持（基数树优化）
- **域名**: `*.example.com` 或 `example.com`
- **IPv4地址**: `192.168.1.1` → 自动转换为 `192.168.1.1/32`
- **IPv6地址**: `2001:db8::1` → 自动转换为 `2001:db8::1/128`
- **CIDR网段**: `192.168.0.0/16`, `2001:db8::/32`
- **端口**: `80`, `443`
- **通配符**: `*.google.com`

#### 基数树性能特点
- **高效查找**: O(32) 时间复杂度的 IPv4 网段匹配
- **高效查找**: O(128) 时间复杂度的 IPv6 网段匹配
- **内存优化**: 共享前缀，减少内存占用
- **大规模支持**: 轻松处理 10,000+ 条 IP 网段规则

## 📊 性能统计

### 基数树版本输出示例

```
2025/11/25 01:59:32 Router loaded: 11 rules, 7 IP rules, 10744 China rules (IPv4: 78 nodes, IPv6: 292 nodes)
2025/11/25 01:59:32 IPv4/IPv6 support: ✓, Actions - Direct: 9, Proxy: 0, Block: 2
2025/11/25 01:59:32 SOCKS5 server started on [::]:1086
```

**性能指标:**
- **总规则数**: 11 条 ACL 规则
- **IP规则数**: 7 条 CIDR 网段规则
- **中国IP规则**: 10,744 条网段（自动加载）
- **IPv4节点**: 78 个基数树节点
- **IPv6节点**: 292 个基数树节点
- **编译后大小**: ~4.3MB
- **内存占用**: 极低（基数树优化）
- **查找性能**: O(32) IPv4, O(128) IPv6

## 🛠️ 开发和测试

### 编译要求
- Go 1.21 或更高版本
- Termux/Linux 环境
- 网络权限

### 运行测试
```bash
# 在 go 目录下运行
cd examples/
go run test_proxy.go 127.0.0.1:1080 http://httpbin.org/ip
```

### 项目特点
- **零依赖**: 仅使用 Go 标准库
- **跨平台**: 支持 Linux、macOS、Windows
- **高性能**: 基数树优化的路由查找
- **模块化**: 清晰的代码结构，易于扩展

## 📋 系统要求

- Go 1.21+
- Linux/macOS/Windows
- 网络连接权限

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 📄 许可证

MIT License