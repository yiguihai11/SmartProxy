# Go SOCKS5 代理服务器架构设计

## 📋 从 Python 版本移植的核心功能

基于对 Python 源码的深入分析，需要移植以下核心功能：

### 🎯 1. 完整的 SOCKS5 协议支持 (socks5_protocol.py → socks5/)
- ✅ IPv4/IPv6 双栈支持
- ✅ TCP/UDP/BIND 命令支持
- ✅ 用户认证系统 (用户名/密码)
- ✅ 限速和流量控制
- ✅ 连接超时管理
- ✅ 并发连接限制
- ✅ UDP 碎片化支持

### 🎯 2. 智能检测和路由 (start_proxy.py + 提取器)
- ✅ TLS SNI 提取 (sni_extractor.py)
- ✅ HTTP Host 提取 (http_host_extractor.py)
- ✅ 智能路由决策引擎
- ✅ 流量分析和统计
- ✅ 实时连接监控

### 🎯 3. 高级网络服务
- ✅ 智能 DNS 服务器 (dns_module.py)
- ✅ DNS 缓存和劫持
- ✅ 上游代理选择器 (proxy_selector.py)
- ✅ 连接池管理
- ✅ 健康检查

### 🎯 4. 安全和管理系统
- ✅ 安全认证系统 (secure_auth.py)
- ✅ 用户权限管理
- ✅ Web 管理界面 (web_server.py)
- ✅ 实时监控 API
- ✅ 配置热重载

### 🎯 5. 数据管理
- ✅ 中国路由基数树 (route_trie.py)
- ✅ 黑名单管理 (blacklist.py)
- ✅ 流量统计和日志
- ✅ 性能监控

## 🏗️ Go 版本模块架构

```
go/
├── cmd/                           # 命令行工具
│   └── server/                    # 服务器启动入口
│       └── main.go               # 主程序
├── internal/                      # 内部包
│   ├── socks5/                   # SOCKS5 协议实现
│   │   ├── protocol.go           # 协议核心
│   │   ├── auth.go               # 认证系统
│   │   ├── connection.go         # 连接管理
│   │   ├── udp.go                # UDP 支持
│   │   └── bind.go               # BIND 支持
│   ├── router/                   # 路由引擎
│   │   ├── router.go             # 路由器 (已存在)
│   │   ├── trie.go               # 基数树 (已存在)
│   │   ├── detector.go           # 流量检测器
│   │   └── decision.go           # 路由决策
│   ├── detection/                # 流量检测
│   │   ├── sni.go                # SNI 提取
│   │   ├── http.go               # HTTP Host 提取
│   │   └── analyzer.go           # 流量分析器
│   ├── dns/                      # DNS 服务
│   │   ├── server.go             # DNS 服务器
│   │   ├── cache.go              # DNS 缓存
│   │   ├── hijack.go             # DNS 劫持
│   │   └── resolver.go           # DNS 解析器
│   ├── proxy/                    # 代理管理
│   │   ├── selector.go           # 代理选择器
│   │   ├── node.go               # 代理节点
│   │   ├── pool.go               # 连接池
│   │   └── health.go             # 健康检查
│   ├── auth/                     # 认证系统
│   │   ├── manager.go            # 认证管理器
│   │   ├── hash.go               # 密码哈希
│   │   ├── user.go               # 用户管理
│   │   └── acl.go                # 访问控制
│   ├── config/                   # 配置管理
│   │   ├── manager.go            # 配置管理器
│   │   ├── loader.go             # 配置加载器
│   │   └── watcher.go            # 配置监控
│   ├── stats/                    # 统计监控
│   │   ├── collector.go          # 数据收集器
│   │   ├── metrics.go            # 性能指标
│   │   └── reporter.go           # 报告生成器
│   └── web/                      # Web 界面
│       ├── server.go             # Web 服务器
│       ├── handlers.go           # HTTP 处理器
│       ├── api.go                # API 接口
│       └── websocket.go          # WebSocket 支持
├── pkg/                          # 公共包
│   ├── netutil/                  # 网络工具
│   │   ├── ip.go                 # IP 工具
│   │   ├── port.go               # 端口工具
│   │   └── protocol.go           # 协议工具
│   ├── crypto/                   # 加密工具
│   │   ├── hash.go               # 哈希工具
│   │   └── random.go             # 随机数工具
│   └── logger/                   # 日志工具
│       ├── logger.go             # 日志器
│       └── formater.go           # 格式化器
├── api/                          # API 定义
│   ├── v1/                       # API v1
│   │   ├── handler.go            # 处理器接口
│   │   ├── middleware.go         # 中间件
│   │   └── routes.go             # 路由定义
│   └── openapi/                  # OpenAPI 规范
├── web/                          # Web 资源
│   ├── static/                   # 静态文件
│   │   ├── css/                  # 样式文件
│   │   ├── js/                   # 脚本文件
│   │   └── img/                  # 图片文件
│   └── templates/                # 模板文件
│       ├── index.html            # 主页面
│       ├── config.html           # 配置页面
│       └── monitor.html          # 监控页面
├── configs/                      # 配置文件
│   ├── default.json              # 默认配置
│   ├── development.json          # 开发配置
│   └── production.json           # 生产配置
├── scripts/                      # 脚本文件
│   ├── build.sh                  # 构建脚本
│   ├── deploy.sh                 # 部署脚本
│   └── migrate.sh                # 数据迁移脚本
├── docs/                         # 文档
│   ├── api.md                    # API 文档
│   ├── deployment.md             # 部署文档
│   └── development.md            # 开发文档
├── go.mod                        # Go 模块
├── go.sum                        # 依赖锁定
├── Makefile                      # 构建脚本
├── Dockerfile                    # Docker 配置
├── docker-compose.yml           # Docker Compose
└── README.md                     # 项目说明
```

## 🔄 数据流架构

```
客户端请求 → SOCKS5协议解析 → 流量检测 → 路由决策 → 网络连接 → 数据转发
                                    ↓
                            ┌─────────────────┐
                            │   SNI/HTTP检测    │
                            │  智能域名识别     │
                            └─────────────────┘
                                    ↓
                            ┌─────────────────┐
                            │   路由决策引擎     │
                            │ 基数树快速匹配    │
                            │ 规则引擎决策     │
                            └─────────────────┘
                                    ↓
                            ┌─────────────────┐
                            │   执行引擎        │
                            │ 直接连接/代理    │
                            │ DNS解析/劫持     │
                            └─────────────────┘
```

## 🎯 实现优先级

### Phase 1: 基础功能 (当前已有基础上扩展)
1. ✅ SOCKS5 协议完整实现
2. ✅ 基数树路由引擎
3. 🔄 SNI/HTTP 检测器
4. 🔄 用户认证系统

### Phase 2: 高级功能
5. 🔄 智能 DNS 服务器
6. 🔄 代理选择器
7. 🔄 流量统计和监控
8. 🔄 Web 管理界面

### Phase 3: 企业功能
9. 🔄 连接池管理
10. 🔄 健康检查系统
11. 🔄 配置热重载
12. 🔄 集群部署支持

## 🚀 技术选型

- **Web 框架**: Gin (轻量高性能)
- **WebSocket**: Gorilla WebSocket
- **配置管理**: Viper
- **日志**: Logrus/Zap
- **数据库**: SQLite/Badger (嵌入式)
- **缓存**: Go-Cache
- **指标**: Prometheus
- **容器化**: Docker

## 📈 性能目标

- **并发连接**: 10,000+
- **吞吐量**: 1Gbps+
- **内存使用**: < 100MB (1万连接)
- **CPU 使用**: < 50% (4核)
- **延迟**: < 1ms (路由决策)
- **可用性**: 99.9%

现在开始实现这些功能！