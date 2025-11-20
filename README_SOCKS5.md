# 智能SOCKS5代理服务

这是一个功能完整的SOCKS5代理服务器，专门为redsocks转发设计，支持SNI/Host解析和智能路由。

## 功能特点

### 核心功能
- ✅ **完整的SOCKS5协议支持** - 支持CONNECT命令
- ✅ **上游代理转发** - 将流量转发到上游SOCKS5服务器
- ✅ **SNI/Host解析** - 自动检测TLS SNI和HTTP Host头
- ✅ **智能路由** - 基于域名和IP的ACL规则
- ✅ **高性能异步架构** - 基于asyncio的异步处理

### 高级特性
- 🔍 **SNI检测** - 从TLS握手包中提取服务器名称
- 🌐 **HTTP Host检测** - 从HTTP请求中提取Host头
- 📋 **ACL规则** - 支持allow/deny/block规则
- 🚀 **零拷贝优化** - 高效的数据转发
- 📊 **详细日志** - 完整的连接和错误日志
- 🔧 **灵活配置** - JSON格式配置文件

## 安装和使用

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 配置代理
编辑 `conf/config.json` 文件，确保上游代理配置正确：

```json
{
  "listener": {
    "socks5_port": 1080,
    "dns_port": 1053,
    "ipv6_enabled": false
  },
  "proxy_nodes": [
    {
      "identifier": "default",
      "protocol": "socks5",
      "ip": "127.0.0.1",
      "port": 1081
    }
  ]
}
```

### 3. 启动服务
```bash
python start_proxy.py
```

服务启动后会显示：
```
正在加载配置...
正在启动SOCKS5代理服务器...
SOCKS5代理服务启动成功!
监听端口: 1080
上游代理: 127.0.0.1:1081
日志文件: smartproxy.log

按 Ctrl+C 停止服务
```

### 4. 测试服务
```bash
python test_socks5.py
```

## Redsocks配置

在redsocks配置中添加以下配置：

```ini
redsocks {
    local_ip = 127.0.0.1;
    local_port = 1080;
    ip = 127.0.0.1;
    port = 1081;
    type = socks5;
}
```

## 配置说明

### 基本配置
- `socks5_port`: 本地SOCKS5服务监听端口
- `proxy_nodes`: 上游代理服务器配置
- `ipv6_enabled`: 是否启用IPv6支持

### ACL规则
```json
"acl_rules": [
  {
    "action": "allow",
    "pattern": "*.cn",
    "description": "中国域名直连"
  },
  {
    "action": "deny",
    "pattern": "25",
    "description": "SMTP端口拒绝"
  }
]
```

### 动作类型
- `allow`: 允许直连
- `deny`: 拒绝连接
- `block`: 屏蔽访问

### 模式匹配
- `*.example.com`: 域名匹配
- `192.168.1.0/24`: IP网段匹配
- `80`: 端口匹配

## SNI/Host检测

### TLS SNI检测
自动从TLS ClientHello消息中提取SNI信息，用于识别目标网站。

### HTTP Host检测
自动从HTTP请求头中提取Host字段，支持HTTP/1.1和HTTP/1.0。

### 应用场景
- 智能路由决策
- 域名统计分析
- 安全策略执行

## 日志格式

日志文件 `smartproxy.log` 包含以下信息：

```
2024-01-01 12:00:00,000 - socks5_server - INFO - New SOCKS5 connection from ('127.0.0.1', 54321)
2024-01-01 12:00:00,100 - socks5_server.SNIResolver - INFO - Extracted SNI: www.google.com
2024-01-01 12:00:00,200 - socks5_server - INFO - Connected to upstream proxy 127.0.0.1:1081
```

## 性能优化

### 内存管理
- 使用连接池减少连接开销
- 异步I/O提高并发性能
- 内存缓冲区优化数据传输

### 网络优化
- TCP_NODELAY减少延迟
- SO_REUSEADDR快速重连
- 优化的数据转发算法

## 故障排除

### 常见问题

1. **连接被拒绝**
   - 检查上游代理是否运行
   - 确认端口配置正确

2. **SNI检测失败**
   - 确保客户端发送TLS握手
   - 检查网络中间件是否修改TLS包

3. **性能问题**
   - 检查系统资源使用
   - 优化ACL规则复杂度

### 调试模式
启动时添加详细日志：

```python
import logging
logging.getLogger('socks5_server').setLevel(logging.DEBUG)
```

## 安全注意事项

1. **访问控制** - 配置适当的ACL规则
2. **日志保护** - 定期清理日志文件
3. **网络安全** - 在可信环境中使用

## 技术架构

```
客户端 → redsocks → 本地SOCKS5代理 → 上游SOCKS5代理 → 目标服务器
```

### 数据流
1. redsocks将TCP流量转发到本地SOCKS5代理
2. 本地代理进行SNI/Host检测
3. 根据配置决定直连或转发到上游代理
4. 建立端到端数据通道

## 开发和扩展

### 添加新功能
1. 修改 `Config` 类添加配置项
2. 在 `SNIResolver` 中添加检测逻辑
3. 更新 `SOCKS5Handler` 处理流程

### 性能监控
可以添加统计信息收集：
- 连接数统计
- 流量统计
- 错误率统计

## 许可证

本项目采用MIT许可证，详见LICENSE文件。