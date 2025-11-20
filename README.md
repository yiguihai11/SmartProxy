# 智能SOCKS5代理服务器

一个专为redsocks透明代理设计的SOCKS5服务器，支持精确的SNI/Host检测和智能路由。

## 🎯 核心特性

- ✅ **完整的SOCKS5协议支持** - 支持CONNECT和UDP ASSOCIATE命令
- ✅ **SNI/Host检测** - 自动识别HTTPS SNI和HTTP Host头
- ✅ **端口智能过滤** - 只检测80/8080/443端口的流量
- ✅ **上游代理转发** - 支持多级代理链
- ✅ **智能路由决策** - 基于域名的策略路由
- ✅ **UDP协议支持** - 支持DNS、NTP、DHCP等UDP协议
- ✅ **高性能异步架构** - 基于asyncio

## 📁 项目结构

```
smartproxy/
├── README.md                   # 本文件
├── socks5_server.py           # 主服务文件 (增强版)
├── fake_handshake_detector.py # SNI检测器 (假握手方式)
├── traffic_interceptor.py     # 流量拦截器 (HTTP Host检测)
├── udp_relay.py              # UDP中继协议处理器
├── start_proxy.py            # 服务启动脚本
├── test_socks5.py            # SOCKS5功能测试脚本
├── test_fake_handshake.py    # SNI检测测试脚本
├── test_udp.py               # UDP功能测试脚本
├── test.py                   # 原始测试工具
├── requirements.txt          # Python依赖
├── CLAUDE.md                 # AI编程指南
└── conf/
    └── config.json           # 主配置文件
```

## 🚀 快速开始

### 1. 安装依赖
```bash
pip install -r requirements.txt
```

### 2. 配置代理
编辑 `conf/config.json`，配置上游SOCKS5代理：
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
python3 start_proxy.py
```

### 4. 测试功能
```bash
python3 test_socks5.py
```

## 🔧 Redsocks配置

在redsocks配置中指向本服务：

```ini
redsocks {
    local_ip = 127.0.0.1;
    local_port = 1080;      # 本服务监听端口
    ip = 127.0.0.1;
    port = 1081;            # 上游SOCKS5端口
    type = socks5;
}
```

## 🎨 智能检测功能

### 检测范围
- **端口**: 80, 8080 (HTTP) | 443 (HTTPS)
- **协议**: HTTP/HTTPS
- **内容**: Host头、SNI扩展、绝对URL

### 检测方式

#### HTTP流量 (端口80/8080)
- ✅ **Host头**: `Host: example.com`
- ✅ **绝对URL**: `GET http://example.com/path HTTP/1.1`

#### HTTPS流量 (端口443)
- ✅ **TLS SNI**: 从ClientHello扩展中提取服务器名称
- ✅ **证书信息**: 从服务器响应中提取CN/SAN

### 智能路由规则

配置文件支持多种路由规则：

```json
{
  "proxy_bind_rules": [
    {
      "pattern": "*.google.com",
      "target": "us_proxy",
      "description": "谷歌服务走美国代理"
    },
    {
      "pattern": "443",
      "target": "https_proxy",
      "description": "HTTPS流量走专用代理"
    },
    {
      "pattern": "[8080,8443]",
      "target": "dev_proxy",
      "description": "开发端口走开发代理"
    }
  ]
}
```

## 📊 日志输出

服务运行时会输出详细日志：

```
2024-01-01 12:00:00 - enhanced_socks5_server - INFO - Enhanced SOCKS5 server started
2024-01-01 12:00:01 - enhanced_socks5_server.EnhancedSOCKS5Handler - INFO - New SOCKS5 connection
2024-01-01 12:00:02 - enhanced_socks5_server.EnhancedSOCKS5Handler - INFO - Detected HTTP Host: httpbin.org
2024-01-01 12:00:03 - enhanced_socks5_server.EnhancedSOCKS5Handler - INFO - Detected SNI: google.com
2024-01-01 12:00:04 - enhanced_socks5_server.EnhancedSOCKS5Handler - INFO - Connected to upstream proxy
```

## 🛠️ 开发和测试

### 功能测试
```bash
# 测试SOCKS5代理功能
python3 test_socks5.py

# 测试原始连接工具
python3 test.py
```

### 开发模式
启动时设置调试级别：
```python
import logging
logging.getLogger('socks5_server').setLevel(logging.DEBUG)
logging.getLogger('traffic_interceptor').setLevel(logging.DEBUG)
```

## ⚡ 性能特性

- **异步I/O**: 支持高并发连接
- **内存优化**: 高效的缓冲区管理
- **连接复用**: 智能连接池管理
- **零拷贝**: 最小化数据复制开销

## 🔒 安全特性

- **访问控制**: 支持IP/域名ACL规则
- **日志审计**: 完整的访问日志记录
- **连接验证**: SOCKS5协议完整性检查

## 📋 系统要求

- Python 3.8+
- Termux/ Linux环境
- 网络权限

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 📄 许可证

MIT License