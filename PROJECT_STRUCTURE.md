# SmartProxy 项目结构

## 📁 核心代码文件

### 🐍 Python模块
- **`start_proxy.py`** - 主启动脚本
- **`socks5_server.py`** - 核心SOCKS5代理服务器实现（包含智能黑名单）
- **`sni_extractor.py`** - SNI/Host检测器
- **`udp_relay.py`** - UDP中继协议处理器

### ⚙️ 配置文件
- **`conf/config.json`** - 主配置文件
- **`conf/chnroutes.txt`** - 中国路由表

### 📚 文档
- **`README.md`** - 项目主文档
- **`README_SOCKS5.md`** - SOCKS5功能说明
- **`CLAUDE.md`** - AI编程助手使用指南

### 📦 依赖
- **`requirements.txt`** - Python依赖包列表

## 🚀 启动方式

```bash
# 启动代理服务器
python start_proxy.py

# 或后台运行
python start_proxy.py &
```

## 🔧 核心功能

### ✨ 智能黑名单机制
- **基于IP:端口**的精确黑名单
- **自动过期清理**（可配置时间）
- **SNI/Host信息收集**（HTTPS/HTTP）
- **立即回退到SOCKS5代理**，跳过直连检测

### 🎯 智能路由
- **直连检测**：仅对80/8080/443端口进行智能检测
- **自动回退**：直连失败立即使用SOCKS5代理
- **协议支持**：IPv4/IPv6双栈支持

### 📡 流量检测
- **SNI检测**：HTTPS流量SNI主机名提取
- **Host检测**：HTTP流量Host头识别
- **UDP支持**：完整的UDP ASSOCIATE支持

## 🏗️ 项目架构

```
smartproxy/
├── 🚀 start_proxy.py          # 启动脚本
├── 🔧 socks5_server.py        # 核心代理服务器
│   ├── 📋 BlacklistEntry      # 简化的黑名单条目
│   ├── 🧠 SmartBlacklist     # 黑名单管理器
│   ├── 🔍 EnhancedSOCKS5Handler # 增强的SOCKS5处理器
│   └── 🧭 SmartRouter        # 智能路由决策
├── 🕵️ sni_extractor.py        # SNI检测器
├── 📡 udp_relay.py            # UDP中继
├── 📁 conf/                   # 配置目录
│   ├── ⚙️ config.json        # 主配置
│   └── 🌐 chnroutes.txt      # 中国路由
├── 📚 README.md              # 项目文档
└── 📦 requirements.txt        # Python依赖
```

## ✨ 主要特性

1. **智能黑名单**：直连失败自动记录，下次连接立即回退
2. **端口精确控制**：基于IP:端口的精确黑名单机制
3. **协议智能检测**：自动识别IPv4/IPv6协议类型
4. **SNI/Host收集**：收集HTTPS/HTTP流量的主机名信息
5. **性能优化**：跳过已知的失败连接，节省时间
6. **自动清理**：定期清理过期的黑名单条目

## 🎯 使用场景

- **透明代理**：配合iptables实现透明代理
- **智能路由**：根据检测结果选择直连或代理
- **性能优化**：避免重复的连接尝试
- **网络诊断**：记录连接失败原因