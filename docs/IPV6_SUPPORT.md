# IPv6支持说明

## 概述

SmartProxy完全支持IPv6，包括TCP和UDP连接。本文档详细说明了IPv6的配置和使用方法。

## IPv6支持的功能

### 1. TCP连接
- ✅ IPv4/IPv6双栈监听
- ✅ 纯IPv6监听模式
- ✅ SOCKS5协议的IPv6地址类型支持

### 2. UDP转发
- ✅ Full Cone NAT支持IPv6
- ✅ UDP打洞支持IPv6
- ✅ SOCKS5 UDP ASSOCIATE支持IPv6

### 3. NAT穿透
- ✅ IPv6 STUN服务器支持
- ✅ IPv6 UPnP端口映射
- ✅ IPv6 TURN中继支持

## 配置IPv6

### 1. 监听器配置

在配置文件中设置IPv6选项：

```json
{
  "listener": {
    "socks5_port": 1080,
    "web_port": 8080,
    "dns_port": 1053,
    "ipv6_enabled": true,    // 启用IPv6支持
    "ipv6_only": false      // 是否仅监听IPv6
  }
}
```

#### 配置选项说明

- **ipv6_enabled**: 是否启用IPv6支持
  - `true`: 支持IPv6（默认）
  - `false`: 仅IPv4

- **ipv6_only**: 是否仅使用IPv6
  - `true`: 仅监听IPv6地址
  - `false`: IPv6优先，失败后回退IPv4（默认）

### 2. 监听模式

#### 模式1：双栈（IPv6 + IPv4）
```json
{
  "ipv6_enabled": true,
  "ipv6_only": false
}
```
监听 `[::]:1080`，同时接受IPv4和IPv6连接

#### 模式2：纯IPv6
```json
{
  "ipv6_enabled": true,
  "ipv6_only": true
}
```
仅监听IPv6地址 `[::]:1080`

#### 模式3：纯IPv4
```json
{
  "ipv6_enabled": false,
  "ipv6_only": false
}
```
仅监听IPv4地址 `0.0.0.0:1080`

### 3. NAT穿透配置

```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "auto",
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun ipv6.l.google.com:19302",
      "stun.ipv6.stunprotocol.org:3478",
      "[2001:4860:4860::8888]:3478",
      "[2607:f0d0:1002:51::4]:3478"
    ],
    "turn_server": "[2001:db8::1]:3478",
    "turn_username": "user",
    "turn_password": "pass",
    "upnp_enabled": true
  }
}
```

## 客户端配置

### 1. SOCKS5客户端设置

#### 使用IPv6地址
```
代理服务器: [::1]:1080          # 本地IPv6
代理服务器: [2001:db8::100]:1080 # 远程IPv6
```

#### 使用域名（自动解析IPv6）
```
代理服务器: proxy.example.com:1080
```

### 2. 测试IPv6连接

#### 测试脚本
```bash
# 测试IPv6连接
python3 test_ipv6.py ::1 1080

# 测试双栈连接
python3 test_nat_types.py ::1 1080
```

#### 使用curl测试
```bash
# 通过IPv6代理访问IPv6网站
curl --socks5 [::1]:1080 http://ipv6.google.com

# 通过IPv4代理访问IPv6网站
curl --socks5 127.0.0.1:1080 http://ipv6.google.com
```

## 网络环境配置

### 1. 系统级IPv6配置

#### Linux
```bash
# 启用IPv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6

# 检查IPv6地址
ip -6 addr show

# 测试IPv6连接
ping6 ipv6.google.com
```

#### Windows
```cmd
# 启用IPv6
netsh interface ipv6 install

# 查看IPv6地址
ipconfig /all

# 测试IPv6连接
ping -6 ipv6.google.com
```

### 2. 防火墙配置

#### iptables (IPv4)
```bash
# 允许SOCKS5端口
iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
iptables -A INPUT -p udp --dport 1080 -j ACCEPT
```

#### ip6tables (IPv6)
```bash
# 允许SOCKS5端口
ip6tables -A INPUT -p tcp --dport 1080 -j ACCEPT
ip6tables -A INPUT -p udp --dport 1080 -j ACCEPT
```

### 3. 路由器配置

确保路由器支持并启用了IPv6：
- 启用IPv6转发
- 配置IPv6防火墙规则
- 确保UPnP支持IPv6（如果需要）

## 常见问题

### 1. "IPv6 listen failed"错误

**原因**: 系统不支持IPv6或IPv6未启用

**解决方案**:
```bash
# Linux
sysctl -w net.ipv6.conf.all.disable_ipv6=0

# 检查系统支持
cat /proc/net/if_inet6
```

### 2. 客户端无法连接IPv6地址

**检查项目**:
- 客户端是否支持IPv6
- 网络路径是否支持IPv6
- 防火墙是否阻止IPv6

**测试**:
```bash
# 从客户端测试
nc -v6 [server_ipv6] 1080
telnet6 [server_ipv6] 1080
```

### 3. NAT穿透失败

**可能原因**:
- ISP不支持IPv6
- 路由器不支持IPv6 NAT穿透
- STUN服务器不可达

**解决方案**:
- 使用IPv4 STUN服务器
- 配置TURN服务器作为备选
- 检查网络IPv6支持

## 性能优化

### 1. 优先使用IPv6

在支持双栈的环境中，可以配置优先使用IPv6：

```json
{
  "nat_traversal": {
    "stun_servers": [
      "[2001:4860:4860::8888]:3478",
      "stun.l.google.com:19302"
    ]
  }
}
```

### 2. 并发测试

测试IPv4和IPv6的并发性能：

```bash
# 并发测试脚本
for i in {1..10}; do
    curl --socks5 [::1]:1080 http://ipv6.google.com &
    curl --socks5 127.0.0.1:1080 http://google.com &
done
wait
```

## 监控和日志

### 1. 日志级别

设置详细日志以观察IPv6连接：

```json
{
  "logging": {
    "level": "debug",
    "enable_access_logs": true
  }
}
```

### 2. 监控指标

- IPv6连接数
- IPv4连接数
- NAT穿透成功率
- 延迟对比

### 3. 日志示例

```
[SOCKS5] SOCKS5 server listening on IPv6 (dual-stack)
[NAT] IPv6 STUN server [2001:4860:4860::8888]:3478 success
[Connection] New IPv6 connection from [2001:db8::1]:54321
[UDP] Full Cone mapping created for IPv6 client
```

## 最佳实践

1. **默认启用IPv6**: 保持IPv6默认启用，以支持现代网络
2. **配置回退**: 总是配置IPv4作为备选方案
3. **测试覆盖**: 同时测试IPv4和IPv6功能
4. **文档更新**: 记录IPv6相关的特殊配置
5. **监控告警**: 监控IPv6连接的异常情况

## 相关文档

- [NAT穿透配置](NAT_TRAVERSAL_CONFIG.md)
- [测试工具说明](../test_ipv6.py)
- [IPv6基础知识](https://tools.ietf.org/html/rfc8200)