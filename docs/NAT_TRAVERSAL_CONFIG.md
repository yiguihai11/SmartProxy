# NAT穿透配置说明

## 概述

SmartProxy支持多种NAT穿透技术，可以在复杂的网络环境中实现UDP通信。本文档详细说明了NAT穿透功能的配置选项。

## 配置结构

在配置文件中，`nat_traversal`部分包含以下选项：

```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "auto",
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun1.l.google.com:19302",
      "stun2.l.google.com:19302"
    ],
    "turn_server": "",
    "turn_username": "",
    "turn_password": "",
    "upnp_enabled": true,
    "port_mapping_range": {
      "start": 20000,
      "end": 30000
    },
    "keepalive_interval": 30
  }
}
```

## 配置项说明

### enabled
- **类型**: boolean
- **默认值**: true
- **说明**: 是否启用NAT穿透功能。如果设置为false，所有NAT穿透相关功能都将被禁用。

### mode
- **类型**: string
- **可选值**: "auto", "direct", "fullcone", "holepunch", "turn"
- **默认值**: "auto"
- **说明**: NAT穿透模式选择：
  - `auto`: 自动选择最佳模式（推荐）
  - `direct`: 直接连接（适用于公网IP）
  - `fullcone`: Full Cone NAT模式（需要UPnP支持）
  - `holepunch`: UDP打洞模式
  - `turn`: TURN中继模式（最后备选）

### stun_servers
- **类型**: array of strings
- **默认值**: Google STUN服务器列表
- **说明**: STUN服务器列表，用于获取公网IP和端口。建议配置多个服务器以提高可靠性。

**常用公共STUN服务器**：
```json
"stun_servers": [
  "stun.l.google.com:19302",
  "stun1.l.google.com:19302",
  "stun2.l.google.com:19302",
  "stun.stunprotocol.org:3478",
  "stun.ekiga.net:3478",
  "stun.ideasip.com:3478",
  "stun.voiparound.com:3478",
  "stun.voxgratia.org:3478",
  "stun ipv6.l.google.com:19302",
  "stun.ipv6.stunprotocol.org:3478",
  "[2001:4860:4860::8888]:3478",
  "[2607:f0d0:1002:51::4]:3478"
]
```

### turn_server
- **类型**: string
- **默认值**: ""
- **说明**: TURN服务器地址（格式：host:port）。TURN用于在其他NAT穿透方法失败时提供中继服务。

### turn_username / turn_password
- **类型**: string
- **默认值**: ""
- **说明**: TURN服务器的认证凭据。

### upnp_enabled
- **类型**: boolean
- **默认值**: true
- **说明**: 是否启用UPnP端口映射。启用后，程序会尝试通过UPnP在路由器上创建端口映射。

### port_mapping_range
- **类型**: object
- **默认值**: { "start": 20000, "end": 30000 }
- **说明**: UPnP端口映射的端口范围。

### keepalive_interval
- **类型**: integer
- **默认值**: 30
- **说明**: NAT映射的保活间隔（秒）。定期发送保活包以维持NAT映射不超时。

## 自建STUN/TURN服务器

### 自建coturn服务器

coturn是一个开源的STUN/TURN服务器实现。以下是快速部署指南：

1. **安装coturn**：
   ```bash
   # Ubuntu/Debian
   sudo apt-get install coturn

   # CentOS/RHEL
   sudo yum install coturn
   ```

2. **配置coturn**：
   编辑 `/etc/turnserver.conf`：
   ```ini
   # 监听端口
   listening-port=3478
   tls-listening-port=5349

   # 认证
   use-auth-secret
   static-auth-secret=your-secret-key

   # 域
   realm=yourdomain.com

   # 允许的IP范围
   total-quota=100
   user-quota=12
   max-bps=64000

   # 日志
   log-file=/var/log/turnserver.log
   verbose
   ```

3. **启动服务**：
   ```bash
   sudo systemctl start coturn
   sudo systemctl enable coturn
   ```

4. **在SmartProxy中配置**：
   ```json
   {
     "nat_traversal": {
       "stun_servers": ["your-server.com:3478"],
       "turn_server": "your-server.com:3478",
       "turn_username": "turnuser",
       "turn_password": "turnpass"
     }
   }
   ```

### 使用Docker部署coturn

```yaml
# docker-compose.yml
version: '3'
services:
  coturn:
    image: coturn/coturn:latest
    ports:
      - "3478:3478/udp"
      - "3478:3478/tcp"
      - "5349:5349/udp"
      - "5349:5349/tcp"
    command: >
      -n
      --listening-port=3478
      --tls-listening-port=5349
      --use-auth-secret
      --static-auth-secret=your-secret-key
      --realm=turn.example.com
      --total-quota=100
      --user-quota=12
      --max-bps=64000
    volumes:
      - ./turnserver.conf:/etc/coturn/turnserver.conf
    restart: unless-stopped
```

## 网络环境建议

### 1. 公网IP环境
```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "direct"
  }
}
```

### 2. 路由器支持UPnP
```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "fullcone",
    "upnp_enabled": true
  }
}
```

### 3. 普通NAT环境
```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "holepunch",
    "stun_servers": [
      "stun.l.google.com:19302",
      "stun.stunprotocol.org:3478"
    ]
  }
}
```

### 4. 对称NAT或严格防火墙
```json
{
  "nat_traversal": {
    "enabled": true,
    "mode": "turn",
    "turn_server": "turn.example.com:3478",
    "turn_username": "username",
    "turn_password": "password"
  }
}
```

## 故障排除

### 1. STUN服务器不可达
- 检查防火墙是否阻止UDP 3478端口
- 尝试使用不同的STUN服务器
- 确认网络可以访问外网

### 2. UPnP映射失败
- 确认路由器启用了UPnP功能
- 检查设备是否在同一网段
- 尝试手动在路由器上设置端口转发

### 3. UDP打洞失败
- 可能是对称NAT环境
- 尝试使用TURN中继
- 增加打洞尝试次数

### 4. TURN连接失败
- 验证TURN服务器地址和端口
- 检查用户名密码是否正确
- 确认TURN服务器正在运行

## 安全注意事项

1. **TURN服务器安全**：
   - 使用强密码
   - 启用TLS加密
   - 限制访问IP

2. **UPnP安全**：
   - 仅在可信网络环境中启用
   - 定期检查端口映射
   - 使用最小端口范围

3. **日志监控**：
   - 监控异常的NAT穿透请求
   - 定期检查连接日志
   - 设置合理的速率限制