# 智能代理配置文件说明

## 概述

本配置文件为智能代理系统提供完整的配置选项，支持多种代理协议、智能路由、用户认证、限速控制等高级功能。

## 配置文件结构

### 基础服务配置

#### listener - 监听器配置
```json
{
  "listener": {
    "socks5_port": 1080,        // SOCKS5代理端口
    "dns_port": 1053,           // 智能DNS服务端口
    "ipv6_enabled": false       // 是否启用IPv6支持
  }
}
```

#### connection_settings - 连接设置
```json
{
  "connection_settings": {
    "tcp_timeout_seconds": 60,    // TCP连接超时时间(秒)
    "udp_timeout_seconds": 300    // UDP会话超时时间(秒)
  }
}
```

### SOCKS5代理配置

#### socks5 - SOCKS5服务配置
```json
{
  "socks5": {
    "enable_auth": true,                    // 是否启用用户认证
    "max_connections": 1000,                // 最大连接数
    "cleanup_interval": 300,                // NAT清理间隔(秒)
    "auth_users": [                         // 认证用户列表
      {
        "username": "admin",                // 用户名
        "enabled": true,                    // 是否启用
        "password": "password123",          // 明文密码(可选)
        "password_hash": "hash_value",      // 密码哈希(推荐)
        "acls": {                           // 用户ACL规则
          "rate_limit_down_kbps": 0,        // 下载限速(Kbps, 0为无限制)
          "rate_limit_up_kbps": 0,          // 上传限速(Kbps, 0为无限制)
          "max_connections": 100,           // 最大连接数
          "allow_proxy_forward": true,      // 是否允许代理转发
          "time_rules": []                  // 时间规则(如"09:00-18:00")
        }
      }
    ]
  }
}
```

### Web管理界面

#### web_interface - Web管理配置
```json
{
  "web_interface": {
    "enabled": true,          // 是否启用Web管理界面
    "port": 8080             // Web界面端口
  }
}
```

### 智能路由配置

#### chnroutes - 中国路由规则
```json
{
  "chnroutes": {
    "enable": true,                         // 是否启用中国路由
    "path": "conf/chnroutes.txt"           // 路由规则文件路径
  }
}
```

#### smart_proxy - 智能代理
```json
{
  "smart_proxy": {
    "enable": true,                        // 是否启用智能代理
    "timeout_ms": 3000,                    // 连接超时(毫秒)
    "blacklist_expiry_minutes": 360        // 黑名单过期时间(分钟)
  }
}
```

### DNS服务配置

#### dns - DNS服务配置
```json
{
  "dns": {
    "groups": {                            // DNS服务器组
      "cn": [                              // 国内DNS服务器
        "223.5.5.5:53",
        "119.29.29.29:53"
      ],
      "foreign": [                         // 国外DNS服务器
        "8.8.8.8:53",
        "1.1.1.1:53"
      ]
    },
    "cache": {                             // DNS缓存配置
      "max_size": 2000,                    // 最大缓存条目
      "default_ttl": 300,                  // 默认TTL(秒)
      "cleanup_interval": 60               // 清理间隔(秒)
    },
    "hijack_rules": [                      // DNS劫持规则
      {
        "pattern": "api.dev.local",        // 匹配模式
        "target": "127.0.0.1",            // 目标IP
        "description": "本地API服务"        // 描述
      }
    ]
  }
}
```

#### dns_advanced - 高级DNS配置
```json
{
  "dns_advanced": {
    "enable_ecs": true,                    // 启用EDNS客户端子网
    "enable_dnssec": false,                // 启用DNSSEC验证
    "max_concurrent_queries": 1000,        // 最大并发查询数
    "response_cache_size": 10000,          // 响应缓存大小
    "enable_negative_caching": true,       // 启用否定缓存
    "negative_ttl": 60                     // 否定缓存TTL
  }
}
```

### 性能优化配置

#### memory_pool - 内存池配置
```json
{
  "memory_pool": {
    "size_mb": 16,                         // 内存池大小(MB)
    "block_sizes": [                       // 块大小列表
      "4096",
      "16384",
      "65536",
      "262144"
    ],
    "auto_adjust": true                    // 自动调整内存池
  }
}
```

#### zero_copy - 零拷贝配置
```json
{
  "zero_copy": {
    "enabled": true,                       // 是否启用零拷贝
    "buffer_size": 65536                  // 缓冲区大小
  }
}
```

#### connection_pool - 连接池配置
```json
{
  "connection_pool": {
    "enabled": true,                       // 是否启用连接池
    "max_per_host": 50,                    // 每主机最大连接数
    "max_idle": 300,                       // 最大空闲时间(秒)
    "max_age": 3600                       // 连接最大存活时间(秒)
  }
}
```

#### performance - 性能配置
```json
{
  "performance": {
    "buffer_size": 65536,                  // 缓冲区大小
    "worker_threads": 4,                   // 工作线程数
    "accept_queue_size": 100,              // 接受队列大小
    "max_packet_size": 65507,              // 最大数据包大小
    "epoll_timeout_ms": 1000              // epoll超时时间
  }
}
```

### 负载均衡与健康检查

#### node_health_check - 节点健康检查
```json
{
  "node_health_check": {
    "interval_seconds": 600                // 健康检查间隔(秒)
  }
}
```

#### load_balancing - 负载均衡配置
```json
{
  "load_balancing": {
    "algorithm": "weighted_round_robin",   // 负载均衡算法
    "health_check_enabled": true,          // 启用健康检查
    "health_check_interval": 30,           // 健康检查间隔(秒)
    "health_check_timeout": 5,             // 健康检查超时(秒)
    "failover_threshold": 3,               // 故障转移阈值
    "recovery_check_interval": 60          // 恢复检查间隔(秒)
  }
}
```

### 代理节点配置

#### proxy_nodes - 代理节点列表
```json
{
  "proxy_nodes": [
    {
      "identifier": "local_socks5",        // 节点唯一标识
      "protocol": "socks5",               // 代理协议(socks5/http/shadowsocks/vmess/trojan)
      "ip": "127.0.0.1",                 // 代理服务器IP
      "port": 1081,                      // 代理服务器端口
      "weight": 5,                        // 节点权重
      "enabled": true,                    // 是否启用
      "auth_method": "none",              // 认证方法(none/userpass)
      "username": "user",                 // 认证用户名(可选)
      "password": "password"              // 认证密码(可选)
    }
  ]
}
```

### 访问控制规则

#### acl_rules - ACL规则
```json
{
  "acl_rules": [
    {
      "action": "allow|deny|block",       // 动作类型
      "pattern": "*.cn",                  // 匹配模式(域名/IP/CIDR)
      "description": "中国域名直连"        // 规则描述
    }
  ]
}
```

#### proxy_bind_rules - 代理绑定规则
```json
{
  "proxy_bind_rules": [
    {
      "pattern": "*.google.com",          // 匹配模式
      "target": "us_proxy",               // 目标代理节点
      "description": "谷歌服务强制走美国代理" // 规则描述
    }
  ]
}
```

### 流量控制与QoS

#### traffic_control - 流量控制配置
```json
{
  "traffic_control": {
    "enable_qos": false,                   // 是否启用QoS
    "default_priority": 0,                 // 默认优先级
    "high_priority_patterns": [            // 高优先级模式
      "*.google.com",
      "*.github.com"
    ],
    "low_priority_patterns": [             // 低优先级模式
      "*.torrent.com",
      "*.download.com"
    ],
    "max_global_bandwidth_kbps": 0,        // 全局最大带宽(Kbps)
    "per_user_bandwidth_enforcement": true  // 是否强制执行用户带宽限制
  }
}
```

### 安全配置

#### security - 安全配置
```json
{
  "security": {
    "allowed_ips": [                       // 允许的IP范围
      "127.0.0.1",
      "192.168.0.0/16",
      "10.0.0.0/8"
    ],
    "max_auth_attempts": 3,                // 最大认证尝试次数
    "ban_duration_minutes": 30,            // 封禁时长(分钟)
    "enable_brute_force_protection": true, // 启用暴力破解保护
    "enable_ip_whitelist": false           // 启用IP白名单
  }
}
```

### 日志与监控

#### logging - 日志配置
```json
{
  "logging": {
    "level": "INFO",                       // 日志级别(DEBUG/INFO/WARNING/ERROR)
    "file": "logs/smartproxy.log",         // 日志文件路径
    "max_size": "10MB",                    // 单个日志文件最大大小
    "backup_count": 5,                     // 日志文件备份数量
    "enable_console": true                 // 是否启用控制台输出
  }
}
```

#### monitoring - 监控配置
```json
{
  "monitoring": {
    "enable_stats": true,                  // 启用统计信息
    "stats_interval": 60,                  // 统计信息收集间隔(秒)
    "log_slow_requests": true,             // 记录慢请求
    "slow_request_threshold_ms": 5000,     // 慢请求阈值(毫秒)
    "enable_real_time_monitoring": true    // 启用实时监控
  }
}
```

### 高级功能配置

#### advanced - 高级功能配置
```json
{
  "advanced": {
    "enable_connection_tracking": true,     // 启用连接跟踪
    "enable_traffic_shaping": true,         // 启用流量整形
    "enable_health_check": true,            // 启用健康检查
    "graceful_shutdown_timeout": 30,        // 优雅关闭超时(秒)
    "enable_memory_optimization": true,     // 启用内存优化
    "max_memory_usage_mb": 512              // 最大内存使用量(MB)
  }
}
```

### GeoIP配置

#### geoip - GeoIP地理位置配置
```json
{
  "geoip": {
    "enabled": false,                       // 是否启用GeoIP
    "database_path": "conf/GeoIP2-Country.mmdb", // GeoIP数据库路径
    "country_rules": {                      // 国家规则
      "CN": "direct",                       // 中国 - 直连
      "US": "proxy",                        // 美国 - 代理
      "JP": "proxy"                         // 日本 - 代理
    },
    "unknown_country_action": "proxy"       // 未知国家处理方式
  }
}
```

## 使用说明

1. **配置文件位置**: `conf/config.json`
2. **配置热重载**: 通过Web界面或API可重载配置
3. **配置验证**: 启动时会自动验证配置文件格式
4. **日志记录**: 配置错误会记录在日志中

## 最佳实践

1. **安全配置**:
   - 使用密码哈希而非明文密码
   - 启用IP白列表限制访问
   - 设置合理的认证尝试限制

2. **性能优化**:
   - 根据系统资源调整工作线程数
   - 启用内存池和零拷贝提升性能
   - 配置合适的缓存大小

3. **监控运维**:
   - 启用日志记录和监控统计
   - 配置健康检查确保节点可用性
   - 设置合理的时间和流量限制

## 注意事项

1. 代理节点的认证信息应妥善保管
2. 路由规则和ACL规则的顺序可能影响匹配结果
3. 部分配置项需要重启服务才能生效
4. GeoIP数据库需要定期更新以保持准确性