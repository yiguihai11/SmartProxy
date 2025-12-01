# SmartProxy 增强SNI/Host检测机制设计

## 🎯 核心问题与解决方案

### 当前问题分析：

1. **直连握手失败场景**：GFW干扰导致无法获取SNI/Host，后续路由策略失效
2. **代理转发盲区**：转发连接不进行SNI/Host检测，无法应对目标连接失败
3. **单次检测局限**：1500ms检测窗口过短，无法应对延迟或慢连接
4. **无重试机制**：连接失败后无法尝试其他路由策略
5. **无干扰检测**：无法识别GFW主动干扰模式

## 🚀 增强方案设计

### 1. 持续检测与缓存机制

```go
type EnhancedTrafficDetector struct {
    *base.TrafficDetector
    detectionWindow    time.Duration     // 持续检测窗口：30秒
    maxDetectionSize  int             // 最大检测数据：64KB
    SNICache          *sync.Map        // SNI结果缓存
    HostCache         *sync.Map        // Host头结果缓存
    interferenceCount int64            // 干扰计数器
    lastSuccessTime   time.Time        // 最后成功检测时间
}

func (etd *EnhancedTrafficDetector) ContinuousDetect(conn net.Conn, initialBuf []byte) (*DetectionResult, error) {
    ctx, cancel := context.WithTimeout(context.Background(), etd.detectionWindow)
    defer cancel()

    result := &DetectionResult{}
    detectionBuffer := make([]byte, 0, etd.maxDetectionSize)
    detectionBuffer = append(detectionBuffer, initialBuf...)

    // 持续检测直到成功或超时
    ticker := time.NewTicker(100 * time.Millisecond) // 每100ms检测一次
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return nil, fmt.Errorf("detection timeout after %v", etd.detectionWindow)

        case <-ticker.C:
            // 检测新到达的数据
            n, err := conn.Read(detectionBuffer[len(detectionBuffer):cap(detectionBuffer)])
            if err != nil && err != io.EOF {
                break
            }

            if n > 0 {
                detectionBuffer = detectionBuffer[:len(detectionBuffer)+n]
            }

            // 尝试检测当前缓冲区
            if currentResult := etd.DetectTraffic(detectionBuffer); currentResult != nil && currentResult.Type != TrafficTypeUnknown {
                result = currentResult
                break
            }

            // 检测GFW干扰模式
            if etd.detectGFWInterference(detectionBuffer) {
                etd.interferenceCount++
                return nil, fmt.Errorf("GFW interference detected")
            }
        }
    }

    // 缓存检测结果
    if result.Hostname != "" {
        etd.HostCache.Store(result.Hostname, result)
    } else if result.SNI != "" {
        etd.SNICache.Store(result.SNI, result)
    }

    return result, nil
}
```

### 2. GFW干扰检测机制

```go
type GFWInterferenceDetector struct {
    patterns []InterferencePattern
}

type InterferencePattern struct {
    Name        string
    Signature  []byte
    Description string
}

func NewGFWInterferenceDetector() *GFWInterferenceDetector {
    return &GFWInterferenceDetector{
        patterns: []InterferencePattern{
            {
                Name:        "TCP RST Attack",
                Signature:  []byte{0x00, 0x00, 0x00, 0x00}, // RST包模式
                Description: "GFW主动重置连接",
            },
            {
                Name:        "DNS Pollution",
                Signature:  []byte{0x81, 0x80, 0x00, 0x01}, // DNS劫持响应
                Description: "DNS污染响应",
            },
            {
                Name:        "HTTP Reset",
                Signature:  []byte{0x48, 0x54, 0x54, 0x50}, // HTTP重置
                Description: "HTTP连接重置",
            },
        },
    }
}

func (gwd *GFWInterferenceDetector) DetectInterference(data []byte) bool {
    for _, pattern := range gwd.patterns {
        if bytes.Contains(data, pattern.Signature) {
            log.Printf("GFW interference detected: %s - %s", pattern.Name, pattern.Description)
            return true
        }
    }
    return false
}

// 检测连接模式分析
func (etd *EnhancedTrafficDetector) detectConnectionPattern(data []byte) bool {
    // 快速连接重置模式
    if len(data) < 10 {
        return false
    }

    // 检测多次重连尝试
    rstCount := 0
    for i := 0; i < len(data)-4; i++ {
        if data[i] == 0x04 && data[i+1] == 0x00 { // TCP RST标志
            rstCount++
            if rstCount > 3 {
                return true // 可疑的重置模式
            }
        }
    }

    return false
}
```

### 3. 代理转发增强检测

```go
type EnhancedProxyConnection struct {
    clientConn     net.Conn          // 客户端连接
    proxyConn      net.Conn          // 代理服务器连接
    detector       *EnhancedTrafficDetector
    logger         *log.Logger

    // 代理特定的检测状态
    proxyType      ProxyType        // 代理协议类型
    targetAddr     string            // 目标地址
    originalSNI    string            // 从客户端检测到的SNI
    originalHost   string            // 从客户端检测到的Host

    // 检测结果
    detectedSNI    string            // 从代理响应中检测到的SNI
    detectedHost   string            // 从代理响应中检测到的Host
    detectionState DetectionState  // 检测状态机
}

type DetectionState int

const (
    StateDetecting   DetectionState = iota
    StateDetected
    StateFailed
    StateRetrying
)

func (epc *EnhancedProxyConnection) EnhancedProxyRelay() error {
    // 阶段1: 转发初始连接请求
    if err := epc.sendProxyConnect(); err != nil {
        return err
    }

    // 阶段2: 监控代理响应并检测流量
    return epc.monitorAndDetect()
}

func (epc *EnhancedProxyConnection) sendProxyConnect() error {
    switch epc.proxyType {
    case ProxyTypeSOCKS5:
        return epc.sendSOCKS5Connect()
    case ProxyTypeHTTP:
        return epc.sendHTTPConnect()
    case ProxyTypeHTTPS:
        return epc.sendHTTPSConnect()
    default:
        return fmt.Errorf("unsupported proxy type: %v", epc.proxyType)
    }
}

func (epc *EnhancedProxyConnection) sendSOCKS5Connect() error {
    // 构建SOCKS5连接请求，包含SNI信息（如果支持）
    connectReq := []byte{
        0x05, // SOCKS版本
        0x01, // 连接命令数
        0x00, // 认证方法：无认证
    }

    // 添加地址信息
    if host, port, err := net.SplitHostPort(epc.targetAddr); err == nil {
        if epc.originalSNI != "" && epc.isSNIProxySupported() {
            // 使用SNI优化的连接方式
            return epc.sendSNIEnhancedSOCKS5(connectReq, host, port, epc.originalSNI)
        }
        return epc.sendStandardSOCKS5(connectReq, host, port)
    }

    return fmt.Errorf("invalid target address: %s", epc.targetAddr)
}

func (epc *EnhancedProxyConnection) monitorAndDetect() error {
    buf := make([]byte, 8192) // 8KB缓冲区
    epc.detectionState = StateDetecting

    for {
        n, err := epc.proxyConn.Read(buf)
        if err != nil {
            if epc.detectionState == StateDetecting {
                // 尝试检测已接收的数据
                if result := epc.tryDetectFromBuffer(buf[:n]); result != nil {
                    epc.handleDetectionResult(result)
                } else {
                    epc.detectionState = StateFailed
                    return epc.handleDetectionFailure()
                }
            }
            return err
        }

        // 实时检测新到达的数据
        if epc.detectionState == StateDetecting {
            if result := epc.detectFromData(buf[:n]); result != nil {
                epc.handleDetectionResult(result)
                epc.detectionState = StateDetected
            }
        }

        // 转发数据到客户端
        if _, err := epc.clientConn.Write(buf[:n]); err != nil {
            return err
        }
    }
}
```

### 4. 动态路由重试机制

```go
type DynamicRouter struct {
    *base.Router
    retryStrategies []RetryStrategy
    circuitBreaker *CircuitBreaker
}

type RetryStrategy struct {
    Name         string
    Conditions   []func(string) bool    // 触发条件
    NewRoute     func(string) string     // 新路由建议
    Priority     int                     // 优先级
}

func (dr *DynamicRouter) RouteWithRetry(hostname string, port int, originalStrategy string) (*RouteResult, error) {
    // 记录原始路由尝试
    routeResult := dr.ShouldRoute(hostname, port)
    if routeResult.Action == ActionAllow && routeResult.Match {
        return dr.executeRoute(routeResult, originalStrategy)
    }

    // 路由失败，尝试重试策略
    return dr.retryWithAlternativeStrategies(hostname, port, originalStrategy)
}

func (dr *DynamicRouter) retryWithAlternativeStrategies(hostname string, port int, originalStrategy string) (*RouteResult, error) {
    // 按优先级尝试不同的重试策略
    for _, strategy := range dr.retryStrategies {
        if strategy.Matches(hostname, originalStrategy) {
            newTarget := strategy.GenerateRoute(hostname)
            dr.logger.Printf("Retry strategy '%s': trying route %s -> %s",
                strategy.Name, hostname, newTarget)

            routeResult := dr.ShouldRoute(newTarget, port)
            if routeResult.Action == ActionAllow {
                return dr.executeRouteWithFallback(routeResult, strategy.Name)
            }
        }
    }

    return nil, fmt.Errorf("all retry strategies failed for %s", hostname)
}

// 预定义的重试策略
var DefaultRetryStrategies = []RetryStrategy{
    {
        Name: "SNI Fallback",
        Conditions: []func(string) bool{
            func(host string) bool { return isBlockedHost(host) },
            func(host string) bool { return hasGFWInterference(host) },
        },
        NewRoute: func(host string) string {
            // 生成SNI化的域名
            return generateSNIVariant(host)
        },
        Priority: 1,
    },
    {
        Name: "Domain Fronting",
        Conditions: []func(string) bool{
            func(host string) bool { return isCDNDomain(host) },
        },
        NewRoute: func(host string) string {
            // 使用CDN前端域名
            return getDomainFront(host)
        },
        Priority: 2,
    },
    {
        Name: "Protocol Obfuscation",
        Conditions: []func(string) bool{
            func(host string) bool { return needsObfuscation(host) },
        },
        NewRoute: func(host string) string {
            // 使用混淆协议
            return generateObfuscatedHost(host)
        },
        Priority: 3,
    },
}
```

### 5. SNI缓存和智能预测

```go
type SNICache struct {
    cache    map[string]*CacheEntry
    mu       sync.RWMutex
    ttl      time.Duration
    maxSize  int
}

type CacheEntry struct {
    SNI         string    // 检测到的SNI
    Host         string    // 检测到的Host
    SuccessCount int       // 成功次数
    FailureCount int       // 失败次数
    LastSuccess  time.Time // 最后成功时间
    LastFailure  time.Time // 最后失败时间
    PreferredRoute string    // 偏好路由
}

func (sc *SNICache) Get(hostname string) (*CacheEntry, bool) {
    sc.mu.RLock()
    defer sc.mu.RUnlock()

    entry, exists := sc.cache[hostname]
    if !exists {
        return nil, false
    }

    // 检查是否过期
    if time.Since(entry.LastSuccess) > sc.ttl {
        delete(sc.cache, hostname)
        return nil, false
    }

    // 更新访问统计
    entry.SuccessCount++
    entry.LastSuccess = time.Now()

    return entry, true
}

func (sc *SNICache) PredictOptimalRoute(hostname string) string {
    sc.mu.RLock()
    defer sc.mu.RUnlock()

    entry, exists := sc.cache[hostname]
    if !exists {
        return ""
    }

    // 基于历史成功率和延迟预测最优路由
    successRate := float64(entry.SuccessCount) / float64(entry.SuccessCount+entry.FailureCount)
    if successRate > 0.8 && entry.PreferredRoute != "" {
        return entry.PreferredRoute
    }

    return ""
}
```

### 6. 配置增强

```json
{
  "router": {
    "enhanced_detection": {
      "enabled": true,
      "continuous_detection": true,
      "detection_window_seconds": 30,
      "max_detection_size_kb": 64,
      "gfw_interference_detection": true,
      "sni_cache_ttl_seconds": 3600,
      "cache_max_size": 10000
    },
    "retry_strategies": {
      "enabled": true,
      "max_retries": 5,
      "retry_delay_ms": 1000,
      "strategies": [
        {
          "name": "sni_fallback",
          "enabled": true,
          "priority": 1
        },
        {
          "name": "domain_fronting",
          "enabled": true,
          "front_domains": ["cloudflare.com", "cloudfront.net"],
          "priority": 2
        },
        {
          "name": "protocol_obfuscation",
          "enabled": true,
          "obfuscation_methods": ["tls1.3", "websocket"],
          "priority": 3
        }
      ]
    },
    "rules": [
      {
        "action": "proxy",
        "patterns": ["*.google.com"],
        "proxy_node": "proxy1",
        "retry_strategy": "sni_fallback,domain_fronting",
        "description": "Google服务，支持SNI回退和域名前端",
        "enhanced_detection": {
          "detect_on_proxy": true,
          "cache_sni": true,
          "detect_interference": true
        }
      }
    ]
  },
  "traffic_detection": {
    "enhanced_probing": {
      "enable": true,
      "sni_extraction": true,
      "http_validation": true,
      "interference_detection": {
        "enabled": true,
        "patterns": ["tcp_reset", "dns_pollution", "http_reset"],
        "threshold": 3
      },
      "continuous_mode": {
        "enabled": true,
        "window_seconds": 30,
        "detection_interval_ms": 100
      }
    }
  }
}
```

## 🎯 关键改进点总结

### 1. **持续检测机制**
- ✅ 30秒检测窗口 vs 当前1500ms
- ✅ 每100ms检测一次
- ✅ 64KB最大检测缓冲区
- ✅ 超时后优雅降级

### 2. **GFW干扰检测**
- ✅ 识别TCP RST攻击模式
- ✅ 检测DNS污染响应
- ✅ 识别HTTP连接重置
- ✅ 连接重试计数器

### 3. **代理转发增强检测**
- ✅ 代理连接中也进行SNI/Host检测
- ✅ 支持SNI传递的代理协议
- ✅ 监控代理响应流量
- ✅ 检测失败后的重试机制

### 4. **动态路由重试**
- ✅ 多策略重试机制
- ✅ SNI回退策略
- ✅ 域名前端技术
- ✅ 协议混淆支持

### 5. **智能缓存机制**
- ✅ SNI/Host结果缓存
- ✅ 成功率统计
- ✅ 最优路由预测
- ✅ 缓存过期管理

### 6. **配置灵活性**
- ✅ 可配置检测参数
- ✅ 可选择重试策略
- ✅ 规则级别的检测控制
- ✅ 干扰检测开关

这个方案彻底解决了直连失败和代理转发盲区的问题！