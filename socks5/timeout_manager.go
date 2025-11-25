package socks5

import (
	"log"
	"os"
	"sync"
	"time"
)

// ConnectionType 连接类型
type ConnectionType string

const (
	ConnectionTypeTCP ConnectionType = "tcp"
	ConnectionTypeUDP ConnectionType = "udp"
)

// ConnectionInfo 连接信息
type ConnectionInfo struct {
	ID              string          `json:"id"`
	Type            ConnectionType  `json:"type"`
	CreatedAt       time.Time       `json:"created_at"`
	LastActivity    time.Time       `json:"last_activity"`
	TargetPort      int             `json:"target_port"`
	BytesTransferred int64          `json:"bytes_transferred"`
	PacketCount     int64           `json:"packet_count"`
	ErrorCount      int             `json:"error_count"`
	IsIdle          bool            `json:"is_idle"`
	AdditionalInfo  map[string]interface{} `json:"additional_info,omitempty"`
}

// ConnectionStats 连接统计信息
type ConnectionStats struct {
	TCPConnections    int     `json:"tcp_connections"`
	UDPSessions       int     `json:"udp_sessions"`
	TotalTimeouts     int     `json:"total_timeouts"`
	ActiveConnections int     `json:"active_connections"`
	MemoryUsageEst    int     `json:"memory_usage_estimate"`
	AvgDuration       float64 `json:"avg_connection_duration"`
}

// ConnectionSettings 连接设置
type ConnectionSettings struct {
	TCPTimeoutSeconds int `json:"tcp_timeout_seconds"`
	UDPTimeoutSeconds int `json:"udp_timeout_seconds"`
}

// Config 配置接口
type TimeoutConfig interface {
	GetConnectionSettings() ConnectionSettings
}

// ConnectionTimeoutManager 连接超时管理器
type ConnectionTimeoutManager struct {
	config           TimeoutConfig
	logger           Logger
	activeConnections map[string]*ConnectionInfo
	connectionStats   ConnectionStats
	adaptiveTimeouts map[string]int
	connectionPatterns map[string]interface{}
	mu               sync.RWMutex
}

// NewConnectionTimeoutManager 创建连接超时管理器
func NewConnectionTimeoutManager(config TimeoutConfig, logger Logger) *ConnectionTimeoutManager {
	if logger == nil {
		logger = log.New(os.Stdout, "[TimeoutManager] ", log.LstdFlags)
	}

	ctm := &ConnectionTimeoutManager{
		config:           config,
		logger:           logger,
		activeConnections: make(map[string]*ConnectionInfo),
		connectionStats:   ConnectionStats{},
		adaptiveTimeouts: map[string]int{
			"tcp_short":  30,  // 短连接TCP超时 (如HTTP请求)
			"tcp_long":   300, // 长连接TCP超时 (如WebSocket)
			"tcp_idle":   60,  // 空闲TCP超时 (默认配置)
			"udp_active": 60,  // 活跃UDP会话超时
			"udp_idle":   180, // 空闲UDP会话超时
		},
		connectionPatterns: map[string]interface{}{
			"http_ports":         []int{80, 443, 8080, 8443},
			"streaming_ports":    []int{1935, 8000, 9000},
			"gaming_ports":       []int{}, // 使用范围检查
			"bittorrent_ports":   []int{6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889},
		},
	}

	return ctm
}

// GetTCPTimeout 根据连接信息动态确定TCP超时时间
func (ctm *ConnectionTimeoutManager) GetTCPTimeout(connectionInfo *ConnectionInfo) int {
	targetPort := connectionInfo.TargetPort
	bytesTransferred := connectionInfo.BytesTransferred
	connectionAge := time.Since(connectionInfo.CreatedAt).Seconds()
	isIdle := connectionInfo.IsIdle

	ctm.mu.RLock()
	httpPorts := ctm.connectionPatterns["http_ports"].([]int)
	streamingPorts := ctm.connectionPatterns["streaming_ports"].([]int)
	bittorrentPorts := ctm.connectionPatterns["bittorrent_ports"].([]int)
	ctm.mu.RUnlock()

	// 检测连接类型
	if ctm.containsInt(httpPorts, targetPort) {
		// HTTP/HTTPS连接 - 通常较短但有keep-alive
		if bytesTransferred > 1024*1024 { // 大文件传输
			longTimeout := ctm.adaptiveTimeouts["tcp_long"]
			adjustedTimeout := int(connectionAge + 120)
			if adjustedTimeout < longTimeout {
				return adjustedTimeout
			}
			return longTimeout
		} else if isIdle {
			return ctm.adaptiveTimeouts["tcp_short"]
		} else {
			return ctm.adaptiveTimeouts["tcp_idle"]
		}
	} else if ctm.containsInt(streamingPorts, targetPort) {
		// 流媒体连接 - 需要更长的超时
		return ctm.adaptiveTimeouts["tcp_long"]
	} else if ctm.isGamingPort(targetPort) {
		// 游戏连接 - 需要低延迟但稳定的连接
		idleTimeout := ctm.adaptiveTimeouts["tcp_idle"]
		if idleTimeout < 120 {
			return 120
		}
		return idleTimeout
	} else if ctm.containsInt(bittorrentPorts, targetPort) {
		// P2P连接 - 长时间保持
		return ctm.adaptiveTimeouts["tcp_long"]
	} else {
		// 默认策略 - 根据连接历史动态调整
		if connectionAge > 300 && bytesTransferred > 10*1024*1024 {
			// 长期活跃的大流量连接
			return ctm.adaptiveTimeouts["tcp_long"]
		} else if isIdle {
			return ctm.adaptiveTimeouts["tcp_idle"]
		} else {
			settings := ctm.config.GetConnectionSettings()
			return settings.TCPTimeoutSeconds
		}
	}
}

// GetUDPTimeout 根据UDP会话信息确定超时时间
func (ctm *ConnectionTimeoutManager) GetUDPTimeout(sessionInfo *ConnectionInfo) int {
	targetPort := sessionInfo.TargetPort
	packetCount := sessionInfo.PacketCount
	timeSinceActivity := time.Since(sessionInfo.LastActivity).Seconds()

	// DNS查询 - 短超时
	if targetPort == 53 {
		return 30
	}

	// DHCP - 中等超时
	if targetPort == 67 || targetPort == 68 {
		return 120
	}

	// 游戏或实时应用 - 根据活动频率调整
	if packetCount > 100 { // 高频会话
		if timeSinceActivity < 10 { // 仍在活跃
			return ctm.adaptiveTimeouts["udp_active"]
		} else { // 短暂空闲
			return ctm.adaptiveTimeouts["udp_idle"]
		}
	}

	// 默认UDP会话超时
	settings := ctm.config.GetConnectionSettings()
	return settings.UDPTimeoutSeconds
}

// ShouldForceCloseUDP 判断是否应该强制关闭UDP会话
func (ctm *ConnectionTimeoutManager) ShouldForceCloseUDP(sessionInfo *ConnectionInfo) bool {
	errorCount := sessionInfo.ErrorCount
	timeSinceActivity := time.Since(sessionInfo.LastActivity).Seconds()
	timeout := float64(ctm.GetUDPTimeout(sessionInfo))

	// 异常情况立即关闭
	if errorCount > 5 {
		return true
	}

	// 长时间无活动且无数据传输
	if timeSinceActivity > timeout*1.5 {
		return true
	}

	return false
}

// RegisterConnection 注册新连接进行跟踪
func (ctm *ConnectionTimeoutManager) RegisterConnection(connID string, connType ConnectionType, info map[string]interface{}) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	connectionInfo := &ConnectionInfo{
		ID:             connID,
		Type:           connType,
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
		AdditionalInfo: info,
	}

	// 从AdditionalInfo中提取常见字段
	if targetPort, exists := info["target_port"]; exists {
		if port, ok := targetPort.(int); ok {
			connectionInfo.TargetPort = port
		}
	}

	ctm.activeConnections[connID] = connectionInfo

	if connType == ConnectionTypeTCP {
		ctm.connectionStats.TCPConnections++
	} else if connType == ConnectionTypeUDP {
		ctm.connectionStats.UDPSessions++
	}

	ctm.logger.Printf("Registered %s connection: %s", connType, connID)
}

// UpdateConnectionActivity 更新连接活动状态
func (ctm *ConnectionTimeoutManager) UpdateConnectionActivity(connID string, bytesCount int64) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	if connInfo, exists := ctm.activeConnections[connID]; exists {
		connInfo.LastActivity = time.Now()
		connInfo.BytesTransferred += bytesCount
	}
}

// UpdatePacketCount 更新UDP包计数
func (ctm *ConnectionTimeoutManager) UpdatePacketCount(connID string, packetCount int64) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	if connInfo, exists := ctm.activeConnections[connID]; exists {
		connInfo.PacketCount += packetCount
	}
}

// IncrementErrorCount 增加错误计数
func (ctm *ConnectionTimeoutManager) IncrementErrorCount(connID string) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	if connInfo, exists := ctm.activeConnections[connID]; exists {
		connInfo.ErrorCount++
	}
}

// SetIdle 设置连接空闲状态
func (ctm *ConnectionTimeoutManager) SetIdle(connID string, isIdle bool) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	if connInfo, exists := ctm.activeConnections[connID]; exists {
		connInfo.IsIdle = isIdle
	}
}

// CleanupExpiredConnections 清理过期连接，返回被清理的连接ID列表
func (ctm *ConnectionTimeoutManager) CleanupExpiredConnections() []string {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	currentTime := time.Now()
	var expiredConnections []string

	for connID, connData := range ctm.activeConnections {
		var timeout int

		if connData.Type == ConnectionTypeTCP {
			timeout = ctm.GetTCPTimeout(connData)
		} else if connData.Type == ConnectionTypeUDP {
			timeout = ctm.GetUDPTimeout(connData)
		} else {
			continue
		}

		timeSinceActivity := currentTime.Sub(connData.LastActivity).Seconds()
		if timeSinceActivity > float64(timeout) {
			expiredConnections = append(expiredConnections, connID)
			delete(ctm.activeConnections, connID)

			// 更新统计
			if connData.Type == ConnectionTypeTCP {
				ctm.connectionStats.TCPConnections--
			} else if connData.Type == ConnectionTypeUDP {
				ctm.connectionStats.UDPSessions--
			}
			ctm.connectionStats.TotalTimeouts++

			ctm.logger.Printf("Expired connection cleaned up: %s (idle for %.1f seconds)", connID, timeSinceActivity)
		}
	}

	// 更新统计信息
	ctm.connectionStats.ActiveConnections = len(ctm.activeConnections)
	ctm.connectionStats.MemoryUsageEst = len(ctm.activeConnections) * 256 // 估算内存使用

	return expiredConnections
}

// GetConnectionStats 获取连接统计信息
func (ctm *ConnectionTimeoutManager) GetConnectionStats() ConnectionStats {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	// 复制统计信息
	stats := ctm.connectionStats
	stats.ActiveConnections = len(ctm.activeConnections)
	stats.MemoryUsageEst = len(ctm.activeConnections) * 256

	// 计算平均连接持续时间
	if stats.ActiveConnections > 0 {
		var totalDuration float64
		count := 0

		for _, conn := range ctm.activeConnections {
			totalDuration += time.Since(conn.CreatedAt).Seconds()
			count++
		}

		if count > 0 {
			stats.AvgDuration = totalDuration / float64(count)
		}
	}

	return stats
}

// GetActiveConnections 获取活跃连接列表
func (ctm *ConnectionTimeoutManager) GetActiveConnections() map[string]*ConnectionInfo {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	// 创建副本以避免并发访问问题
	connections := make(map[string]*ConnectionInfo)
	for id, conn := range ctm.activeConnections {
		// 创建副本
		connCopy := *conn
		connections[id] = &connCopy
	}

	return connections
}

// RemoveConnection 移除特定连接
func (ctm *ConnectionTimeoutManager) RemoveConnection(connID string) bool {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	if connData, exists := ctm.activeConnections[connID]; exists {
		delete(ctm.activeConnections, connID)

		// 更新统计
		if connData.Type == ConnectionTypeTCP {
			ctm.connectionStats.TCPConnections--
		} else if connData.Type == ConnectionTypeUDP {
			ctm.connectionStats.UDPSessions--
		}

		ctm.connectionStats.ActiveConnections = len(ctm.activeConnections)
		ctm.logger.Printf("Connection removed: %s", connID)
		return true
	}

	return false
}

// GetConnection 获取特定连接信息
func (ctm *ConnectionTimeoutManager) GetConnection(connID string) (*ConnectionInfo, bool) {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	if connInfo, exists := ctm.activeConnections[connID]; exists {
		// 返回副本
		connCopy := *connInfo
		return &connCopy, true
	}

	return nil, false
}

// UpdateAdaptiveTimeouts 更新自适应超时设置
func (ctm *ConnectionTimeoutManager) UpdateAdaptiveTimeouts(newTimeouts map[string]int) {
	ctm.mu.Lock()
	defer ctm.mu.Unlock()

	for key, value := range newTimeouts {
		if _, exists := ctm.adaptiveTimeouts[key]; exists {
			ctm.adaptiveTimeouts[key] = value
			ctm.logger.Printf("Updated adaptive timeout %s: %d seconds", key, value)
		}
	}
}

// 辅助方法

// containsInt 检查整数切片是否包含特定值
func (ctm *ConnectionTimeoutManager) containsInt(slice []int, value int) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// isGamingPort 检查是否为游戏端口
func (ctm *ConnectionTimeoutManager) isGamingPort(port int) bool {
	// 游戏端口通常在 10000-20000 范围内
	return port >= 10000 && port <= 20000
}

// GetTimeoutStats 获取超时统计信息
func (ctm *ConnectionTimeoutManager) GetTimeoutStats() map[string]interface{} {
	ctm.mu.RLock()
	defer ctm.mu.RUnlock()

	return map[string]interface{}{
		"adaptive_timeouts": ctm.adaptiveTimeouts,
		"connection_stats":  ctm.connectionStats,
		"total_connections":  len(ctm.activeConnections),
	}
}