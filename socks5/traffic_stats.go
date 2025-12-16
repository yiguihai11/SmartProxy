package socks5

import (
	"sync"
	"sync/atomic"
	"time"
)

// TrafficStats 流量统计
type TrafficStats struct {
	// 总流量（字节）
	TotalUpload   int64 `json:"total_upload"`
	TotalDownload int64 `json:"total_download"`

	// 会话统计
	ActiveConnections int64 `json:"active_connections"`

	mutex sync.RWMutex
}

// TrafficMonitor 流量监控器
type TrafficMonitor struct {
	stats          *TrafficStats
	updateInterval time.Duration
	stopChan       chan struct{}
	ticker         *time.Ticker
	mutex          sync.RWMutex

	// 连接流量跟踪
	connectionStats map[string]*ConnectionTraffic
	connMutex       sync.RWMutex
}

// ConnectionTraffic 单个连接的流量统计
type ConnectionTraffic struct {
	Upload   int64
	Download int64
	LastSeen time.Time
}

// 全局流量监控器
var globalTrafficMonitor *TrafficMonitor

// NewTrafficMonitor 创建新的流量监控器
func NewTrafficMonitor(updateInterval time.Duration) *TrafficMonitor {
	if globalTrafficMonitor != nil {
		return globalTrafficMonitor
	}

	monitor := &TrafficMonitor{
		stats:           &TrafficStats{},
		updateInterval:  updateInterval,
		stopChan:        make(chan struct{}),
		connectionStats: make(map[string]*ConnectionTraffic),
	}

	// 设置全局实例
	globalTrafficMonitor = monitor

	// 立即执行一次更新
	monitor.updateActiveConnections()

	if monitor.updateInterval > 0 {
		monitor.ticker = time.NewTicker(updateInterval)
		go monitor.startMonitoring()
	}

	return monitor
}

// GetGlobalTrafficMonitor 获取全局流量监控器
func GetGlobalTrafficMonitor() *TrafficMonitor {
	if globalTrafficMonitor == nil {
		return NewTrafficMonitor(1 * time.Second) // 默认1秒更新间隔
	}
	return globalTrafficMonitor
}

// startMonitoring 启动流量监控
func (tm *TrafficMonitor) startMonitoring() {
	for {
		select {
		case <-tm.ticker.C:
			tm.updateActiveConnections()
		case <-tm.stopChan:
			return
		}
	}
}

// updateActiveConnections 更新活跃连接数
func (tm *TrafficMonitor) updateActiveConnections() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// 更新活跃连接数
	tm.stats.ActiveConnections = int64(len(tm.connectionStats))
}

// AddConnection 添加连接
func (tm *TrafficMonitor) AddConnection(connID string) {
	tm.connMutex.Lock()
	defer tm.connMutex.Unlock()

	tm.connectionStats[connID] = &ConnectionTraffic{
		LastSeen: time.Now(),
	}
}

// RemoveConnection 移除连接
func (tm *TrafficMonitor) RemoveConnection(connID string) {
	tm.connMutex.Lock()
	defer tm.connMutex.Unlock()

	delete(tm.connectionStats, connID)
}

// RecordUpload 记录上传流量
func (tm *TrafficMonitor) RecordUpload(connID string, bytes int64) {
	atomic.AddInt64(&tm.stats.TotalUpload, bytes)

	tm.connMutex.Lock()
	if conn, exists := tm.connectionStats[connID]; exists {
		conn.Upload += bytes
		conn.LastSeen = time.Now()
	}
	tm.connMutex.Unlock()
}

// RecordDownload 记录下载流量
func (tm *TrafficMonitor) RecordDownload(connID string, bytes int64) {
	atomic.AddInt64(&tm.stats.TotalDownload, bytes)

	tm.connMutex.Lock()
	if conn, exists := tm.connectionStats[connID]; exists {
		conn.Download += bytes
		conn.LastSeen = time.Now()
	}
	tm.connMutex.Unlock()
}

// GetStats 获取流量统计
func (tm *TrafficMonitor) GetStats() *TrafficStats {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	// 返回副本
	stats := &TrafficStats{
		TotalUpload:       atomic.LoadInt64(&tm.stats.TotalUpload),
		TotalDownload:     atomic.LoadInt64(&tm.stats.TotalDownload),
		ActiveConnections: tm.stats.ActiveConnections,
	}

	return stats
}

// Stop 停止监控
func (tm *TrafficMonitor) Stop() {
	if tm.ticker != nil {
		tm.ticker.Stop()
	}
	close(tm.stopChan)
}

// Reset 重置统计
func (tm *TrafficMonitor) Reset() {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	atomic.StoreInt64(&tm.stats.TotalUpload, 0)
	atomic.StoreInt64(&tm.stats.TotalDownload, 0)
}
