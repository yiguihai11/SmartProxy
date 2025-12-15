package socks5

import (
	"runtime"
	"sync"
	"time"
)

// MemoryStats 内存统计信息
type MemoryStats struct {
	// 系统内存信息
	Alloc      uint64  `json:"alloc"`        // 已分配的堆内存 (bytes)
	TotalAlloc uint64  `json:"total_alloc"`  // 累计分配的内存 (bytes)
	Sys        uint64  `json:"sys"`          // 从系统获得的内存 (bytes)
	NumGC      uint32  `json:"num_gc"`       // GC运行次数
	GCPause    uint64  `json:"gc_pause"`     // 累计GC暂停时间 (nanoseconds)

	// 应用内存统计
	ActiveConnections int64 `json:"active_connections"` // 当前活跃连接数
	ActiveUDPSessions int64 `json:"active_udp_sessions"` // 当前活跃UDP会话数
	ActiveDNSCache     int64 `json:"active_dns_cache"`    // DNS缓存条目数

	// 缓冲区池统计
	BufferPoolStats map[string]*PoolStats `json:"buffer_pool_stats"`
	mutex           sync.RWMutex
}

// PoolStats 对象池统计
type PoolStats struct {
	ActiveObjects   int64     `json:"active_objects"`   // 当前活跃对象数
	PooledObjects   int64     `json:"pooled_objects"`   // 池中对象数
	TotalRequests   int64     `json:"total_requests"`   // 总请求次数
	Hits            int64     `json:"hits"`             // 命中次数
	Misses          int64     `json:"misses"`           // 未命中次数
	Evictions       int64     `json:"evictions"`        // 驱逐次数
	TotalMemoryUsed int64     `json:"total_memory_used"` // 总内存使用量 (bytes)
	PoolMemoryUsed  int64     `json:"pool_memory_used"`  // 池中内存使用量 (bytes)
	MaxPoolSize     int64     `json:"max_pool_size"`    // 池最大大小
	LastAccess      time.Time `json:"last_access"`      // 最后访问时间
	mutex           sync.RWMutex
}

// MemoryMonitor 内存监控器
type MemoryMonitor struct {
	stats          *MemoryStats
	runtimeEnabled bool
	updateInterval time.Duration
	stopChan       chan struct{}
	ticker         *time.Ticker
	mutex          sync.RWMutex
	// 内存使用历史记录
	history       []MemorySnapshot
	maxHistory    int
}

// MemorySnapshot 内存快照
type MemorySnapshot struct {
	Timestamp       time.Time `json:"timestamp"`
	MemoryStats     *MemoryStats `json:"memory_stats"`
	LoadAverage     float64 `json:"load_average"`     // 负载平均值 (1分钟)
	ConnectionsPerSec int64    `json:"connections_per_sec"` // 每秒连接数
	RequestsPerSec  int64    `json:"requests_per_sec"`    // 每秒请求数
}

// 全局内存监控器
var globalMemoryMonitor *MemoryMonitor

// NewMemoryMonitor 创建新的内存监控器
func NewMemoryMonitor(updateInterval time.Duration) *MemoryMonitor {
	// 如果已经存在实例，直接返回
	if globalMemoryMonitor != nil {
		return globalMemoryMonitor
	}

	// 创建新实例
	monitor := &MemoryMonitor{
		stats: &MemoryStats{
			BufferPoolStats: make(map[string]*PoolStats),
		},
		runtimeEnabled:  true,
		updateInterval: updateInterval,
		maxHistory:     100, // 保留最近100个快照
		stopChan:       make(chan struct{}),
	}

	// 设置全局实例
	globalMemoryMonitor = monitor

	// 立即执行一次更新以获取初始数据
	monitor.updateMemoryStats()

	if monitor.updateInterval > 0 {
		monitor.ticker = time.NewTicker(updateInterval)
		go monitor.startMonitoring()
	}

	return monitor
}

// GetGlobalMemoryMonitor 获取全局内存监控器
func GetGlobalMemoryMonitor() *MemoryMonitor {
	if globalMemoryMonitor == nil {
		return NewMemoryMonitor(30 * time.Second) // 默认30秒更新间隔
	}
	return globalMemoryMonitor
}

// startMonitoring 启动内存监控
func (mm *MemoryMonitor) startMonitoring() {
	for {
		select {
		case <-mm.ticker.C:
			mm.updateMemoryStats()
		case <-mm.stopChan:
			return
		}
	}
}

// updateMemoryStats 更新内存统计信息
func (mm *MemoryMonitor) updateMemoryStats() {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 更新系统内存信息
	if mm.runtimeEnabled {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		mm.stats.Alloc = m.Alloc
		mm.stats.TotalAlloc = m.TotalAlloc
		mm.stats.Sys = m.Sys
		mm.stats.NumGC = m.NumGC
		mm.stats.GCPause = m.PauseTotalNs
	}

	// 创建内存快照（直接复制，避免死锁）
	snapshot := MemorySnapshot{
		Timestamp: time.Now(),
		MemoryStats: mm.copyStatsDirect(),
	}

	// 添加到历史记录
	mm.history = append(mm.history, snapshot)
	if len(mm.history) > mm.maxHistory {
		mm.history = mm.history[1:] // 移除最旧的快照
	}
}

// copyStatsDirect 在已持有锁的情况下复制统计信息
func (mm *MemoryMonitor) copyStatsDirect() *MemoryStats {
	// 深拷贝BufferPoolStats
	bufferPoolStats := make(map[string]*PoolStats)
	for name, stats := range mm.stats.BufferPoolStats {
		stats.mutex.RLock()
		bufferPoolStats[name] = &PoolStats{
			ActiveObjects:   stats.ActiveObjects,
			PooledObjects:   stats.PooledObjects,
			TotalRequests:   stats.TotalRequests,
			Hits:            stats.Hits,
			Misses:          stats.Misses,
			Evictions:       stats.Evictions,
			TotalMemoryUsed: stats.TotalMemoryUsed,
			PoolMemoryUsed:  stats.PoolMemoryUsed,
			MaxPoolSize:     stats.MaxPoolSize,
			LastAccess:      stats.LastAccess,
		}
		stats.mutex.RUnlock()
	}

	return &MemoryStats{
		Alloc:            mm.stats.Alloc,
		TotalAlloc:       mm.stats.TotalAlloc,
		Sys:              mm.stats.Sys,
		NumGC:            mm.stats.NumGC,
		GCPause:          mm.stats.GCPause,
		ActiveConnections: mm.stats.ActiveConnections,
		ActiveUDPSessions: mm.stats.ActiveUDPSessions,
		ActiveDNSCache:    mm.stats.ActiveDNSCache,
		BufferPoolStats:   bufferPoolStats,
	}
}

// getStatsCopy 获取统计信息的副本
func (mm *MemoryMonitor) getStatsCopy() *MemoryStats {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// 深拷贝BufferPoolStats
	bufferPoolStats := make(map[string]*PoolStats)
	for name, stats := range mm.stats.BufferPoolStats {
		stats.mutex.RLock()
		bufferPoolStats[name] = &PoolStats{
			ActiveObjects:   stats.ActiveObjects,
			PooledObjects:   stats.PooledObjects,
			TotalRequests:   stats.TotalRequests,
			Hits:            stats.Hits,
			Misses:          stats.Misses,
			Evictions:       stats.Evictions,
			TotalMemoryUsed: stats.TotalMemoryUsed,
			PoolMemoryUsed:  stats.PoolMemoryUsed,
			MaxPoolSize:     stats.MaxPoolSize,
			LastAccess:      stats.LastAccess,
		}
		stats.mutex.RUnlock()
	}

	return &MemoryStats{
		Alloc:            mm.stats.Alloc,
		TotalAlloc:       mm.stats.TotalAlloc,
		Sys:              mm.stats.Sys,
		NumGC:            mm.stats.NumGC,
		GCPause:          mm.stats.GCPause,
		ActiveConnections: mm.stats.ActiveConnections,
		ActiveUDPSessions: mm.stats.ActiveUDPSessions,
		ActiveDNSCache:    mm.stats.ActiveDNSCache,
		BufferPoolStats:   bufferPoolStats,
	}
}

// GetStats 获取当前内存统计信息
func (mm *MemoryMonitor) GetStats() *MemoryStats {
	return mm.getStatsCopy()
}

// GetHistory 获取内存历史记录
func (mm *MemoryMonitor) GetHistory() []MemorySnapshot {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// 返回历史记录的副本
	history := make([]MemorySnapshot, len(mm.history))
	copy(history, mm.history)
	return history
}

// Stop 停止内存监控
func (mm *MemoryMonitor) Stop() {
	if mm.ticker != nil {
		mm.ticker.Stop()
	}
	close(mm.stopChan)
}

// UpdateActiveConnections 更新活跃连接数
func (mm *MemoryMonitor) UpdateActiveConnections(count int64) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	mm.stats.ActiveConnections = count
}

// UpdateActiveUDPSessions 更新活跃UDP会话数
func (mm *MemoryMonitor) UpdateActiveUDPSessions(count int64) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	mm.stats.ActiveUDPSessions = count
}

// UpdateActiveDNSCache 更新DNS缓存条目数
func (mm *MemoryMonitor) UpdateActiveDNSCache(count int64) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	mm.stats.ActiveDNSCache = count
}

// RegisterPoolStats 注册对象池统计
func (mm *MemoryMonitor) RegisterPoolStats(name string, stats *PoolStats) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	mm.stats.BufferPoolStats[name] = stats
}

// UnregisterPoolStats 取消注册对象池统计
func (mm *MemoryMonitor) UnregisterPoolStats(name string) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()
	delete(mm.stats.BufferPoolStats, name)
}

// GetMemoryUsageReport 获取内存使用报告
func (mm *MemoryMonitor) GetMemoryUsageReport() map[string]interface{} {
	stats := mm.GetStats()

	report := map[string]interface{}{
		"timestamp": time.Now().Unix(),
		"system_memory": map[string]interface{}{
			"allocated_bytes":     stats.Alloc,
			"total_allocated":    stats.TotalAlloc,
			"system_bytes":       stats.Sys,
			"gc_count":           stats.NumGC,
			"gc_pause_ms":        stats.GCPause / 1000000, // 转换为毫秒
		},
		"application_memory": map[string]interface{}{
			"active_connections": stats.ActiveConnections,
			"active_udp_sessions": stats.ActiveUDPSessions,
			"dns_cache_entries":   stats.ActiveDNSCache,
		},
		"pool_stats": make(map[string]interface{}),
	}

	// 添加池统计信息
	for name, poolStats := range stats.BufferPoolStats {
		poolStats.mutex.RLock()
		hitRate := float64(0)
		if poolStats.TotalRequests > 0 {
			hitRate = float64(poolStats.Hits) / float64(poolStats.TotalRequests) * 100
		}

		report["pool_stats"].(map[string]interface{})[name] = map[string]interface{}{
			"active_objects":    poolStats.ActiveObjects,
			"pooled_objects":    poolStats.PooledObjects,
			"total_requests":    poolStats.TotalRequests,
			"hits":             poolStats.Hits,
			"misses":           poolStats.Misses,
			"hit_rate_percent":  hitRate,
			"evictions":        poolStats.Evictions,
			"total_memory_mb":   poolStats.TotalMemoryUsed / 1024 / 1024,
			"pool_memory_mb":    poolStats.PoolMemoryUsed / 1024 / 1024,
			"max_pool_size":     poolStats.MaxPoolSize,
			"last_access":       poolStats.LastAccess.Format(time.RFC3339),
		}
		poolStats.mutex.RUnlock()
	}

	return report
}

// InitMemoryStats 初始化内存统计
func (mm *MemoryMonitor) InitMemoryStats() {
	// 这里可以添加初始统计逻辑
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 重置统计信息
	mm.stats = &MemoryStats{
		BufferPoolStats: make(map[string]*PoolStats),
	}
}

// CleanupHistory 清理历史记录
func (mm *MemoryMonitor) CleanupHistory(olderThan time.Duration) {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	cutoff := time.Now().Add(-olderThan)
	newHistory := make([]MemorySnapshot, 0)

	for _, snapshot := range mm.history {
		if snapshot.Timestamp.After(cutoff) {
			newHistory = append(newHistory, snapshot)
		}
	}

	mm.history = newHistory
}

// GetMemoryEfficiency 获取内存效率报告
func (mm *MemoryMonitor) GetMemoryEfficiency() map[string]interface{} {
	stats := mm.GetStats()

	// 计算GC效率
	var gcEfficiency float64
	if stats.NumGC > 0 && stats.TotalAlloc > 0 {
		gcEfficiency = float64(stats.Alloc) / float64(stats.TotalAlloc) * 100
	}

	// 计算池化效率
	var totalHits, totalRequests int64
	for _, poolStats := range stats.BufferPoolStats {
		totalHits += poolStats.Hits
		totalRequests += poolStats.TotalRequests
	}

	var poolEfficiency float64
	if totalRequests > 0 {
		poolEfficiency = float64(totalHits) / float64(totalRequests) * 100
	}

	return map[string]interface{}{
		"gc_efficiency_percent": gcEfficiency,
		"pool_efficiency_percent": poolEfficiency,
		"total_requests": totalRequests,
		"total_hits": totalHits,
		"total_misses": totalRequests - totalHits,
		"memory_pressure": mm.getMemoryPressure(),
	}
}

// getMemoryPressure 获取内存压力等级
func (mm *MemoryMonitor) getMemoryPressure() string {
	if !mm.runtimeEnabled {
		return "unknown"
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 计算内存压力
	pressure := float64(m.Alloc) / float64(m.Sys)

	if pressure > 0.9 {
		return "high"
	} else if pressure > 0.7 {
		return "medium"
	} else {
		return "low"
	}
}