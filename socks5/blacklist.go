package socks5

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// 分片数量，使用质数减少哈希冲突
	NumShards = 251
)

// IPShard 单个IP分片
type IPShard struct {
	ips   map[string]time.Time
	mutex sync.RWMutex
}

// BlacklistManager manages a thread-safe IP blacklist with sharded maps.
type BlacklistManager struct {
	shards         [NumShards]IPShard
	expiryDuration time.Duration
	logger         *log.Logger

	// 统计信息
	totalIPs     int64
	cleanupCount int64
}

// shardCount 计算IP应该分配到哪个分片
func (bm *BlacklistManager) shardCount(ipStr string) uint32 {
	// 使用FNV哈希算法
	hash := uint32(2166136261)
	for _, c := range ipStr {
		hash ^= uint32(c)
		hash *= 16777619
	}
	return hash % NumShards
}

// NewBlacklistManager creates and returns a new BlacklistManager.
func NewBlacklistManager(expiryMinutes int, logger *log.Logger) *BlacklistManager {
	if logger == nil {
		logger = log.New(log.Writer(), "[Blacklist] ", log.LstdFlags)
	}

	bm := &BlacklistManager{
		expiryDuration: time.Duration(expiryMinutes) * time.Minute,
		logger:         logger,
	}

	// 初始化所有分片
	for i := 0; i < NumShards; i++ {
		bm.shards[i].ips = make(map[string]time.Time)
	}

	// Start a background routine to clean up expired entries.
	go bm.startCleanupRoutine()
	logger.Printf("Blacklist manager initialized with %d shards and %v expiry duration.", NumShards, bm.expiryDuration)
	return bm
}

// Add adds an IP address to the blacklist. If the IP already exists,
// its expiry time is updated.
func (bm *BlacklistManager) Add(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		bm.logger.Printf("Attempted to add invalid IP to blacklist: %s", ipStr)
		return
	}

	ipStr = ip.String() // 规范化IP格式
	shardIndex := bm.shardCount(ipStr)
	shard := &bm.shards[shardIndex]

	expiryTime := time.Now().Add(bm.expiryDuration)

	// 使用原子操作更新统计信息
	addNew := false

	shard.mutex.Lock()
	if _, exists := shard.ips[ipStr]; !exists {
		addNew = true
	}
	shard.ips[ipStr] = expiryTime
	shard.mutex.Unlock()

	if addNew {
		atomic.AddInt64(&bm.totalIPs, 1)
	}
}

// IsBlacklisted checks if an IP address is currently on the blacklist.
func (bm *BlacklistManager) IsBlacklisted(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // Invalid IPs are not considered blacklisted.
	}

	ipStr = ip.String() // 规范化IP格式
	shardIndex := bm.shardCount(ipStr)
	shard := &bm.shards[shardIndex]

	shard.mutex.RLock()
	expiry, exists := shard.ips[ipStr]
	shard.mutex.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(expiry) {
		// The entry has expired but hasn't been cleaned up yet.
		return false
	}

	return true
}

// GetStats 获取黑名单统计信息
func (bm *BlacklistManager) GetStats() map[string]interface{} {
	totalIPs := atomic.LoadInt64(&bm.totalIPs)
	cleanupCount := atomic.LoadInt64(&bm.cleanupCount)

	// 统计各分片的IP数量
	var shardCounts []int
	for i := 0; i < NumShards; i++ {
		shard := &bm.shards[i]
		shard.mutex.RLock()
		shardCounts = append(shardCounts, len(shard.ips))
		shard.mutex.RUnlock()
	}

	// 计算分布方差（简单方法）
	maxCount := 0
	minCount := int(^uint32(0) >> 1) // 最大int值
	for _, count := range shardCounts {
		if count > maxCount {
			maxCount = count
		}
		if count < minCount {
			minCount = count
		}
	}

	return map[string]interface{}{
		"total_ips":       totalIPs,
		"cleanup_count":   cleanupCount,
		"shard_count":     NumShards,
		"shard_max_count": maxCount,
		"shard_min_count": minCount,
		"shard_balance":   maxCount - minCount,
	}
}

// startCleanupRoutine periodically scans the blacklist and removes expired entries.
func (bm *BlacklistManager) startCleanupRoutine() {
	// Clean up every 1/10th of the expiry duration, or 10 minutes, whichever is smaller.
	cleanupInterval := bm.expiryDuration / 10
	if cleanupInterval > 10*time.Minute {
		cleanupInterval = 10 * time.Minute
	}
	if cleanupInterval < 1*time.Minute {
		cleanupInterval = 1 * time.Minute
	}

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		bm.cleanup()
	}
}

// cleanup removes expired IP addresses from the blacklist (并发清理)
func (bm *BlacklistManager) cleanup() {
	now := time.Now()
	totalCleaned := 0

	// 并发清理所有分片
	var wg sync.WaitGroup
	for i := 0; i < NumShards; i++ {
		wg.Add(1)
		go func(shardIndex int) {
			defer wg.Done()
			shard := &bm.shards[shardIndex]

			shard.mutex.Lock()
			cleaned := 0
			for ip, expiry := range shard.ips {
				if now.After(expiry) {
					delete(shard.ips, ip)
					cleaned++
				}
			}
			shard.mutex.Unlock()

			if cleaned > 0 {
				atomic.AddInt64(&bm.totalIPs, -int64(cleaned))
				atomic.AddInt64(&bm.cleanupCount, 1)
				totalCleaned += cleaned
			}
		}(i)
	}

	wg.Wait()

	if totalCleaned > 0 {
		bm.logger.Printf("Cleaned up %d expired IP(s) from %d shards.", totalCleaned, NumShards)
	}
}
