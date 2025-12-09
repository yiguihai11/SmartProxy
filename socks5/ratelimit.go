package socks5

import (
	"context"
	"fmt"
	"log"
	"os"
	"smartproxy/config"
	"sync"
	"time"
)

// RateLimitType 限速类型
type RateLimitType string

const (
	RateLimitTypeGlobal     RateLimitType = "global"     // 全局限速
	RateLimitTypeUser       RateLimitType = "user"       // 用户限速
	RateLimitTypeIP         RateLimitType = "ip"         // IP限速
	RateLimitTypeConnection RateLimitType = "connection" // 连接限速
)

// RateLimitUnit 限速单位
type RateLimitUnit string

const (
	RateLimitUnitBps  RateLimitUnit = "bps"  // 每秒字节数
	RateLimitUnitKbps RateLimitUnit = "kbps" // 每秒千字节数
	RateLimitUnitMbps RateLimitUnit = "mbps" // 每秒兆字节数
)

// RateLimitRule 限速规则
type RateLimitRule struct {
	ID            string        `json:"id"`
	Type          RateLimitType `json:"type"`
	Key           string        `json:"key"`            // 限速键 (用户名/IP等)
	UploadLimit   int64         `json:"upload_limit"`   // 上传限速 (bps)
	DownloadLimit int64         `json:"download_limit"` // 下载限速 (bps)
	Enabled       bool          `json:"enabled"`
	Priority      int           `json:"priority"` // 优先级
}

// RateLimitStats 限速统计
type RateLimitStats struct {
	TotalBytes     int64     `json:"total_bytes"`
	AllowedBytes   int64     `json:"allowed_bytes"`
	ThrottledBytes int64     `json:"throttled_bytes"`
	DroppedBytes   int64     `json:"dropped_bytes"`
	LastUpdate     time.Time `json:"last_update"`
}

// TokenBucket 令牌桶实现
type TokenBucket struct {
	capacity   int64     // 桶容量 (bytes)
	tokens     int64     // 当前令牌数
	refillRate int64     // 每秒填充速率 (bytes)
	lastRefill time.Time // 上次填充时间
	mu         sync.Mutex
}

// NewTokenBucket 创建新的令牌桶
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow 检查是否允许通过指定字节数
func (tb *TokenBucket) Allow(bytes int64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// 填充令牌
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int64(elapsed * float64(tb.refillRate))

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}

	// 检查是否有足够令牌
	if tb.tokens >= bytes {
		tb.tokens -= bytes
		return true
	}

	return false
}

// WaitFor 等待直到可以通过指定字节数
func (tb *TokenBucket) WaitFor(ctx context.Context, bytes int64) error {
	for {
		if tb.Allow(bytes) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
			// 继续等待
		}
	}
}

// Available 返回当前可用令牌数
func (tb *TokenBucket) Available() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// 更新令牌
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int64(elapsed * float64(tb.refillRate))

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.capacity {
			tb.tokens = tb.capacity
		}
		tb.lastRefill = now
	}

	return tb.tokens
}

// RateLimiter 限速器
type RateLimiter struct {
	rules           map[string]*RateLimitRule
	uploadBuckets   map[string]*TokenBucket
	downloadBuckets map[string]*TokenBucket
	globalUpload    *TokenBucket
	globalDownload  *TokenBucket
	stats           map[string]*RateLimitStats
	mu              sync.RWMutex
	logger          Logger
}

// NewRateLimiter 创建新的限速器
func NewRateLimiter(logger Logger) *RateLimiter {
	if logger == nil {
		logger = log.New(os.Stdout, "[RateLimiter] ", log.LstdFlags)
	}

	return &RateLimiter{
		rules:           make(map[string]*RateLimitRule),
		uploadBuckets:   make(map[string]*TokenBucket),
		downloadBuckets: make(map[string]*TokenBucket),
		stats:           make(map[string]*RateLimitStats),
		logger:          logger,
	}
}

// SetGlobalLimits 设置全局限速
func (rl *RateLimiter) SetGlobalLimits(uploadBps, downloadBps int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.globalUpload = NewTokenBucket(uploadBps*2, uploadBps) // 2秒突发
	rl.globalDownload = NewTokenBucket(downloadBps*2, downloadBps)

	rl.logger.Printf("Set global rate limits: upload=%d bps, download=%d bps", uploadBps, downloadBps)
}

// AddRule 添加限速规则
func (rl *RateLimiter) AddRule(rule *RateLimitRule) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// 验证规则
	if rule.ID == "" {
		return &SecurityError{"Rule ID cannot be empty"}
	}

	if rule.UploadLimit <= 0 && rule.DownloadLimit <= 0 {
		return &SecurityError{"At least one limit must be specified"}
	}

	rl.rules[rule.ID] = rule

	// 自动计算突发大小：2秒突发容量
	key := rule.Key
	if rule.UploadLimit > 0 {
		uploadBurst := rule.UploadLimit * 2 // 2秒突发
		rl.uploadBuckets[key] = NewTokenBucket(uploadBurst, rule.UploadLimit)
	}
	if rule.DownloadLimit > 0 {
		downloadBurst := rule.DownloadLimit * 2 // 2秒突发
		rl.downloadBuckets[key] = NewTokenBucket(downloadBurst, rule.DownloadLimit)
	}

	// 初始化统计
	rl.stats[key] = &RateLimitStats{
		LastUpdate: time.Now(),
	}

	rl.logger.Printf("Added rate limit rule: %s (%s: %s)", rule.ID, rule.Type, key)
	return nil
}

// RemoveRule 移除限速规则
func (rl *RateLimiter) RemoveRule(ruleID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rule, exists := rl.rules[ruleID]
	if !exists {
		return false
	}

	key := rule.Key
	delete(rl.rules, ruleID)
	delete(rl.uploadBuckets, key)
	delete(rl.downloadBuckets, key)
	delete(rl.stats, key)

	rl.logger.Printf("Removed rate limit rule: %s", ruleID)
	return true
}

// CheckUploadLimit 检查上传限速
func (rl *RateLimiter) CheckUploadLimit(identifier string, bytes int64) bool {
	// 检查全局限速
	if rl.globalUpload != nil && !rl.globalUpload.Allow(bytes) {
		rl.updateStats("global", bytes, 0, bytes, 0)
		return false
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// 检查特定规则
	for _, rule := range rl.rules {
		if !rule.Enabled || rule.UploadLimit <= 0 {
			continue
		}

		if rl.matchesRule(rule, identifier) {
			bucket, exists := rl.uploadBuckets[rule.Key]
			if exists && !bucket.Allow(bytes) {
				rl.updateStats(rule.Key, bytes, 0, bytes, 0)
				return false
			}
		}
	}

	// 允许通过
	rl.updateStats(identifier, bytes, bytes, 0, 0)
	return true
}

// CheckDownloadLimit 检查下载限速
func (rl *RateLimiter) CheckDownloadLimit(identifier string, bytes int64) bool {
	// 检查全局限速
	if rl.globalDownload != nil && !rl.globalDownload.Allow(bytes) {
		rl.updateStats("global", bytes, 0, 0, bytes)
		return false
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// 检查特定规则
	for _, rule := range rl.rules {
		if !rule.Enabled || rule.DownloadLimit <= 0 {
			continue
		}

		if rl.matchesRule(rule, identifier) {
			bucket, exists := rl.downloadBuckets[rule.Key]
			if exists && !bucket.Allow(bytes) {
				rl.updateStats(rule.Key, bytes, 0, 0, bytes)
				return false
			}
		}
	}

	// 允许通过
	rl.updateStats(identifier, bytes, bytes, 0, 0)
	return true
}

// WaitForUpload 等待上传限速
func (rl *RateLimiter) WaitForUpload(ctx context.Context, identifier string, bytes int64) error {
	// 检查全局限速
	if rl.globalUpload != nil {
		if err := rl.globalUpload.WaitFor(ctx, bytes); err != nil {
			rl.updateStats("global", bytes, 0, bytes, 0)
			return err
		}
	}

	rl.mu.RLock()
	rules := make([]*RateLimitRule, 0, len(rl.rules))
	for _, rule := range rl.rules {
		if rule.Enabled && rule.UploadLimit > 0 && rl.matchesRule(rule, identifier) {
			rules = append(rules, rule)
		}
	}
	rl.mu.RUnlock()

	// 等待最严格的限制
	for _, rule := range rules {
		bucket := rl.uploadBuckets[rule.Key]
		if bucket != nil {
			if err := bucket.WaitFor(ctx, bytes); err != nil {
				rl.updateStats(rule.Key, bytes, 0, bytes, 0)
				return err
			}
		}
	}

	rl.updateStats(identifier, bytes, bytes, 0, 0)
	return nil
}

// WaitForDownload 等待下载限速
func (rl *RateLimiter) WaitForDownload(ctx context.Context, identifier string, bytes int64) error {
	// 检查全局限速
	if rl.globalDownload != nil {
		if err := rl.globalDownload.WaitFor(ctx, bytes); err != nil {
			rl.updateStats("global", bytes, 0, 0, bytes)
			return err
		}
	}

	rl.mu.RLock()
	rules := make([]*RateLimitRule, 0, len(rl.rules))
	for _, rule := range rl.rules {
		if rule.Enabled && rule.DownloadLimit > 0 && rl.matchesRule(rule, identifier) {
			rules = append(rules, rule)
		}
	}
	rl.mu.RUnlock()

	// 等待最严格的限制
	for _, rule := range rules {
		bucket := rl.downloadBuckets[rule.Key]
		if bucket != nil {
			if err := bucket.WaitFor(ctx, bytes); err != nil {
				rl.updateStats(rule.Key, bytes, 0, 0, bytes)
				return err
			}
		}
	}

	rl.updateStats(identifier, bytes, bytes, 0, 0)
	return nil
}

// matchesRule 检查标识符是否匹配规则
func (rl *RateLimiter) matchesRule(rule *RateLimitRule, identifier string) bool {
	switch rule.Type {
	case RateLimitTypeGlobal:
		return rule.Key == "global"
	case RateLimitTypeUser:
		return rule.Key == identifier
	case RateLimitTypeIP:
		return rule.Key == identifier
	case RateLimitTypeConnection:
		return rule.Key == identifier
	default:
		return false
	}
}

// updateStats 更新统计信息
func (rl *RateLimiter) updateStats(key string, total, allowed, throttled, dropped int64) {
	stats, exists := rl.stats[key]
	if !exists {
		stats = &RateLimitStats{LastUpdate: time.Now()}
		rl.stats[key] = stats
	}

	stats.TotalBytes += total
	stats.AllowedBytes += allowed
	stats.ThrottledBytes += throttled
	stats.DroppedBytes += dropped
	stats.LastUpdate = time.Now()
}

// GetStats 获取限速统计
func (rl *RateLimiter) GetStats() map[string]*RateLimitStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// 创建副本
	stats := make(map[string]*RateLimitStats)
	for key, stat := range rl.stats {
		statCopy := *stat
		stats[key] = &statCopy
	}

	return stats
}

// GetRules 获取所有限速规则
func (rl *RateLimiter) GetRules() map[string]*RateLimitRule {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// 创建副本
	rules := make(map[string]*RateLimitRule)
	for id, rule := range rl.rules {
		ruleCopy := *rule
		rules[id] = &ruleCopy
	}

	return rules
}

// GetBucketStatus 获取令牌桶状态
func (rl *RateLimiter) GetBucketStatus(key string) (uploadAvailable, downloadAvailable int64) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if bucket, exists := rl.uploadBuckets[key]; exists {
		uploadAvailable = bucket.Available()
	}

	if bucket, exists := rl.downloadBuckets[key]; exists {
		downloadAvailable = bucket.Available()
	}

	return
}

// ClearStats 清空统计信息
func (rl *RateLimiter) ClearStats() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.stats = make(map[string]*RateLimitStats)
}


// GetUsageRate 获取使用率 (0-100)
func (rl *RateLimiter) GetUsageRate(key string) (uploadRate, downloadRate float64) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if bucket, exists := rl.uploadBuckets[key]; exists {
		uploadRate = float64(bucket.capacity-bucket.tokens) / float64(bucket.capacity) * 100
	}

	if bucket, exists := rl.downloadBuckets[key]; exists {
		downloadRate = float64(bucket.capacity-bucket.tokens) / float64(bucket.capacity) * 100
	}

	return
}

// LoadUserRateLimitsFromConfig 从配置文件加载用户级限速
func (rl *RateLimiter) LoadUserRateLimitsFromConfig(configUsers []config.AuthUser) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// 清除现有的用户级限速规则
	for key, rule := range rl.rules {
		if rule.Type == RateLimitTypeUser {
			delete(rl.rules, key)
			delete(rl.uploadBuckets, key)
			delete(rl.downloadBuckets, key)
		}
	}

	// 加载新的用户级限速规则
	for _, configUser := range configUsers {
		if !configUser.Enabled || configUser.RateLimit == nil {
			continue
		}

		rule := &RateLimitRule{
			ID:            fmt.Sprintf("user_%s", configUser.Username),
			Type:          RateLimitTypeUser,
			Key:           configUser.Username,
			UploadLimit:   configUser.RateLimit.UploadBPS,
			DownloadLimit: configUser.RateLimit.DownloadBPS,
			Enabled:       true,
			Priority:      100, // 用户限速优先级较高
		}

		rl.rules[rule.ID] = rule

		// 自动计算突发大小：2秒突发容量
		if rule.UploadLimit > 0 {
			uploadBurst := rule.UploadLimit * 2 // 2秒突发
			rl.uploadBuckets[rule.Key] = NewTokenBucket(uploadBurst, rule.UploadLimit)
		}
		if rule.DownloadLimit > 0 {
			downloadBurst := rule.DownloadLimit * 2 // 2秒突发
			rl.downloadBuckets[rule.Key] = NewTokenBucket(downloadBurst, rule.DownloadLimit)
		}
	}

	rl.logger.Printf("Loaded rate limits for %d users from config", len(configUsers))
	return nil
}
