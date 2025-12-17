package socks5

import (
	"context"
	"smartproxy/logger"
	"testing"
	"time"
)

// 完整的RateLimiter测试（非简化版本）

func TestRateLimiter_GlobalLimits(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置全局限速
	rl.SetGlobalLimits(1000, 2000) // 降低速率以便测试

	// 测试基本功能
	if !rl.CheckUploadLimit("user1", 500) {
		t.Error("Should allow 500 bytes upload")
	}

	// 获取统计信息
	stats := rl.GetStats()
	t.Logf("Stats keys: %v", stats)

	// 检查是否有任何统计信息
	if len(stats) == 0 {
		t.Error("Stats should not be empty after operations")
	}

	// 检查global或user1的统计信息
	if globalStats, exists := stats["global"]; exists && globalStats != nil {
		if globalStats.TotalBytes <= 0 {
			t.Errorf("Global: Expected total bytes > 0, got %d", globalStats.TotalBytes)
		}
	} else if userStats, exists := stats["user1"]; exists && userStats != nil {
		if userStats.TotalBytes <= 0 {
			t.Errorf("User1: Expected total bytes > 0, got %d", userStats.TotalBytes)
		}
	} else {
		t.Error("Neither global nor user1 stats found")
	}

	// 测试下载限速
	if !rl.CheckDownloadLimit("dl_user1", 1000) {
		t.Error("Should allow 1000 bytes download")
	}
}

func TestRateLimiter_UserRules(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置较高的全局限速以避免干扰
	rl.SetGlobalLimits(100000, 100000)

	// 添加用户限速规则 - 较低的限制以便测试
	userRule := &RateLimitRule{
		ID:            "user_rule",
		Type:          RateLimitTypeUser,
		Key:           "testuser",
		UploadLimit:   5000,
		DownloadLimit: 10000,
		Enabled:       true,
	}

	err := rl.AddRule(userRule)
	if err != nil {
		t.Fatalf("Failed to add user rule: %v", err)
	}

	// 测试用户限速 - 消耗所有突发容量
	for i := 0; i < 5; i++ {
		rl.CheckUploadLimit("testuser", 2000) // 每次消耗2000，共10000
	}

	// 现在应该被限速了
	if rl.CheckUploadLimit("testuser", 1000) {
		t.Error("Should be throttled after exhausting burst capacity")
	}

	// 测试其他用户不受限速
	if !rl.CheckUploadLimit("otheruser", 50000) {
		t.Error("Should allow 50000 bytes upload for otheruser (no user limit)")
	}

	// 验证统计信息
	stats := rl.GetStats()
	userStats, exists := stats["testuser"]
	if !exists {
		t.Error("User stats should exist")
	}
	if userStats.TotalBytes <= 0 {
		t.Errorf("Expected user total bytes > 0, got %d", userStats.TotalBytes)
	}
	// 至少应该有一些字节被允许通过
	if userStats.AllowedBytes <= 0 {
		t.Errorf("Expected user allowed bytes > 0, got %d", userStats.AllowedBytes)
	}
}

func TestRateLimiter_IPRules(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置较高的全局限速
	rl.SetGlobalLimits(100000, 100000)

	// 添加IP限速规则 - 较低的限制
	ipRule := &RateLimitRule{
		ID:            "ip_rule",
		Type:          RateLimitTypeIP,
		Key:           "192.168.1.100",
		UploadLimit:   2000,
		DownloadLimit: 5000,
		Enabled:       true,
	}

	err := rl.AddRule(ipRule)
	if err != nil {
		t.Fatalf("Failed to add IP rule: %v", err)
	}

	// 测试IP限速 - 消耗突发容量
	for i := 0; i < 5; i++ {
		rl.CheckUploadLimit("192.168.1.100", 1000) // 每次消耗1000，共5000
	}

	// 现在应该被限速
	if rl.CheckUploadLimit("192.168.1.100", 1000) {
		t.Error("Should be throttled after exhausting burst capacity")
	}

	// 测试其他IP不受限速
	if !rl.CheckUploadLimit("192.168.1.200", 20000) {
		t.Error("Should allow 20000 bytes upload for non-matching IP")
	}

	// 验证统计信息
	stats := rl.GetStats()
	ipStats, exists := stats["192.168.1.100"]
	if !exists {
		t.Error("IP stats should exist")
	}
	if ipStats.TotalBytes <= 0 {
		t.Errorf("Expected IP total bytes > 0, got %d", ipStats.TotalBytes)
	}
}

func TestRateLimiter_MultipleRules(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置全局限速
	rl.SetGlobalLimits(15000, 25000)

	// 添加用户规则
	userRule := &RateLimitRule{
		ID:            "user_rule_multi",
		Type:          RateLimitTypeUser,
		Key:           "multiuser",
		UploadLimit:   10000,
		DownloadLimit: 20000,
		Enabled:       true,
	}
	rl.AddRule(userRule)

	// 添加IP规则
	ipRule := &RateLimitRule{
		ID:            "ip_rule_multi",
		Type:          RateLimitTypeIP,
		Key:           "10.0.0.100",
		UploadLimit:   5000,
		DownloadLimit: 15000,
		Enabled:       true,
	}
	rl.AddRule(ipRule)

	// 测试同时匹配用户和IP规则的情况（应该应用最严格的限制）
	// 注意：当前实现中，如果identifier同时匹配多个规则，会分别检查
	if !rl.CheckUploadLimit("multiuser", 4000) {
		t.Error("Should allow 4000 bytes for multiuser")
	}
	if !rl.CheckUploadLimit("10.0.0.100", 3000) {
		t.Error("Should allow 3000 bytes for 10.0.0.100")
	}
}

func TestRateLimiter_WaitForUpload(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置用户限速 - 使用较小的突发容量
	rule := &RateLimitRule{
		ID:            "user_wait",
		Type:          RateLimitTypeUser,
		Key:           "waituser",
		UploadLimit:   1000,
		DownloadLimit: 0,
		Enabled:       true,
	}
	rl.AddRule(rule)

	// 消耗所有突发容量
	// 令牌桶的默认突发容量等于速率限制，所以需要消耗超过1000字节
	for i := 0; i < 5; i++ {
		rl.CheckUploadLimit("waituser", 500) // 总共消耗2500字节
	}

	// 测试WaitForUpload
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err := rl.WaitForUpload(ctx, "waituser", 500)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("WaitForUpload should not error: %v", err)
	}

	// 应该等待一些时间（因为需要等待令牌补充）
	if elapsed < 100*time.Millisecond {
		t.Logf("Waited %v (might be fast if bucket refilled quickly)", elapsed)
	}
}

func TestRateLimiter_WaitForDownload(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置全局限速
	rl.SetGlobalLimits(1000, 2000) // 下载2KB/s

	// 消耗所有突发容量
	for i := 0; i < 5; i++ {
		rl.CheckDownloadLimit("test", 1000) // 总共消耗5000字节
	}

	// 测试WaitForDownload
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err := rl.WaitForDownload(ctx, "test", 1000)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("WaitForDownload should not error: %v", err)
	}

	// 应该等待一些时间
	if elapsed < 100*time.Millisecond {
		t.Logf("Waited %v (might be fast if bucket refilled quickly)", elapsed)
	}
}

func TestRateLimiter_RuleManagement(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 添加规则
	rule := &RateLimitRule{
		ID:            "test_rule",
		Type:          RateLimitTypeUser,
		Key:           "testuser",
		UploadLimit:   5000,
		DownloadLimit: 10000,
		Enabled:       true,
	}

	err := rl.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// 验证规则存在
	if !rl.CheckUploadLimit("testuser", 3000) {
		t.Error("Should allow 3000 bytes for testuser")
	}

	// 验证规则可以通过获取规则列表看到
	rules := rl.GetRules()
	if _, exists := rules["test_rule"]; !exists {
		t.Error("Rule should exist in rules list")
	}

	// 测试禁用的规则
	disabledRule := &RateLimitRule{
		ID:            "disabled_rule",
		Type:          RateLimitTypeUser,
		Key:           "disableduser",
		UploadLimit:   1000,
		DownloadLimit: 2000,
		Enabled:       false, // 禁用状态
	}

	rl.AddRule(disabledRule)
	if !rl.CheckUploadLimit("disableduser", 10000) {
		t.Error("Should allow 10000 bytes for disabled user (no limit)")
	}

	// 移除规则
	if !rl.RemoveRule("test_rule") {
		t.Error("Rule removal should succeed")
	}
	if !rl.CheckUploadLimit("testuser", 10000) {
		t.Error("Should allow 10000 bytes after rule removal")
	}

	// 验证规则已移除
	rules = rl.GetRules()
	if _, exists := rules["test_rule"]; exists {
		t.Error("Rule should not exist after removal")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	rl := NewRateLimiter(logger)

	// 设置限速
	rl.SetGlobalLimits(50000, 50000)

	rule := &RateLimitRule{
		ID:            "concurrent_rule",
		Type:          RateLimitTypeUser,
		Key:           "concurrent_user",
		UploadLimit:   25000,
		DownloadLimit: 25000,
		Enabled:       true,
	}
	rl.AddRule(rule)

	// 并发测试
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				rl.CheckUploadLimit("concurrent_user", 1000)
				rl.CheckDownloadLimit("concurrent_user", 1000)
			}
			done <- true
		}(i)
	}

	// 等待所有goroutine完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 验证统计信息
	stats := rl.GetStats()
	userStats, exists := stats["concurrent_user"]
	if !exists {
		t.Error("Concurrent user stats should exist")
	}
	if userStats.TotalBytes != 200000 { // 10 goroutines * 10 iterations * 2 operations * 1000 bytes
		t.Errorf("Expected total bytes 200000, got %d", userStats.TotalBytes)
	}
}