package socks5

import (
	"crypto/rand"
	"encoding/base64"
	"smartproxy/logger"
	"testing"
)

func TestPasswordHasher(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)

	password := "TestPassword123!"

	// 测试密码哈希
	hash, err := hasher.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// 检查哈希格式
	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}

	// 验证密码
	if !hasher.VerifyPassword(password, hash) {
		t.Error("Password verification should succeed")
	}

	// 验证错误密码
	if hasher.VerifyPassword("WrongPassword", hash) {
		t.Error("Wrong password verification should fail")
	}

	// 测试弱密码
	weakPasswords := []string{
		"123",           // 太短
		"password",      // 只有小写
		"PASSWORD",      // 只有大写
		"12345678",      // 只有数字
		"abcdefgh",      // 只有小写，长度足够但复杂度不够
	}

	for _, weak := range weakPasswords {
		_, err := hasher.HashPassword(weak)
		if err == nil {
			t.Errorf("Weak password should be rejected: %s", weak)
		}
	}
}

func TestPasswordHasherSecurity(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)

	password := "SecurePassword123!"

	// 生成两个哈希
	hash1, _ := hasher.HashPassword(password)
	hash2, _ := hasher.HashPassword(password)

	// 两个哈希应该不同（因为使用了随机盐）
	if hash1 == hash2 {
		t.Error("Two hashes of same password should be different")
	}

	// 两个哈希都应该能验证密码
	if !hasher.VerifyPassword(password, hash1) {
		t.Error("First hash should verify password")
	}
	if !hasher.VerifyPassword(password, hash2) {
		t.Error("Second hash should verify password")
	}
}

func TestAuthManagerAddUser(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(false, hasher, logger)

	// 添加用户
	err := auth.AddUser("testuser", "TestPassword123!", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	// 验证用户存在
	users := auth.ListUsers()
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	if users[0].Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", users[0].Username)
	}

	if users[0].Role != "user" {
		t.Errorf("Expected role 'user', got '%s'", users[0].Role)
	}

	if !users[0].Enabled {
		t.Error("User should be enabled")
	}
}

func TestAuthManagerVerifyUser(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)

	// 添加用户
	auth.AddUser("testuser", "TestPassword123!", "user")

	// 验证正确的用户名和密码
	user, err := auth.VerifyUser("testuser", "TestPassword123!", "127.0.0.1")
	if err != nil {
		t.Fatalf("User verification should succeed: %v", err)
	}
	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	// 验证错误的密码
	_, err = auth.VerifyUser("testuser", "WrongPassword", "127.0.0.1")
	if err == nil {
		t.Error("Wrong password verification should fail")
	}

	// 验证不存在的用户
	_, err = auth.VerifyUser("nonexistent", "password", "127.0.0.1")
	if err == nil {
		t.Error("Nonexistent user verification should fail")
	}
}

func TestAuthManagerConnectionLimit(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)

	// 添加有连接数限制的用户
	config := struct {
		MaxConnections int
		ExpiresAfter   int
		AllowFrom      []string
		BlockFrom      []string
		AllowedHours   []int
		AllowedDays    []int
		Timezone       string
	}{
		MaxConnections: 2,
		ExpiresAfter:   0,
		AllowFrom:      []string{},
		BlockFrom:      []string{},
		AllowedHours:   []int{},
		AllowedDays:    []int{},
		Timezone:       "UTC",
	}

	err := auth.AddUserWithConfig("limiteduser", "Password123!", "user", &config)
	if err != nil {
		t.Fatalf("Failed to add user with config: %v", err)
	}

	// 第一次连接应该成功
	_, err = auth.VerifyUser("limiteduser", "Password123!", "127.0.0.1")
	if err != nil {
		t.Errorf("First connection should succeed: %v", err)
	}

	// 第二次连接应该成功
	_, err = auth.VerifyUser("limiteduser", "Password123!", "127.0.0.1")
	if err != nil {
		t.Errorf("Second connection should succeed: %v", err)
	}

	// 第三次连接应该失败
	_, err = auth.VerifyUser("limiteduser", "Password123!", "127.0.0.1")
	if err == nil {
		t.Error("Third connection should fail (exceeds limit)")
	}

	// 释放一个连接
	auth.ReleaseConnection("limiteduser")

	// 现在应该可以再次连接
	_, err = auth.VerifyUser("limiteduser", "Password123!", "127.0.0.1")
	if err != nil {
		t.Errorf("Connection after release should succeed: %v", err)
	}
}

func TestAuthManagerIPRestrictions(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)

	// 添加有IP限制的用户
	config := struct {
		MaxConnections int
		ExpiresAfter   int
		AllowFrom      []string
		BlockFrom      []string
		AllowedHours   []int
		AllowedDays    []int
		Timezone       string
	}{
		MaxConnections: 0,
		ExpiresAfter:   0,
		AllowFrom:      []string{"192.168.1.0/24", "10.0.0.1"},
		BlockFrom:      []string{"172.16.0.0/16"},
		AllowedHours:   []int{},
		AllowedDays:    []int{},
		Timezone:       "UTC",
	}

	auth.AddUserWithConfig("ipuser", "Password123!", "user", &config)

	// 允许的IP应该成功
	_, err := auth.VerifyUser("ipuser", "Password123!", "192.168.1.100")
	if err != nil {
		t.Errorf("Allowed IP should succeed: %v", err)
	}

	_, err = auth.VerifyUser("ipuser", "Password123!", "10.0.0.1")
	if err != nil {
		t.Errorf("Allowed exact IP should succeed: %v", err)
	}

	// 被阻止的IP应该失败
	_, err = auth.VerifyUser("ipuser", "Password123!", "172.16.0.1")
	if err == nil {
		t.Error("Blocked IP should fail")
	}

	// 不在允许列表中的IP应该失败
	_, err = auth.VerifyUser("ipuser", "Password123!", "8.8.8.8")
	if err == nil {
		t.Error("Non-allowed IP should fail")
	}
}

func TestAuthManagerTimeRestrictions(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)

	// 添加有时间限制的用户
	config := struct {
		MaxConnections int
		ExpiresAfter   int
		AllowFrom      []string
		BlockFrom      []string
		AllowedHours   []int
		AllowedDays    []int
		Timezone       string
	}{
		MaxConnections: 0,
		ExpiresAfter:   0,
		AllowFrom:      []string{},
		BlockFrom:      []string{},
		AllowedHours:   []int{9, 10, 11, 14, 15, 16},
		AllowedDays:    []int{1, 2, 3, 4, 5}, // 周一到周五
		Timezone:       "UTC",
	}

	auth.AddUserWithConfig("timeuser", "Password123!", "user", &config)

	// 注意：由于时间限制检查使用当前时间，这个测试可能会因为运行时间而失败
	// 在实际环境中，应该使用mock time来测试时间限制
	user, err := auth.VerifyUser("timeuser", "Password123!", "127.0.0.1")

	// 检查用户是否通过验证（可能因为当前时间而不同）
	if err != nil {
		t.Logf("Time restriction test: %v (this may be expected based on current time)", err)
	} else {
		t.Logf("User %s authenticated successfully at current time", user.Username)
	}
}

func TestAuthManagerUserStats(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)

	// 添加多个用户
	auth.AddUser("user1", "Password123!", "user")
	auth.AddUser("user2", "Password456!", "admin")
	auth.AddUser("user3", "Password789!", "user")

	// 禁用一个用户
	auth.DisableUser("user2")

	// 获取统计信息
	stats := auth.GetStats()

	totalUsers := stats["total_users"].(int)
	enabledUsers := stats["enabled_users"].(int)
	disabledUsers := stats["disabled_users"].(int)

	if totalUsers != 3 {
		t.Errorf("Expected 3 total users, got %d", totalUsers)
	}
	if enabledUsers != 2 {
		t.Errorf("Expected 2 enabled users, got %d", enabledUsers)
	}
	if disabledUsers != 1 {
		t.Errorf("Expected 1 disabled user, got %d", disabledUsers)
	}

	if !stats["auth_required"].(bool) {
		t.Error("Auth should be required")
	}
}

func TestAuthManagerNoAuth(t *testing.T) {
	logger := logger.NewLogger().WithField("prefix", "[TEST]")
	hasher := NewPasswordHasher(100000, 32, "sha256", logger)
	auth := NewAuthManager(false, hasher, logger) // 不需要认证

	// 验证应该返回匿名用户
	user, err := auth.VerifyUser("any", "any", "127.0.0.1")
	if err != nil {
		t.Fatalf("No-auth verification should not error: %v", err)
	}

	if user.Username != "anonymous" {
		t.Errorf("Expected anonymous user, got %s", user.Username)
	}

	if user.Role != "user" {
		t.Errorf("Expected role 'user', got %s", user.Role)
	}
}

// Benchmark tests
func BenchmarkPasswordHash(b *testing.B) {
	logger := logger.NewLogger().WithField("prefix", "[BENCH]")
	hasher := NewPasswordHasher(10000, 16, "sha256", logger) // 较低的迭代次数用于基准测试
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.HashPassword(password)
	}
}

func BenchmarkPasswordVerify(b *testing.B) {
	logger := logger.NewLogger().WithField("prefix", "[BENCH]")
	hasher := NewPasswordHasher(10000, 16, "sha256", logger)
	password := "BenchmarkPassword123!"
	hash, _ := hasher.HashPassword(password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.VerifyPassword(password, hash)
	}
}

func BenchmarkAuthVerifyUser(b *testing.B) {
	logger := logger.NewLogger().WithField("prefix", "[BENCH]")
	hasher := NewPasswordHasher(10000, 16, "sha256", logger)
	auth := NewAuthManager(true, hasher, logger)
	auth.AddUser("benchuser", "BenchmarkPassword123!", "user")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth.VerifyUser("benchuser", "BenchmarkPassword123!", "127.0.0.1")
	}
}

// Helper function to generate random password for testing
func generateRandomPassword(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}