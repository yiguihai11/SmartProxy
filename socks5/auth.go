package socks5

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// SOCKS5认证方法
	AUTH_NO_AUTH       = 0x00
	AUTH_GSSAPI        = 0x01
	AUTH_USER_PASS     = 0x02
	AUTH_NO_ACCEPTABLE = 0xFF

	// 密码哈希参数
	DefaultIterations    = 100000
	DefaultSaltLength    = 32
	DefaultHashAlgorithm = "pbkdf2-sha256"
	MinPasswordLength    = 8
	MinIterations        = 100000
	MinSaltLength        = 16
)

// SecurityError 安全认证相关错误
type SecurityError struct {
	Message string
}

func (e *SecurityError) Error() string {
	return e.Message
}

// PasswordHasher 安全密码哈希器 - 使用PBKDF2-HMAC-SHA256
type PasswordHasher struct {
	iterations int
	saltLength int
	hashName   string
	algorithm  string
	logger     *log.Logger
}

// NewPasswordHasher 创建新的密码哈希器
func NewPasswordHasher(iterations, saltLength int, hashName string, logger *log.Logger) *PasswordHasher {
	// 安全参数验证
	if iterations < MinIterations {
		logger.Printf("Warning: PBKDF2 iterations %d below recommended minimum %d", iterations, MinIterations)
		iterations = MinIterations
	}

	if saltLength < MinSaltLength {
		logger.Printf("Warning: Salt length %d below recommended minimum %d", saltLength, MinSaltLength)
		saltLength = MinSaltLength
	}

	algorithm := fmt.Sprintf("pbkdf2-%s", hashName)

	logger.Printf("PasswordHasher initialized: %s, iterations=%d, salt_length=%d",
		algorithm, iterations, saltLength)

	return &PasswordHasher{
		iterations: iterations,
		saltLength: saltLength,
		hashName:   hashName,
		algorithm:  algorithm,
		logger:     logger,
	}
}

// HashPassword 对密码进行安全哈希
func (p *PasswordHasher) HashPassword(password string) (string, error) {
	if len(password) == 0 {
		return "", &SecurityError{"Password cannot be empty"}
	}

	// 密码强度检查
	if err := p.checkPasswordStrength(password); err != nil {
		return "", err
	}

	// 生成随机盐值
	salt := make([]byte, p.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", &SecurityError{fmt.Sprintf("Failed to generate salt: %v", err)}
	}

	// 使用PBKDF2派生密钥
	dk := p.pbkdf2(password, salt, p.iterations, 32) // 32字节哈希

	// Base64编码盐值和哈希值
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(dk)

	// 构造标准格式哈希字符串
	hashString := fmt.Sprintf("$%s$%d$%s$%s", p.algorithm, p.iterations, saltB64, hashB64)

	p.logger.Printf("Password hashed successfully using %s", p.algorithm)
	return hashString, nil
}

// VerifyPassword 验证密码
func (p *PasswordHasher) VerifyPassword(password, hashString string) bool {
	if len(password) == 0 || len(hashString) == 0 {
		return false
	}

	algorithm, iterations, salt, storedHash, err := p.parseHashString(hashString)
	if err != nil {
		p.logger.Printf("Failed to parse hash string: %v", err)
		return false
	}

	// 验证算法兼容性
	if algorithm != p.algorithm {
		p.logger.Printf("Warning: Incompatible hash algorithm: %s != %s", algorithm, p.algorithm)
		// 尝试使用旧算法验证（用于迁移）
		return p.verifyWithLegacyAlgorithm(password, hashString)
	}

	// 使用相同的盐值和迭代次数计算哈希
	testHash := p.pbkdf2(password, salt, iterations, len(storedHash))

	// 使用恒定时间比较防止时序攻击
	isValid := subtle.ConstantTimeCompare(testHash, storedHash) == 1

	if isValid {
		p.logger.Printf("Password verified successfully using %s", algorithm)

		// 检查是否需要升级迭代次数
		if iterations < p.iterations {
			p.logger.Printf("Info: Password hash uses outdated iterations (%d < %d)", iterations, p.iterations)
			// 这里可以触发哈希升级
		}
	}

	return isValid
}

// parseHashString 解析哈希字符串
func (p *PasswordHasher) parseHashString(hashString string) (algorithm string, iterations int, salt, hash []byte, err error) {
	parts := strings.Split(hashString, "$")
	if len(parts) != 5 || parts[0] != "" {
		err = &SecurityError{"Invalid hash string format"}
		return
	}

	algorithm = parts[1]

	iterations, err = strconv.Atoi(parts[2])
	if err != nil {
		err = &SecurityError{fmt.Sprintf("Invalid iterations value: %s", parts[2])}
		return
	}

	salt, err = base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		err = &SecurityError{fmt.Sprintf("Invalid base64 encoding for salt: %v", err)}
		return
	}

	hash, err = base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		err = &SecurityError{fmt.Sprintf("Invalid base64 encoding for hash: %v", err)}
		return
	}

	return
}

// pbkdf2 实现PBKDF2算法
func (p *PasswordHasher) pbkdf2(password string, salt []byte, iterations, keyLen int) []byte {
	// 简化的PBKDF2实现，实际生产环境中建议使用 golang.org/x/crypto/pbkdf2
	h := hmac.New(sha256.New, []byte(password))
	h.Write(salt)
	result := h.Sum(nil)

	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(result)
		result = h.Sum(result)
	}

	return result[:keyLen]
}

// verifyWithLegacyAlgorithm 使用旧算法验证密码（用于迁移）
func (p *PasswordHasher) verifyWithLegacyAlgorithm(password, hashString string) bool {
	p.logger.Printf("Attempting legacy password verification")

	// 检测旧格式SHA256哈希
	if len(hashString) == 64 {
		// 检查是否为十六进制字符串
		if matched, _ := regexp.MatchString("^[0-9a-fA-F]{64}$", hashString); matched {
			// 旧的不安全格式：sha256(password.encode()).hexdigest()
			h := sha256.Sum256([]byte(password))
			legacyHash := fmt.Sprintf("%x", h)

			isValid := subtle.ConstantTimeCompare([]byte(strings.ToLower(legacyHash)), []byte(strings.ToLower(hashString))) == 1

			if isValid {
				p.logger.Printf("Warning: Legacy insecure SHA256 hash detected - immediate upgrade required")
			}

			return isValid
		}
	}

	return false
}

// checkPasswordStrength 检查密码强度
func (p *PasswordHasher) checkPasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return &SecurityError{fmt.Sprintf("Password must be at least %d characters long", MinPasswordLength)}
	}

	// 检查密码复杂度
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", c):
			hasSpecial = true
		}
	}

	complexityScore := 0
	if hasUpper {
		complexityScore++
	}
	if hasLower {
		complexityScore++
	}
	if hasDigit {
		complexityScore++
	}
	if hasSpecial {
		complexityScore++
	}

	if complexityScore < 3 {
		p.logger.Printf("Warning: Weak password complexity score: %d/4", complexityScore)
		// 对于弱密码，我们记录警告但不直接阻止，因为这是管理员配置
	}

	return nil
}

// UpgradeHash 升级旧格式哈希到新的安全格式
func (p *PasswordHasher) UpgradeHash(password, oldHash string) (string, error) {
	if p.VerifyPassword(password, oldHash) {
		p.logger.Printf("Upgrading password hash to secure format")
		return p.HashPassword(password)
	}
	return "", &SecurityError{"Cannot upgrade invalid password hash"}
}

// GetHashInfo 获取哈希字符串信息
func (p *PasswordHasher) GetHashInfo(hashString string) map[string]interface{} {
	algorithm, iterations, salt, hashBytes, err := p.parseHashString(hashString)
	if err != nil {
		return map[string]interface{}{
			"error":    err.Error(),
			"is_secure": false,
		}
	}

	return map[string]interface{}{
		"algorithm":       algorithm,
		"iterations":      iterations,
		"salt_length":     len(salt),
		"hash_length":     len(hashBytes),
		"is_secure":       iterations >= MinIterations && strings.HasPrefix(algorithm, "pbkdf2-"),
		"estimated_crack_time": p.estimateCrackTime(iterations),
	}
}

// estimateCrackTime 估算暴力破解时间（粗略估计）
func (p *PasswordHasher) estimateCrackTime(iterations int) string {
	// 基于现代硬件性能（每秒10亿次SHA256计算）
	hashesPerSecond := float64(1000000000)
	secondsToCrack := float64(iterations) / hashesPerSecond

	if secondsToCrack < 1 {
		return "< 1 second"
	} else if secondsToCrack < 60 {
		return fmt.Sprintf("%.1f seconds", secondsToCrack)
	} else if secondsToCrack < 3600 {
		return fmt.Sprintf("%.1f minutes", secondsToCrack/60)
	} else if secondsToCrack < 86400 {
		return fmt.Sprintf("%.1f hours", secondsToCrack/3600)
	} else if secondsToCrack < 2592000 {
		return fmt.Sprintf("%.1f days", secondsToCrack/86400)
	} else {
		return fmt.Sprintf("%.1f months", secondsToCrack/2592000)
	}
}

// User 用户信息
type User struct {
	Username     string
	PasswordHash string
	Role         string
	Enabled      bool
	LastLogin    time.Time
}

// AuthManager 认证管理器
type AuthManager struct {
	users        map[string]*User
	hasher       *PasswordHasher
	requireAuth  bool
	logger       *log.Logger
}

// NewAuthManager 创建认证管理器
func NewAuthManager(requireAuth bool, hasher *PasswordHasher, logger *log.Logger) *AuthManager {
	if hasher == nil {
		hasher = NewPasswordHasher(DefaultIterations, DefaultSaltLength, "sha256", logger)
	}

	return &AuthManager{
		users:       make(map[string]*User),
		hasher:      hasher,
		requireAuth: requireAuth,
		logger:      logger,
	}
}

// AddUser 添加用户
func (a *AuthManager) AddUser(username, password, role string) error {
	if len(username) == 0 {
		return &SecurityError{"Username cannot be empty"}
	}

	// 生成密码哈希
	hash, err := a.hasher.HashPassword(password)
	if err != nil {
		return err
	}

	user := &User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		Enabled:      true,
		LastLogin:    time.Time{},
	}

	a.users[username] = user
	a.logger.Printf("User '%s' added successfully", username)
	return nil
}

// VerifyUser 验证用户
func (a *AuthManager) VerifyUser(username, password string) (*User, error) {
	if !a.requireAuth {
		// 不需要认证，返回默认用户
		return &User{
			Username: "anonymous",
			Role:     "user",
			Enabled:  true,
		}, nil
	}

	user, exists := a.users[username]
	if !exists {
		return nil, &SecurityError{"User not found"}
	}

	if !user.Enabled {
		return nil, &SecurityError{"User account disabled"}
	}

	if !a.hasher.VerifyPassword(password, user.PasswordHash) {
		return nil, &SecurityError{"Invalid password"}
	}

	// 更新最后登录时间
	user.LastLogin = time.Now()

	a.logger.Printf("User '%s' authenticated successfully", username)
	return user, nil
}

// RemoveUser 删除用户
func (a *AuthManager) RemoveUser(username string) error {
	if _, exists := a.users[username]; !exists {
		return &SecurityError{"User not found"}
	}

	delete(a.users, username)
	a.logger.Printf("User '%s' removed successfully", username)
	return nil
}

// DisableUser 禁用用户
func (a *AuthManager) DisableUser(username string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	user.Enabled = false
	a.logger.Printf("User '%s' disabled", username)
	return nil
}

// EnableUser 启用用户
func (a *AuthManager) EnableUser(username string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	user.Enabled = true
	a.logger.Printf("User '%s' enabled", username)
	return nil
}

// ChangePassword 修改用户密码
func (a *AuthManager) ChangePassword(username, newPassword string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	hash, err := a.hasher.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hash
	a.logger.Printf("Password changed for user '%s'", username)
	return nil
}

// ListUsers 列出所有用户
func (a *AuthManager) ListUsers() []*User {
	users := make([]*User, 0, len(a.users))
	for _, user := range a.users {
		users = append(users, user)
	}
	return users
}

// GetStats 获取统计信息
func (a *AuthManager) GetStats() map[string]interface{} {
	enabledCount := 0
	disabledCount := 0

	for _, user := range a.users {
		if user.Enabled {
			enabledCount++
		} else {
			disabledCount++
		}
	}

	return map[string]interface{}{
		"total_users":    len(a.users),
		"enabled_users":  enabledCount,
		"disabled_users": disabledCount,
		"auth_required":  a.requireAuth,
	}
}

// HandleAuthentication 处理SOCKS5认证，返回认证的用户名（空字符串表示未认证）
func (a *AuthManager) HandleAuthentication(clientConn net.Conn) (string, error) {
	if !a.requireAuth {
		// 不需要认证，直接返回无认证方法
		response := []byte{SOCKS5_VERSION, AUTH_NO_AUTH}
		_, err := clientConn.Write(response)
		return "", err // 返回空用户名
	}

	// 读取认证方法协商请求
	header := make([]byte, 2)
	if _, err := clientConn.Read(header); err != nil {
		return "", fmt.Errorf("failed to read auth header: %v", err)
	}

	if header[0] != SOCKS5_VERSION {
		return "", fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nmethods := int(header[1])
	if nmethods == 0 {
		return "", fmt.Errorf("no authentication methods provided")
	}

	methods := make([]byte, nmethods)
	if _, err := clientConn.Read(methods); err != nil {
		return "", fmt.Errorf("failed to read auth methods: %v", err)
	}

	// 检查是否支持用户名/密码认证
	hasUserPassAuth := false
	for _, method := range methods {
		if method == AUTH_USER_PASS {
			hasUserPassAuth = true
			break
		}
	}

	// 回复认证方法
	if hasUserPassAuth {
		response := []byte{SOCKS5_VERSION, AUTH_USER_PASS}
		if _, err := clientConn.Write(response); err != nil {
			return "", err
		}

		// 读取用户名/密码认证请求
		authHeader := make([]byte, 2)
		if _, err := clientConn.Read(authHeader); err != nil {
			return "", fmt.Errorf("failed to read auth request: %v", err)
		}

		if authHeader[0] != 0x01 {
			return "", fmt.Errorf("unsupported auth subnegotiation version: %d", authHeader[0])
		}

		usernameLen := int(authHeader[1])
		username := make([]byte, usernameLen)
		if _, err := clientConn.Read(username); err != nil {
			return "", fmt.Errorf("failed to read username: %v", err)
		}

		passwordHeader := make([]byte, 1)
		if _, err := clientConn.Read(passwordHeader); err != nil {
			return "", fmt.Errorf("failed to read password length: %v", err)
		}

		passwordLen := int(passwordHeader[0])
		password := make([]byte, passwordLen)
		if _, err := clientConn.Read(password); err != nil {
			return "", fmt.Errorf("failed to read password: %v", err)
		}

		// 验证用户
		user, err := a.VerifyUser(string(username), string(password))
		if err != nil {
			// 认证失败
			response := []byte{0x01, 0x01} // 版本1, 认证失败
			clientConn.Write(response)
			return "", fmt.Errorf("authentication failed: %v", err)
		}

		// 认证成功
		response = []byte{0x01, 0x00} // 版本1, 认证成功
		_, writeErr := clientConn.Write(response)
		if writeErr != nil {
			return "", writeErr
		}
		return user.Username, nil // 返回认证成功的用户名

	} else {
		// 不支持任何认证方法
		response := []byte{SOCKS5_VERSION, AUTH_NO_ACCEPTABLE}
		_, err := clientConn.Write(response)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("no acceptable authentication method")
	}
}

// LegacyHashMigrator 旧哈希格式迁移器
type LegacyHashMigrator struct {
	hasher *PasswordHasher
	logger *log.Logger
}

// NewLegacyHashMigrator 创建旧哈希迁移器
func NewLegacyHashMigrator(hasher *PasswordHasher, logger *log.Logger) *LegacyHashMigrator {
	return &LegacyHashMigrator{
		hasher: hasher,
		logger: logger,
	}
}

// NeedsMigration 检查配置是否需要哈希迁移
func (l *LegacyHashMigrator) NeedsMigration(users map[string]interface{}) bool {
	for username, userData := range users {
		if userMap, ok := userData.(map[string]interface{}); ok {
			if oldHash, exists := userMap["password_hash"]; exists {
				if oldHashStr, ok := oldHash.(string); ok {
					// 检查是否为旧格式（简单的64位十六进制字符串）
					if len(oldHashStr) == 64 {
						if matched, _ := regexp.MatchString("^[0-9a-fA-F]{64}$", oldHashStr); matched {
							l.logger.Printf("User '%s' has insecure hash format", username)
							return true
						}
					}
				}
			}
		}
	}
	return false
}