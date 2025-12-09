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
	"smartproxy/config"
	"strconv"
	"strings"
	"sync"
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
		result = h.Sum(nil)
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
			"error":     err.Error(),
			"is_secure": false,
		}
	}

	return map[string]interface{}{
		"algorithm":            algorithm,
		"iterations":           iterations,
		"salt_length":          len(salt),
		"hash_length":          len(hashBytes),
		"is_secure":            iterations >= MinIterations && strings.HasPrefix(algorithm, "pbkdf2-"),
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

	// 新增：连接和时间限制
	MaxConnections int
	ExpiresAfter   int // 分钟数
	AllowFrom      []string
	BlockFrom      []string
	AllowedHours   []int
	AllowedDays    []int
	Timezone       string

	// 运行时统计
	CurrentConnections int
	TotalConnections   int64
	LastActivity       time.Time
}

// AuthManager 认证管理器
type AuthManager struct {
	users        map[string]*User
	hasher       *PasswordHasher
	requireAuth  bool
	logger       *log.Logger
	sync.RWMutex // 添加读写锁
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

// AddUser 添加用户（简化版）
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
		Username:           username,
		PasswordHash:       hash,
		Role:               role,
		Enabled:            true,
		LastLogin:          time.Time{},
		MaxConnections:     0,     // 默认无限制
		ExpiresAfter:       0,     // 默认永不过期
		AllowFrom:          nil,   // 默认允许所有IP
		BlockFrom:          nil,   // 默认不阻止任何IP
		AllowedHours:       nil,   // 默认所有时间
		AllowedDays:        nil,   // 默认所有日期
		Timezone:           "UTC", // 默认UTC
		CurrentConnections: 0,
		TotalConnections:   0,
		LastActivity:       time.Time{},
	}

	a.users[username] = user
	a.logger.Printf("User '%s' added successfully", username)
	return nil
}

// AddUserWithConfig 添加用户（完整配置版）
func (a *AuthManager) AddUserWithConfig(username, password, role string, config *struct {
	MaxConnections int
	ExpiresAfter   int
	AllowFrom      []string
	BlockFrom      []string
	AllowedHours   []int
	AllowedDays    []int
	Timezone       string
}) error {
	if len(username) == 0 {
		return &SecurityError{"Username cannot be empty"}
	}

	// 生成密码哈希
	hash, err := a.hasher.HashPassword(password)
	if err != nil {
		return err
	}

	user := &User{
		Username:           username,
		PasswordHash:       hash,
		Role:               role,
		Enabled:            true,
		LastLogin:          time.Time{},
		MaxConnections:     config.MaxConnections,
		ExpiresAfter:       config.ExpiresAfter,
		AllowFrom:          config.AllowFrom,
		BlockFrom:          config.BlockFrom,
		AllowedHours:       config.AllowedHours,
		AllowedDays:        config.AllowedDays,
		Timezone:           config.Timezone,
		CurrentConnections: 0,
		TotalConnections:   0,
		LastActivity:       time.Time{},
	}

	a.users[username] = user
	a.logger.Printf("User '%s' added with full config (max_conn=%d, expires=%d min)", username, config.MaxConnections, config.ExpiresAfter)
	return nil
}

// VerifyUser 验证用户
func (a *AuthManager) VerifyUser(username, password string, clientIP string) (*User, error) {
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

	// 检查账户过期时间
	if user.ExpiresAfter > 0 {
		expireTime := user.LastLogin.Add(time.Duration(user.ExpiresAfter) * time.Minute)
		if time.Now().After(expireTime) {
			return nil, &SecurityError{"Account expired"}
		}
	}

	// 检查IP限制
	if len(user.BlockFrom) > 0 {
		for _, blockedIP := range user.BlockFrom {
			if clientIP == blockedIP {
				return nil, &SecurityError{"IP blocked"}
			}
		}
	}

	if len(user.AllowFrom) > 0 {
		allowed := false
		for _, allowedIP := range user.AllowFrom {
			if clientIP == allowedIP {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, &SecurityError{"IP not allowed"}
		}
	}

	// 检查时间限制
	if !a.isTimeAllowed(user) {
		return nil, &SecurityError{"Time restriction"}
	}

	// 检查连接数限制
	if user.MaxConnections > 0 && user.CurrentConnections >= user.MaxConnections {
		return nil, &SecurityError{"Connection limit exceeded"}
	}

	// 更新最后登录时间和活动统计
	user.LastLogin = time.Now()
	user.LastActivity = time.Now()
	user.CurrentConnections++

	a.logger.Printf("User '%s' authenticated successfully (IP: %s, Connections: %d/%d)",
		username, clientIP, user.CurrentConnections, user.MaxConnections)
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

	// 检查支持的认证方法
	hasUserPassAuth := false
	hasNoAuth := false
	for _, method := range methods {
		if method == AUTH_USER_PASS {
			hasUserPassAuth = true
		}
		if method == AUTH_NO_AUTH {
			hasNoAuth = true
		}
	}

	// 回复认证方法
	if a.requireAuth {
		// 需要认证，但客户端不支持用户名密码认证
		if !hasUserPassAuth {
			response := []byte{SOCKS5_VERSION, AUTH_NO_ACCEPTABLE}
			if _, err := clientConn.Write(response); err != nil {
				return "", fmt.Errorf("failed to write auth response: %v", err)
			}
			return "", fmt.Errorf("client doesn't support required authentication")
		}

		// 使用用户名密码认证
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
		clientIP, _, err := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err != nil {
			clientIP = clientConn.RemoteAddr().String() // Fallback if SplitHostPort fails
		}
		user, err := a.VerifyUser(string(username), string(password), clientIP)
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

	} else if !a.requireAuth {
		// 不需要认证，使用无认证方法
		if !hasNoAuth {
			response := []byte{SOCKS5_VERSION, AUTH_NO_ACCEPTABLE}
			if _, err := clientConn.Write(response); err != nil {
				return "", fmt.Errorf("failed to write auth response: %v", err)
			}
			return "", fmt.Errorf("client doesn't support no-auth method")
		}

		// 发送无认证方法响应
		response := []byte{SOCKS5_VERSION, AUTH_NO_AUTH}
		if _, err := clientConn.Write(response); err != nil {
			return "", fmt.Errorf("failed to write auth response: %v", err)
		}

		return "", nil // 返回空用户名

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


// isTimeAllowed 检查时间是否允许
func (a *AuthManager) isTimeAllowed(user *User) bool {
	if len(user.AllowedHours) == 0 && len(user.AllowedDays) == 0 {
		return true // 无时间限制
	}

	now := time.Now()

	// 检查时区
	loc, err := time.LoadLocation(user.Timezone)
	if err != nil {
		loc = time.UTC
	}
	localNow := now.In(loc)

	// 检查星期几限制
	if len(user.AllowedDays) > 0 {
		currentDay := int(localNow.Weekday())
		allowed := false
		for _, allowedDay := range user.AllowedDays {
			if currentDay == allowedDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// 检查小时限制
	if len(user.AllowedHours) > 0 {
		currentHour := localNow.Hour()
		allowed := false
		for _, allowedHour := range user.AllowedHours {
			if currentHour == allowedHour {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	return true
}

// DecrementConnection 减少用户连接数
func (a *AuthManager) DecrementConnection(username string) {
	if user, exists := a.users[username]; exists {
		if user.CurrentConnections > 0 {
			user.CurrentConnections--
			user.LastActivity = time.Now()
		}
	}
}

// IncrementConnection 增加用户连接数
func (a *AuthManager) IncrementConnection(username string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	// 检查连接数限制
	if user.MaxConnections > 0 {
		if user.CurrentConnections >= user.MaxConnections {
			return &SecurityError{"Connection limit exceeded"}
		}
	}

	user.CurrentConnections++
	user.LastActivity = time.Now()
	return nil
}

// GetUserInfo 获取用户信息
func (a *AuthManager) GetUserInfo(username string) map[string]interface{} {
	if user, exists := a.users[username]; exists {
		return map[string]interface{}{
			"username":            user.Username,
			"enabled":             user.Enabled,
			"current_connections": user.CurrentConnections,
			"total_connections":   user.TotalConnections,
			"max_connections":     user.MaxConnections,
			"expires_after":       user.ExpiresAfter,
			"last_login":          user.LastLogin.Format("2006-01-02 15:04:05"),
			"last_activity":       user.LastActivity.Format("2006-01-02 15:04:05"),
			"allowed_hours":       user.AllowedHours,
			"allowed_days":        user.AllowedDays,
			"allowed_from":        user.AllowFrom,
			"blocked_from":        user.BlockFrom,
			"timezone":            user.Timezone,
		}
	}
	return map[string]interface{}{
		"error": "User not found",
	}
}

// LoadUsersFromConfig 从配置文件加载用户
func (a *AuthManager) LoadUsersFromConfig(configUsers []config.AuthUser) error {
	a.Lock()
	defer a.Unlock()

	a.users = make(map[string]*User)

	for _, configUser := range configUsers {
		user := &User{
			Username:       configUser.Username,
			PasswordHash:   configUser.Password, // 使用明文密码，实际生产环境应该加密
			Role:           "user",
			Enabled:        configUser.Enabled,
			LastLogin:      time.Now(),
			MaxConnections: 0,
			ExpiresAfter:   0,
			AllowFrom:      []string{},
			BlockFrom:      []string{},
			AllowedHours:   []int{},
			AllowedDays:    []int{},
			Timezone:       "UTC",
		}

		// 处理连接限制配置
		if configUser.ConnectionLimit != nil {
			user.MaxConnections = configUser.ConnectionLimit.MaxConnections
			user.ExpiresAfter = configUser.ConnectionLimit.ExpiresAfter * 60 // 转换为秒
			user.AllowFrom = configUser.ConnectionLimit.AllowFrom
			user.BlockFrom = configUser.ConnectionLimit.BlockFrom

			// 处理时间限制
			if configUser.ConnectionLimit.TimeRestriction != nil {
				// 字符串数组转换为int数组，简化处理
				if len(configUser.ConnectionLimit.TimeRestriction.AllowedHours) > 0 {
					user.AllowedHours = make([]int, len(configUser.ConnectionLimit.TimeRestriction.AllowedHours))
					user.Timezone = configUser.ConnectionLimit.TimeRestriction.Timezone
				}
			}
		}

		a.users[configUser.Username] = user
	}

	a.logger.Printf("Loaded %d users from config", len(configUsers))
	return nil
}

// CheckConnectionLimit 检查用户的连接限制
func (a *AuthManager) CheckConnectionLimit(username string, clientIP string) error {
	a.RLock()
	defer a.RUnlock()

	user, exists := a.users[username]
	if !exists {
		return nil // 用户不存在，不进行连接限制检查
	}

	if !user.Enabled {
		return fmt.Errorf("user %s is disabled", username)
	}

	// 检查最大连接数
	if user.MaxConnections > 0 && user.CurrentConnections >= user.MaxConnections {
		return fmt.Errorf("user %s has exceeded maximum connections (%d)", username, user.MaxConnections)
	}

	// 检查IP限制
	if len(user.BlockFrom) > 0 {
		for _, blockedIP := range user.BlockFrom {
			if a.matchesIPRange(clientIP, blockedIP) {
				return fmt.Errorf("IP %s is blocked for user %s", clientIP, username)
			}
		}
	}

	if len(user.AllowFrom) > 0 {
		allowed := false
		for _, allowedIP := range user.AllowFrom {
			if a.matchesIPRange(clientIP, allowedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("IP %s is not allowed for user %s", clientIP, username)
		}
	}

	// 检查时间限制
	if len(user.AllowedHours) > 0 || len(user.AllowedDays) > 0 {
		if !a.isTimeAllowed(user) {
			return fmt.Errorf("access not allowed at this time for user %s", username)
		}
	}

	// 增加连接计数
	user.CurrentConnections++

	return nil
}

// ReleaseConnection 释放连接计数
func (a *AuthManager) ReleaseConnection(username string) {
	a.Lock()
	defer a.Unlock()

	if user, exists := a.users[username]; exists {
		if user.CurrentConnections > 0 {
			user.CurrentConnections--
		}
	}
}

// matchesIPRange 检查IP是否匹配网段
func (a *AuthManager) matchesIPRange(ip, cidr string) bool {
	if !strings.Contains(cidr, "/") {
		return ip == cidr
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	return ipNet.Contains(clientIP)
}
