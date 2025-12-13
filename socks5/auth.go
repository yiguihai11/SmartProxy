package socks5

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"smartproxy/logger"
	"net"
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
	logger     *logger.SlogLogger
}

// NewPasswordHasher 创建新的密码哈希器
func NewPasswordHasher(iterations, saltLength int, hashName string, logger *logger.SlogLogger) *PasswordHasher {
	algorithm := fmt.Sprintf("pbkdf2-%s", hashName)

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

	return hashString, nil
}

// VerifyPassword 验证密码
func (p *PasswordHasher) VerifyPassword(password, hashString string) bool {
	if len(password) == 0 || len(hashString) == 0 {
		return false
	}

	_, iterations, salt, storedHash, err := p.parseHashString(hashString)
	if err != nil {
		p.logger.Info("Failed to parse hash string: %v", err)
		return false
	}

	// 使用相同的盐值和迭代次数计算哈希
	testHash := p.pbkdf2(password, salt, iterations, len(storedHash))

	// 使用恒定时间比较防止时序攻击
	isValid := subtle.ConstantTimeCompare(testHash, storedHash) == 1

	if isValid {
		p.logger.Info("Password verified successfully")
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

// checkPasswordStrength 检查密码强度
func (p *PasswordHasher) checkPasswordStrength(password string) error {
	if len(password) < MinPasswordLength {
		return &SecurityError{fmt.Sprintf("Password must be at least %d characters long", MinPasswordLength)}
	}

	// 简单的复杂度检查
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
		return &SecurityError{"Password must contain at least 3 of: uppercase, lowercase, digit, special character"}
	}

	return nil
}

// GetHashInfo 获取哈希字符串信息
func (p *PasswordHasher) GetHashInfo(hashString string) map[string]interface{} {
	algorithm, iterations, salt, hashBytes, err := p.parseHashString(hashString)
	if err != nil {
		return map[string]interface{}{
			"error": err.Error(),
		}
	}

	return map[string]interface{}{
		"algorithm":   algorithm,
		"iterations":  iterations,
		"salt_length": len(salt),
		"hash_length": len(hashBytes),
	}
}

// User 用户信息
type User struct {
	Username     string
	PasswordHash string
	Role         string
	Enabled      bool
	LastLogin    time.Time

	// 连接和时间限制
	MaxConnections int
	ExpiresAfter   int // 分钟数
	AllowFrom      []string
	BlockFrom      []string
	AllowedHours   []int
	AllowedDays    []int
	Timezone       string

	// 新增：日期限制
	EffectiveDates []string // 生效日期列表（字符串格式）
	ExpiredDates   []string // 过期日期列表（字符串格式）

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
	logger       *logger.SlogLogger
	sync.RWMutex // 添加读写锁
}

// NewAuthManager 创建认证管理器
func NewAuthManager(requireAuth bool, hasher *PasswordHasher, logger *logger.SlogLogger) *AuthManager {
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
	a.logger.Info("User '%s' added successfully", username)
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
	a.logger.Info("User '%s' added with full config (max_conn=%d, expires=%d min)", username, config.MaxConnections, config.ExpiresAfter)
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

	// 检查账户过期时间（基于最后登录时间的会话过期）
	if user.ExpiresAfter > 0 {
		expireTime := user.LastLogin.Add(time.Duration(user.ExpiresAfter) * time.Minute)
		if time.Now().After(expireTime) {
			return nil, &SecurityError{"Account session expired"}
		}
	}

	// 检查日期限制（生效日期和过期日期）
	now := time.Now()
	if !a.IsDateEffective(user.EffectiveDates, user.ExpiredDates, now) {
		return nil, &SecurityError{"Account not effective at this time"}
	}

	// 检查IP限制
	if len(user.BlockFrom) > 0 {
		for _, blockedIP := range user.BlockFrom {
			if a.matchesIPRange(clientIP, blockedIP) {
				return nil, &SecurityError{"IP blocked"}
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
			return nil, &SecurityError{"IP not allowed"}
		}
	}

	// 检查时间限制（使用增强版的时间检查）
	if !a.isTimeAllowedEnhanced(user, now) {
		return nil, &SecurityError{"Time restriction"}
	}

	// 检查连接数限制
	if user.MaxConnections > 0 && user.CurrentConnections >= user.MaxConnections {
		return nil, &SecurityError{"Connection limit exceeded"}
	}

	// 更新最后登录时间和活动统计
	user.LastLogin = now
	user.LastActivity = now
	user.CurrentConnections++
	user.TotalConnections++

	a.logger.Info("User '%s' authenticated successfully (IP: %s, Connections: %d/%d)",
		username, clientIP, user.CurrentConnections, user.MaxConnections)
	return user, nil
}

// RemoveUser 删除用户
func (a *AuthManager) RemoveUser(username string) error {
	if _, exists := a.users[username]; !exists {
		return &SecurityError{"User not found"}
	}

	delete(a.users, username)
	a.logger.Info("User '%s' removed successfully", username)
	return nil
}

// DisableUser 禁用用户
func (a *AuthManager) DisableUser(username string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	user.Enabled = false
	a.logger.Info("User '%s' disabled", username)
	return nil
}

// EnableUser 启用用户
func (a *AuthManager) EnableUser(username string) error {
	user, exists := a.users[username]
	if !exists {
		return &SecurityError{"User not found"}
	}

	user.Enabled = true
	a.logger.Info("User '%s' enabled", username)
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
	a.logger.Info("Password changed for user '%s'", username)
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
		// 检查密码是否为空
		if configUser.Password == "" {
			return &SecurityError{fmt.Sprintf("User %s: password cannot be empty", configUser.Username)}
		}

		user := &User{
			Username:       configUser.Username,
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
			EffectiveDates: []string{},
			ExpiredDates:   []string{},
		}

		// 如果密码不是哈希格式，则进行哈希
		if !strings.HasPrefix(configUser.Password, "$") {
			hashedPassword, err := a.hasher.HashPassword(configUser.Password)
			if err != nil {
				return fmt.Errorf("failed to hash password for user %s: %v", configUser.Username, err)
			}
			user.PasswordHash = hashedPassword
			a.logger.Info("Password hashed for user %s", configUser.Username)
		} else {
			// 已经是哈希格式
			user.PasswordHash = configUser.Password
		}

		// 处理连接限制配置
		if configUser.ConnectionLimit != nil {
			user.MaxConnections = configUser.ConnectionLimit.MaxConnections
			user.ExpiresAfter = configUser.ConnectionLimit.ExpiresAfter * 60 // 转换为秒
			user.AllowFrom = configUser.ConnectionLimit.AllowFrom
			user.BlockFrom = configUser.ConnectionLimit.BlockFrom

			// 处理时间限制
			if configUser.ConnectionLimit.TimeRestriction != nil {
				// 解析时间范围（支持 "09:00-18:00" 格式）
				if len(configUser.ConnectionLimit.TimeRestriction.AllowedHours) > 0 {
					user.AllowedHours = a.ParseTimeRanges(configUser.ConnectionLimit.TimeRestriction.AllowedHours)
				}

				// 解析星期名称（支持 "monday-friday" 格式）
				if len(configUser.ConnectionLimit.TimeRestriction.AllowedDays) > 0 {
					user.AllowedDays = a.ParseDayNames(configUser.ConnectionLimit.TimeRestriction.AllowedDays)
				}

				// 设置时区
				if configUser.ConnectionLimit.TimeRestriction.Timezone != "" {
					user.Timezone = configUser.ConnectionLimit.TimeRestriction.Timezone
				}

				// 设置生效日期
				user.EffectiveDates = configUser.ConnectionLimit.TimeRestriction.EffectiveDates

				// 设置过期日期
				user.ExpiredDates = configUser.ConnectionLimit.TimeRestriction.ExpiredDates
			}
		}

		a.users[configUser.Username] = user
	}

	a.logger.Info("Loaded %d users from config", len(configUsers))
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

// ParseTimeRanges 解析时间范围字符串（如 "09:00-18:00"）
func (a *AuthManager) ParseTimeRanges(timeRanges []string) []int {
	var hours []int
	for _, timeRange := range timeRanges {
		// 支持格式1: "09:00-18:00"
		if strings.Contains(timeRange, "-") {
			parts := strings.Split(timeRange, "-")
			if len(parts) == 2 {
				startHour := a.parseHour(parts[0])
				endHour := a.parseHour(parts[1])

				if startHour != -1 && endHour != -1 {
					for h := startHour; h <= endHour; h++ {
						hours = append(hours, h%24) // 处理跨天情况
					}
				}
			}
		} else {
			// 支持格式2: 单个小时 "09" 或 "9"
			if hour := a.parseHour(timeRange); hour != -1 {
				hours = append(hours, hour)
			}
		}
	}

	// 去重并排序
	return a.uniqueSortedHours(hours)
}

// parseHour 解析小时字符串
func (a *AuthManager) parseHour(hourStr string) int {
	// 移除可能的分钟部分
	if strings.Contains(hourStr, ":") {
		parts := strings.Split(hourStr, ":")
		if len(parts) >= 1 {
			hourStr = parts[0]
		}
	}

	// 去除前导零
	hourStr = strings.TrimPrefix(hourStr, "0")
	if hourStr == "" {
		hourStr = "0"
	}

	if hour, err := strconv.Atoi(hourStr); err == nil && hour >= 0 && hour <= 23 {
		return hour
	}

	return -1
}

// uniqueSortedHours 去重并排序小时列表
func (a *AuthManager) uniqueSortedHours(hours []int) []int {
	unique := make(map[int]bool)
	for _, h := range hours {
		unique[h] = true
	}

	result := make([]int, 0, len(unique))
	for h := range unique {
		result = append(result, h)
	}

	// 排序
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i] > result[j] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// ParseDayNames 解析星期名称列表
func (a *AuthManager) ParseDayNames(dayNames []string) []int {
	dayMap := map[string]int{
		"sunday":    0,
		"monday":    1,
		"tuesday":   2,
		"wednesday": 3,
		"thursday":  4,
		"friday":    5,
		"saturday":  6,
		// 支持缩写
		"sun": 0,
		"mon": 1,
		"tue": 2,
		"wed": 3,
		"thu": 4,
		"fri": 5,
		"sat": 6,
	}

	var days []int
	unique := make(map[int]bool)

	for _, dayName := range dayNames {
		// 支持范围格式 "monday-friday"
		if strings.Contains(dayName, "-") {
			parts := strings.Split(strings.ToLower(dayName), "-")
			if len(parts) == 2 {
				if startDay, ok := dayMap[parts[0]]; ok {
					if endDay, ok := dayMap[parts[1]]; ok {
						// 处理星期范围
						for d := startDay; d <= endDay; d++ {
							if !unique[d] {
								unique[d] = true
								days = append(days, d)
							}
						}
					}
				}
			}
		} else {
			// 单个星期名称
			if day, ok := dayMap[strings.ToLower(dayName)]; ok {
				if !unique[day] {
					unique[day] = true
					days = append(days, day)
				}
			}
		}
	}

	return days
}

// parseDate 解析日期字符串（支持 "2024-01-01" 格式）
func (a *AuthManager) parseDate(dateStr string) (time.Time, error) {
	// 尝试多种日期格式
	formats := []string{
		"2006-01-02",
		"2006/01/02",
		"2006-1-2",
		"2006/1/2",
		"01-02-2006",
		"01/02/2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// IsDateEffective 检查日期是否在生效范围内
func (a *AuthManager) IsDateEffective(effectiveDates []string, expiredDates []string, now time.Time) bool {
	// 如果没有设置任何日期限制，总是生效
	if len(effectiveDates) == 0 && len(expiredDates) == 0 {
		return true
	}

	// 检查生效日期
	if len(effectiveDates) > 0 {
		isEffective := false
		for _, effDate := range effectiveDates {
			if effDateParsed, err := a.parseDate(effDate); err == nil {
				if now.After(effDateParsed) || now.Equal(effDateParsed) {
					isEffective = true
					break
				}
			}
		}
		if !isEffective {
			return false // 不在任何生效日期之后
		}
	}

	// 检查过期日期
	if len(expiredDates) > 0 {
		for _, expDate := range expiredDates {
			if expDateParsed, err := a.parseDate(expDate); err == nil {
				if now.After(expDateParsed) || now.Equal(expDateParsed) {
					return false // 已过期
				}
			}
		}
	}

	return true
}

// isTimeAllowedEnhanced 增强的时间检查，支持所有格式
func (a *AuthManager) isTimeAllowedEnhanced(user *User, clientTime time.Time) bool {
	if len(user.AllowedHours) == 0 && len(user.AllowedDays) == 0 {
		return true // 无时间限制
	}

	// 处理时区
	loc, err := time.LoadLocation(user.Timezone)
	if err != nil {
		loc = time.UTC
	}
	localTime := clientTime.In(loc)

	// 检查日期是否有效
	// 注意：User结构需要扩展以支持日期限制
	// 这里暂时跳过日期检查

	// 检查星期几
	if len(user.AllowedDays) > 0 {
		currentDay := int(localTime.Weekday())
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

	// 检查小时
	if len(user.AllowedHours) > 0 {
		currentHour := localTime.Hour()
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
