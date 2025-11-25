package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebConfig Web界面配置
type WebConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// UserInfo 用户信息（用于API响应，不包含密码）
type UserInfo struct {
	Username string            `json:"username"`
	Enabled  bool              `json:"enabled"`
	ACLs     map[string]string `json:"acls"`
}

// APIResponse 统一API响应格式
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Stats 统计信息
type Stats struct {
	StartTime     time.Time `json:"start_time"`
	Connections   int       `json:"connections"`
	TotalRequests int       `json:"total_requests"`
	ActiveUsers   int       `json:"active_users"`
	ProxyNodes    int       `json:"proxy_nodes"`
}

// WebServer Web管理界面服务器
type WebServer struct {
	config      interface{} // 配置管理器接口
	webConfig   WebConfig
	port        int
	enabled     bool
	logger      *log.Logger
	server      *http.Server
	startTime   time.Time
	webRoot     string
	mu          sync.RWMutex

	// 统计信息
	stats       Stats
	statsMu     sync.RWMutex

	// 用户管理（简化版）
	users       map[string]User
	usersMu     sync.RWMutex
}

// User 用户信息（包含密码哈希）
type User struct {
	Username     string            `json:"username"`
	PasswordHash string            `json:"password_hash"`
	Enabled      bool              `json:"enabled"`
	ACLs         map[string]string `json:"acls"`
}

// ConfigManager 配置管理器接口
type ConfigManager interface {
	GetUsers() map[string]User
	SaveConfig() error
	GetProxyNodes() []interface{}
	AddProxyNode(node interface{}) error
	DeleteProxyNode(id string) error
}

// NewWebServer 创建Web服务器
func NewWebServer(config ConfigManager, webConfig WebConfig, logger *log.Logger) *WebServer {
	if logger == nil {
		logger = log.New(os.Stdout, "[WebServer] ", log.LstdFlags)
	}

	// 默认配置
	if webConfig.Port == 0 {
		webConfig.Port = 8080
	}

	ws := &WebServer{
		config:    config,
		webConfig: webConfig,
		port:      webConfig.Port,
		enabled:   webConfig.Enabled,
		logger:    logger,
		startTime: time.Now(),
		webRoot:   "./web", // Web资源目录
		stats: Stats{
			StartTime: time.Now(),
		},
		users: make(map[string]User),
	}

	// 初始化路由
	ws.setupRoutes()

	return ws
}

// setupRoutes 设置HTTP路由
func (ws *WebServer) setupRoutes() {
	mux := http.NewServeMux()

	// API路由
	mux.HandleFunc("/api/users", ws.handleUsers)
	mux.HandleFunc("/api/status", ws.handleStatus)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/config", ws.handleConfig)
	mux.HandleFunc("/api/proxy-nodes", ws.handleProxyNodes)

	// 静态文件服务
	mux.HandleFunc("/", ws.handleStatic)

	ws.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ws.port),
		Handler: ws.corsMiddleware(mux),
	}
}

// Start 启动Web服务器
func (ws *WebServer) Start() error {
	if !ws.enabled {
		ws.logger.Printf("Web interface disabled")
		return nil
	}

	ws.logger.Printf("Starting web server on port %d", ws.port)

	// 在goroutine中启动服务器
	go func() {
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ws.logger.Printf("Web server error: %v", err)
		}
	}()

	ws.logger.Printf("Web interface started on http://localhost:%d", ws.port)
	return nil
}

// Stop 停止Web服务器
func (ws *WebServer) Stop() error {
	if ws.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return ws.server.Shutdown(ctx)
	}
	return nil
}

// corsMiddleware CORS中间件
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 设置CORS头
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// 处理预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// sendJSONResponse 发送JSON响应
func (ws *WebServer) sendJSONResponse(w http.ResponseWriter, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")

	if response.Success {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}

	json.NewEncoder(w).Encode(response)
}

// handleUsers 处理用户相关API
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ws.getUsers(w, r)
	case http.MethodPost:
		ws.updateUser(w, r)
	case http.MethodPut:
		ws.updateUser(w, r) // PUT也使用相同的处理逻辑
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getUsers 获取用户列表
func (ws *WebServer) getUsers(w http.ResponseWriter, r *http.Request) {
	ws.usersMu.RLock()
	defer ws.usersMu.RUnlock()

	var users []UserInfo
	for _, user := range ws.users {
		users = append(users, UserInfo{
			Username: user.Username,
			Enabled:  user.Enabled,
			ACLs:     user.ACLs,
		})
	}

	response := APIResponse{
		Success: true,
		Data:    users,
	}

	ws.sendJSONResponse(w, response)
}

// updateUser 更新用户信息
func (ws *WebServer) updateUser(w http.ResponseWriter, r *http.Request) {
	var userData struct {
		Username string            `json:"username"`
		Password string            `json:"password"`
		Enabled  bool              `json:"enabled"`
		ACLs     map[string]string `json:"acls"`
	}

	if err := json.NewDecoder(r.Body).Decode(&userData); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	// 处理密码哈希
	passwordHash := ""
	if userData.Password != "" {
		hash := sha256.Sum256([]byte(userData.Password))
		passwordHash = hex.EncodeToString(hash[:])
	}

	// 更新或创建用户
	if user, exists := ws.users[userData.Username]; exists {
		if passwordHash != "" {
			user.PasswordHash = passwordHash
		}
		user.Enabled = userData.Enabled
		user.ACLs = userData.ACLs
	} else {
		if passwordHash == "" {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   "Password is required for new users",
			})
			return
		}

		ws.users[userData.Username] = User{
			Username:     userData.Username,
			PasswordHash: passwordHash,
			Enabled:      userData.Enabled,
			ACLs:         userData.ACLs,
		}
	}

	// 保存配置
	if err := ws.saveConfig(); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save config: %v", err),
		})
		return
	}

	ws.sendJSONResponse(w, APIResponse{Success: true})
}

// handleStatus 处理状态API
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ws.statsMu.RLock()
	defer ws.statsMu.RUnlock()

	status := map[string]interface{}{
		"server_status": "running",
		"start_time":    ws.startTime.Format(time.RFC3339),
		"uptime":        time.Since(ws.startTime).String(),
		"web_enabled":   ws.enabled,
		"web_port":      ws.port,
	}

	response := APIResponse{
		Success: true,
		Data:    status,
	}

	ws.sendJSONResponse(w, response)
}

// handleStats 处理统计API
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	ws.statsMu.RLock()
	ws.usersMu.RLock()
	defer ws.statsMu.RUnlock()
	defer ws.statsMu.RUnlock()

	stats := Stats{
		StartTime:     ws.startTime,
		Connections:   ws.stats.Connections,
		TotalRequests: ws.stats.TotalRequests,
		ActiveUsers:   len(ws.users),
	}

	response := APIResponse{
		Success: true,
		Data:    stats,
	}

	ws.sendJSONResponse(w, response)
}

// handleConfig 处理配置API
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := map[string]interface{}{
			"web": ws.webConfig,
			// 其他配置项...
		}

		response := APIResponse{
			Success: true,
			Data:    config,
		}

		ws.sendJSONResponse(w, response)

	case http.MethodPost:
		var configData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&configData); err != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   "Invalid JSON data",
			})
			return
		}

		// 处理配置更新
		if webConfig, exists := configData["web"]; exists {
			if webMap, ok := webConfig.(map[string]interface{}); ok {
				if port, exists := webMap["port"]; exists {
					if portFloat, ok := port.(float64); ok {
						ws.webConfig.Port = int(portFloat)
					}
				}
				if enabled, exists := webMap["enabled"]; exists {
					if enabledBool, ok := enabled.(bool); ok {
						ws.webConfig.Enabled = enabledBool
					}
				}
			}
		}

		if err := ws.saveConfig(); err != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to save config: %v", err),
			})
			return
		}

		ws.sendJSONResponse(w, APIResponse{Success: true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProxyNodes 处理代理节点API
func (ws *WebServer) handleProxyNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 返回代理节点列表
		nodes := []interface{}{} // 实际实现中从配置中获取

		response := APIResponse{
			Success: true,
			Data:    nodes,
		}

		ws.sendJSONResponse(w, response)

	case http.MethodPost:
		// 添加新的代理节点
		var nodeData interface{}
		if err := json.NewDecoder(r.Body).Decode(&nodeData); err != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   "Invalid JSON data",
			})
			return
		}

		// 实际实现中添加到配置
		ws.sendJSONResponse(w, APIResponse{Success: true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStatic 处理静态文件服务
func (ws *WebServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// 只处理GET请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 安全地构建文件路径
	requestedPath := strings.TrimPrefix(r.URL.Path, "/")
	filePath := filepath.Join(ws.webRoot, requestedPath)

	// 检查路径安全性
	if !strings.HasPrefix(filePath, ws.webRoot) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 检查文件是否存在
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 返回默认的index.html
			http.ServeFile(w, r, filepath.Join(ws.webRoot, "index.html"))
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// 如果是目录，返回index.html
	if info.IsDir() {
		http.ServeFile(w, r, filepath.Join(filePath, "index.html"))
		return
	}

	// 设置正确的Content-Type
	contentType := ws.getContentType(filePath)
	w.Header().Set("Content-Type", contentType)

	// 提供文件
	http.ServeFile(w, r, filePath)
}

// getContentType 根据文件扩展名获取Content-Type
func (ws *WebServer) getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".html":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// saveConfig 保存配置（简化版）
func (ws *WebServer) saveConfig() error {
	// 这里应该调用配置管理器的保存方法
	// 由于这是简化版本，只返回nil
	return nil
}

// UpdateStats 更新统计信息
func (ws *WebServer) UpdateStats() {
	ws.statsMu.Lock()
	defer ws.statsMu.Unlock()

	// 这里可以更新各种统计信息
	ws.stats.TotalRequests++
}

// IncrementConnections 增加连接数
func (ws *WebServer) IncrementConnections() {
	ws.statsMu.Lock()
	defer ws.statsMu.Unlock()

	ws.stats.Connections++
}

// DecrementConnections 减少连接数
func (ws *WebServer) DecrementConnections() {
	ws.statsMu.Lock()
	defer ws.statsMu.Unlock()

	if ws.stats.Connections > 0 {
		ws.stats.Connections--
	}
}

// AddDefaultUser 添加默认用户
func (ws *WebServer) AddDefaultUser(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	hash := sha256.Sum256([]byte(password))
	passwordHash := hex.EncodeToString(hash[:])

	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	ws.users[username] = User{
		Username:     username,
		PasswordHash: passwordHash,
		Enabled:      true,
		ACLs:         make(map[string]string),
	}

	return nil
}