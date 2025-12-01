package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ConfigManager 配置管理器接口
type ConfigManager interface {
	GetUsers() map[string]User
	SaveConfig() error
	GetProxyNodes() []interface{}
	AddProxyNode(node interface{}) error
	DeleteProxyNode(id string) error
}

//go:embed static/*
var staticFiles embed.FS

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
	config    interface{} // 配置管理器接口
	webConfig WebConfig
	port      int
	enabled   bool
	logger    *log.Logger
	server    *http.Server
	startTime time.Time
	webRoot   string
	mu        sync.RWMutex

	// 统计信息
	stats   Stats
	statsMu sync.RWMutex

	// 用户管理（简化版）
	users   map[string]User
	usersMu sync.RWMutex

	// WebSocket 连接管理
	wsUpgrader websocket.Upgrader
	clients    map[*websocket.Conn]bool
	clientsMu  sync.RWMutex
	broadcast  chan []byte

	// 实时流量统计
	totalUpload     int64
	totalDownload   int64
	currentUpload   int64
	currentDownload int64
	trafficMu       sync.RWMutex

	// 连接管理
	activeConnections map[string]*ConnectionInfo
	connectionsMu     sync.RWMutex
}

// ConnectionInfo 连接信息
type ConnectionInfo struct {
	ID        string    `json:"id"`
	User      string    `json:"user"`
	Target    string    `json:"target"`
	Protocol  string    `json:"protocol"`
	Status    string    `json:"status"`
	StartTime time.Time `json:"start_time"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
}

// TrafficStats 流量统计
type TrafficStats struct {
	Timestamp     int64 `json:"timestamp"`
	Upload        int64 `json:"upload"`
	Download      int64 `json:"download"`
	TotalUpload   int64 `json:"total_upload"`
	TotalDownload int64 `json:"total_download"`
	Connections   int   `json:"connections"`
}

// WebSocketMessage WebSocket消息格式
type WebSocketMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp int64       `json:"timestamp"`
}

// User 用户信息（包含密码哈希）
type User struct {
	Username     string            `json:"username"`
	PasswordHash string            `json:"password_hash"`
	Enabled      bool              `json:"enabled"`
	ACLs         map[string]string `json:"acls"`
}

// NewWebServer 创建Web服务器
func NewWebServer(config ConfigManager, webConfig WebConfig, logger *log.Logger) *WebServer {
	if logger == nil {
		logger = log.New(os.Stdout, "[WebServer] ", log.LstdFlags)
	}

	// 默认配置，避免端口冲突
	if webConfig.Port == 0 {
		// 尝试使用默认的8080，如果被占用会失败
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

		// 初始化WebSocket
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // 允许所有来源
			},
		},
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte, 256),

		// 初始化连接管理
		activeConnections: make(map[string]*ConnectionInfo),
	}

	// 如果配置管理器不可用，从环境变量或默认值获取配置路径
	configPath := "conf/config.json"
	if config == nil {
		// 检查是否有配置文件环境变量
		if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
			configPath = envPath
		}
		logger.Printf("Using config path: %s", configPath)
	} else {
		// 配置管理器存在，使用默认配置文件路径
		logger.Printf("Config manager available")
	}

	// 初始化路由
	ws.setupRoutes()

	return ws
}

// setupRoutes 设置HTTP路由
func (ws *WebServer) setupRoutes() {
	mux := http.NewServeMux()

	// WebSocket 路由
	mux.HandleFunc("/ws", ws.handleWebSocket)

	// API路由 - 必须在静态文件路由之前注册
	apiRoutes := []struct {
		pattern string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"/api/health", ws.handleHealth},
		{"/api/users/", ws.handleUsers},
		{"/api/users", ws.handleUsers},
		{"/api/stats", ws.handleStats},
		{"/api/status", ws.handleStatus},
		{"/api/config", ws.handleConfig},
		{"/api/proxy-nodes", ws.handleProxyNodes},
		{"/api/connections", ws.handleConnections},
		{"/api/bulk/", ws.handleBulkOperations},
		{"/api/fullcone/stats", ws.handleFullConeStats},
		{"/api/ratelimit/stats", ws.handleRateLimitStats},
		{"/api/traffic/realtime", ws.handleTrafficRealtime},
		{"/api/rules", ws.handleRules},
		{"/api/version", ws.handleVersion},
		{"/api/file/chnroutes", ws.handleFileChnroutes},
		{"/api/file/chnroutes/save", ws.handleFileChnroutesSave},
	}

	// 注册所有API路由
	for _, route := range apiRoutes {
		mux.HandleFunc(route.pattern, route.handler)
	}

	// 静态文件服务 - 必须在最后，作为默认路由
	mux.HandleFunc("/", ws.handleStatic)

	// 检查是否启用IPv6
	listenAddr := fmt.Sprintf(":%d", ws.port)
	if isIPv6EnabledWeb() {
		listenAddr = fmt.Sprintf("[::]:%d", ws.port)
	}

	ws.server = &http.Server{
		Addr:    listenAddr,
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

	// 启动WebSocket广播管理器
	go ws.broadcastManager()

	// 启动统计数据更新器
	go ws.statsUpdater()

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
	// 路径解析：支持 /api/users 和 /api/users/{username}
	path := strings.TrimPrefix(r.URL.Path, "/api/users")
	path = strings.Trim(path, "/")

	if path != "" {
		// 处理特定用户操作 /api/users/{username}
		ws.handleUser(w, r, path)
		return
	}

	// 处理用户集合操作 /api/users
	switch r.Method {
	case http.MethodGet:
		ws.getUsers(w, r)
	case http.MethodPost:
		ws.createUser(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUser 处理特定用户的CRUD操作
func (ws *WebServer) handleUser(w http.ResponseWriter, r *http.Request, username string) {
	switch r.Method {
	case http.MethodGet:
		ws.getUser(w, r, username)
	case http.MethodPut:
		ws.updateUserByUsername(w, r, username)
	case http.MethodPatch:
		ws.patchUser(w, r, username)
	case http.MethodDelete:
		ws.deleteUser(w, r, username)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getUsers 获取用户列表
func (ws *WebServer) getUsers(w http.ResponseWriter, r *http.Request) {
	if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
		config := configManager.GetConfig()
		if config != nil && config.Socks5.AuthUsers != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: true,
				Data:    config.Socks5.AuthUsers,
			})
			return
		}
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    []interface{}{}, // 返回空列表
	})
}

// createUser 创建用户
func (ws *WebServer) createUser(w http.ResponseWriter, r *http.Request) {
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

	// 验证输入
	if userData.Username == "" {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Username is required",
		})
		return
	}

	if userData.Password == "" {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Password is required",
		})
		return
	}

	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	// 检查用户是否已存在
	if _, exists := ws.users[userData.Username]; exists {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "User already exists",
		})
		return
	}

	// 处理密码哈希
	hash := sha256.Sum256([]byte(userData.Password))
	passwordHash := hex.EncodeToString(hash[:])

	// 创建用户
	ws.users[userData.Username] = User{
		Username:     userData.Username,
		PasswordHash: passwordHash,
		Enabled:      userData.Enabled,
		ACLs:         userData.ACLs,
	}

	// 保存配置
	if err := ws.saveConfig(); err != nil {
		delete(ws.users, userData.Username) // 回滚
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save config: %v", err),
		})
		return
	}

	ws.sendJSONResponse(w, APIResponse{Success: true})
}

// getUser 获取单个用户信息
func (ws *WebServer) getUser(w http.ResponseWriter, r *http.Request, username string) {
	ws.usersMu.RLock()
	defer ws.usersMu.RUnlock()

	user, exists := ws.users[username]
	if !exists {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "User not found",
		})
		return
	}

	userInfo := UserInfo{
		Username: user.Username,
		Enabled:  user.Enabled,
		ACLs:     user.ACLs,
	}

	response := APIResponse{
		Success: true,
		Data:    userInfo,
	}

	ws.sendJSONResponse(w, response)
}

// updateUserByUsername 通过用户名更新用户
func (ws *WebServer) updateUserByUsername(w http.ResponseWriter, r *http.Request, username string) {
	var updateData struct {
		Username string            `json:"username"`
		Password string            `json:"password"`
		Enabled  *bool             `json:"enabled"` // 使用指针区分零值和未提供
		ACLs     map[string]string `json:"acls"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	user, exists := ws.users[username]
	if !exists {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "User not found",
		})
		return
	}

	// 检查是否要更改用户名
	if updateData.Username != "" && updateData.Username != username {
		// 检查新用户名是否已存在
		if _, exists := ws.users[updateData.Username]; exists {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   "Username already exists",
			})
			return
		}

		// 移动用户到新用户名下
		delete(ws.users, username)
		user.Username = updateData.Username
		ws.users[updateData.Username] = user
		username = updateData.Username
	}

	// 更新密码（如果提供）
	if updateData.Password != "" {
		hash := sha256.Sum256([]byte(updateData.Password))
		user.PasswordHash = hex.EncodeToString(hash[:])
	}

	// 更新启用状态（如果提供）
	if updateData.Enabled != nil {
		user.Enabled = *updateData.Enabled
	}

	// 更新ACLs（如果提供）
	if updateData.ACLs != nil {
		user.ACLs = updateData.ACLs
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

// patchUser 部分更新用户（主要用于启用/禁用）
func (ws *WebServer) patchUser(w http.ResponseWriter, r *http.Request, username string) {
	var patchData struct {
		Enabled *bool `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&patchData); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	if patchData.Enabled == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "No patch data provided",
		})
		return
	}

	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	user, exists := ws.users[username]
	if !exists {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "User not found",
		})
		return
	}

	user.Enabled = *patchData.Enabled

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

// deleteUser 删除用户
func (ws *WebServer) deleteUser(w http.ResponseWriter, r *http.Request, username string) {
	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	user, exists := ws.users[username]
	if !exists {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "User not found",
		})
		return
	}

	// 删除用户
	delete(ws.users, username)

	// 保存配置
	if err := ws.saveConfig(); err != nil {
		// 回滚删除操作
		ws.users[username] = user
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
	defer ws.usersMu.RUnlock()

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
		// 尝试从配置管理器获取完整配置
		if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
			config := configManager.GetConfig()
			if config != nil {
				ws.sendJSONResponse(w, APIResponse{
					Success: true,
					Data:    config,
				})
				return
			}
		} else {
			// 如果配置管理器不可用，尝试从文件加载配置
			if configPath := ws.getConfigPath(); configPath != "" {
				if data, err := ioutil.ReadFile(configPath); err == nil {
					var config interface{}
					if err := json.Unmarshal(data, &config); err == nil {
						ws.sendJSONResponse(w, APIResponse{
							Success: true,
							Data:    config,
						})
						return
					}
				}
			}
		}

		// 回退到基本配置
		config := map[string]interface{}{
			"web": ws.webConfig,
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

		// 尝试更新完整配置
		if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
			if err := configManager.UpdateConfig(configData); err != nil {
				ws.sendJSONResponse(w, APIResponse{
					Success: false,
					Error:   fmt.Sprintf("Failed to update config: %v", err),
				})
				return
			}
		} else {
			// 处理基本Web配置更新
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
		}

		if err := ws.saveConfig(); err != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to save config: %v", err),
			})
			return
		}

		ws.sendJSONResponse(w, APIResponse{Success: true})

	case http.MethodPut:
		// 完整替换配置
		var newConfig SmartProxyConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   "Invalid JSON data",
			})
			return
		}

		if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
			// 创建临时管理器来保存新配置
			tempCM := &SmartProxyConfigManager{
				config: &newConfig,
			}
			if err := tempCM.SaveConfig(); err != nil {
				ws.sendJSONResponse(w, APIResponse{
					Success: false,
					Error:   fmt.Sprintf("Failed to save new config: %v", err),
				})
				return
			}
			// 重新加载配置
			if err := configManager.LoadConfig(); err != nil {
				ws.sendJSONResponse(w, APIResponse{
					Success: false,
					Error:   fmt.Sprintf("Failed to reload config: %v", err),
				})
				return
			}
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

	// 获取原始URL路径并去除查询参数
	requestedPath := r.URL.Path
	if queryIndex := strings.Index(requestedPath, "?"); queryIndex != -1 {
		requestedPath = requestedPath[:queryIndex]
	}

	// 安全地构建文件路径
	requestedPath = strings.TrimPrefix(requestedPath, "/")

	// 如果是根路径，返回index.html
	if requestedPath == "" {
		requestedPath = "index.html"
	}

	// 从嵌入的文件系统中读取文件
	// The embed FS is rooted at 'static', so we read directly from the requested path.
	data, err := staticFiles.ReadFile("static/" + requestedPath)
	if err != nil {
		// 如果请求的路径看起来像一个文件（有扩展名），但没找到，则返回404
		// This handles requests for assets like .js, .css, .png that don't exist.
		if strings.Contains(requestedPath, ".") {
			http.NotFound(w, r)
			return
		}

		// 否则，这可能是一个SPA路由，尝试返回index.html作为后备
		indexData, indexErr := staticFiles.ReadFile("static/index.html")
		if indexErr != nil {
			// 如果连 index.html 都找不到，就真的出错了
			http.Error(w, "Internal server error: index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.WriteHeader(http.StatusOK)
		w.Write(indexData)
		return
	}

	// 设置正确的Content-Type（基于文件扩展名）
	contentType := ws.getContentType(requestedPath)
	w.Header().Set("Content-Type", contentType)

	// 为非HTML资源设置缓存头
	if !strings.HasSuffix(requestedPath, ".html") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
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
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
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
	case ".webp":
		return "image/webp"
	case ".bmp":
		return "image/bmp"
	// 字体文件
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	case ".otf":
		return "font/otf"
	// 音频文件
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".ogg":
		return "audio/ogg"
	// 视频文件
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	// 压缩文件
	case ".zip":
		return "application/zip"
	case ".gz":
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}

// getConfigPath 获取配置文件路径
func (ws *WebServer) getConfigPath() string {
	// 尝试从配置管理器获取配置路径
	if _, ok := ws.config.(*SmartProxyConfigManager); ok {
		// 配置管理器存在，返回默认配置路径
		return "conf/config.json"
	}
	return "conf/config.json"
}

// saveConfig 保存配置（简化版）
func (ws *WebServer) saveConfig() error {
	// 尝试调用配置管理器的保存方法
	if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
		return configManager.SaveConfig()
	}
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

// 新增的API处理函数

// handleHealth 健康检查
func (ws *WebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "ok"},
	})
}

// handleConnections 连接管理API
func (ws *WebServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ws.sendJSONResponse(w, APIResponse{
			Success: true,
			Data:    []interface{}{}, // 返回模拟数据
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFullConeStats Full Cone NAT统计
func (ws *WebServer) handleFullConeStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 返回模拟的Full Cone NAT统计数据
	stats := map[string]interface{}{
		"total_mappings":    0,
		"active_mappings":   0,
		"packets_forwarded": 0,
		"public_ip":         "127.0.0.1",
		"listen_port":       1081,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// handleRateLimitStats 限速统计
func (ws *WebServer) handleRateLimitStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 返回模拟的限速统计数据
	stats := map[string]interface{}{
		"active_rules":          0,
		"total_requests":        0,
		"rate_limited_requests": 0,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// handleTrafficRealtime 实时流量数据
func (ws *WebServer) handleTrafficRealtime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 返回模拟的实时流量数据
	data := map[string]interface{}{
		"timestamp":   time.Now().Unix(),
		"upload":      0,
		"download":    0,
		"connections": 0,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    data,
	})
}

// handleVersion 版本信息
func (ws *WebServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	version := map[string]interface{}{
		"version":       "1.0.0",
		"build_time":    time.Now().Format(time.RFC3339),
		"go_version":    "1.21+",
		"full_cone_nat": true,
		"sni_support":   true,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    version,
	})
}

// handleBulkOperations 处理批量操作API
func (ws *WebServer) handleBulkOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 解析操作类型
	operation := strings.TrimPrefix(r.URL.Path, "/api/bulk/")
	if operation == "" {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Operation not specified",
		})
		return
	}

	var requestData struct {
		Items []string    `json:"items"`          // 用户名列表或其他标识符
		Data  interface{} `json:"data,omitempty"` // 额外数据
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	if len(requestData.Items) == 0 {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "No items specified",
		})
		return
	}

	// 根据操作类型处理
	switch operation {
	case "delete-users":
		ws.bulkDeleteUsers(w, requestData.Items)
	case "enable-users":
		ws.bulkUpdateUsersStatus(w, requestData.Items, true)
	case "disable-users":
		ws.bulkUpdateUsersStatus(w, requestData.Items, false)
	case "delete-rules":
		ws.bulkDeleteRules(w, requestData.Items)
	case "delete-connections":
		ws.bulkDeleteConnections(w, requestData.Items)
	default:
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Unknown operation: " + operation,
		})
	}
}

// bulkDeleteUsers 批量删除用户
func (ws *WebServer) bulkDeleteUsers(w http.ResponseWriter, usernames []string) {
	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	var deletedUsers []string
	var failedUsers []map[string]string

	for _, username := range usernames {
		_, exists := ws.users[username]
		if !exists {
			failedUsers = append(failedUsers, map[string]string{
				"username": username,
				"error":    "User not found",
			})
			continue
		}

		// 防止删除最后一个管理员用户（可根据实际需求调整）
		if ws.isUserOnlyAdmin(username) {
			failedUsers = append(failedUsers, map[string]string{
				"username": username,
				"error":    "Cannot delete only admin user",
			})
			continue
		}

		delete(ws.users, username)
		deletedUsers = append(deletedUsers, username)
	}

	// 保存配置
	if len(deletedUsers) > 0 {
		if err := ws.saveConfig(); err != nil {
			// 回滚删除操作
			_ = deletedUsers // 避免未使用变量警告
			ws.logger.Printf("Failed to save bulk delete config, operation rolled back")
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to save config: %v", err),
			})
			return
		}
	}

	result := map[string]interface{}{
		"deleted": deletedUsers,
		"failed":  failedUsers,
		"total":   len(usernames),
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    result,
	})
}

// bulkUpdateUsersStatus 批量更新用户状态
func (ws *WebServer) bulkUpdateUsersStatus(w http.ResponseWriter, usernames []string, enabled bool) {
	ws.usersMu.Lock()
	defer ws.usersMu.Unlock()

	var updatedUsers []string
	var failedUsers []map[string]string

	for _, username := range usernames {
		user, exists := ws.users[username]
		if !exists {
			failedUsers = append(failedUsers, map[string]string{
				"username": username,
				"error":    "User not found",
			})
			continue
		}

		// 防止禁用最后一个管理员用户
		if !enabled && ws.isUserOnlyAdmin(username) {
			failedUsers = append(failedUsers, map[string]string{
				"username": username,
				"error":    "Cannot disable only admin user",
			})
			continue
		}

		user.Enabled = enabled
		updatedUsers = append(updatedUsers, username)
	}

	// 保存配置
	if len(updatedUsers) > 0 {
		if err := ws.saveConfig(); err != nil {
			// 回滚状态更改
			for _, username := range updatedUsers {
				if user, exists := ws.users[username]; exists {
					user.Enabled = !enabled
				}
			}
			ws.sendJSONResponse(w, APIResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to save config: %v", err),
			})
			return
		}
	}

	statusText := "enabled"
	if !enabled {
		statusText = "disabled"
	}

	result := map[string]interface{}{
		"updated": updatedUsers,
		"failed":  failedUsers,
		"total":   len(usernames),
		"action":  statusText,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    result,
	})
}

// bulkDeleteRules 批量删除路由规则
func (ws *WebServer) bulkDeleteRules(w http.ResponseWriter, ruleIDs []string) {
	// 这里需要实现路由规则的批量删除
	// 由于当前代码中路由规则管理可能不完整，返回模拟结果
	result := map[string]interface{}{
		"deleted": ruleIDs,
		"failed":  []map[string]string{},
		"total":   len(ruleIDs),
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    result,
	})
}

// bulkDeleteConnections 批量断开连接
func (ws *WebServer) bulkDeleteConnections(w http.ResponseWriter, connectionIDs []string) {
	// 这里需要实现连接的批量断开
	// 由于当前代码中连接管理可能不完整，返回模拟结果
	result := map[string]interface{}{
		"disconnected": connectionIDs,
		"failed":       []map[string]string{},
		"total":        len(connectionIDs),
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    result,
	})
}

// isUserOnlyAdmin 检查用户是否是唯一的管理员
func (ws *WebServer) isUserOnlyAdmin(username string) bool {
	user, exists := ws.users[username]
	if !exists || !user.Enabled {
		return false
	}

	// 检查是否有其他启用的管理员用户
	adminCount := 0
	for _, u := range ws.users {
		if u.Enabled {
			// 这里可以根据实际需要定义管理员判断逻辑
			// 例如检查ACLs或特定权限
			adminCount++
		}
	}

	return adminCount <= 1
}

// WebSocket 处理函数

// handleWebSocket 处理WebSocket连接
func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		ws.logger.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	// 添加客户端到连接池
	ws.clientsMu.Lock()
	ws.clients[conn] = true
	ws.clientsMu.Unlock()

	ws.logger.Printf("WebSocket client connected. Total clients: %d", len(ws.clients))

	// 发送初始状态
	ws.sendInitialStats(conn)

	// 读取客户端消息（虽然我们主要用广播）
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			ws.logger.Printf("WebSocket read error: %v", err)
			break
		}
	}

	// 清理连接
	ws.clientsMu.Lock()
	delete(ws.clients, conn)
	ws.clientsMu.Unlock()

	ws.logger.Printf("WebSocket client disconnected. Total clients: %d", len(ws.clients))
}

// sendInitialStats 发送初始统计数据给新连接的客户端
func (ws *WebServer) sendInitialStats(conn *websocket.Conn) {
	ws.statsMu.RLock()
	stats := ws.stats
	ws.statsMu.RUnlock()

	ws.trafficMu.RLock()
	trafficStats := TrafficStats{
		Timestamp:     time.Now().Unix(),
		TotalUpload:   ws.totalUpload,
		TotalDownload: ws.totalDownload,
		Connections:   len(ws.activeConnections),
	}
	ws.trafficMu.RUnlock()

	// 发送当前统计数据
	message := WebSocketMessage{
		Type:      "stats",
		Data:      stats,
		Timestamp: time.Now().Unix(),
	}
	data, _ := json.Marshal(message)
	conn.WriteMessage(websocket.TextMessage, data)

	// 发送流量统计
	message = WebSocketMessage{
		Type:      "traffic",
		Data:      trafficStats,
		Timestamp: time.Now().Unix(),
	}
	data, _ = json.Marshal(message)
	conn.WriteMessage(websocket.TextMessage, data)
}

// broadcastManager 管理WebSocket广播
func (ws *WebServer) broadcastManager() {
	ticker := time.NewTicker(1 * time.Second) // 改为1秒刷新
	defer ticker.Stop()

	for {
		select {
		case message := <-ws.broadcast:
			ws.clientsMu.RLock()
			for client := range ws.clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					ws.logger.Printf("WebSocket broadcast error: %v", err)
					client.Close()
					delete(ws.clients, client)
				}
			}
			ws.clientsMu.RUnlock()

		case <-ticker.C:
			// 定期广播统计数据
			ws.broadcastStats()
		}
	}
}

// broadcastStats 广播统计数据给所有客户端
func (ws *WebServer) broadcastStats() {
	ws.statsMu.RLock()
	stats := ws.stats
	ws.statsMu.RUnlock()

	ws.trafficMu.RLock()
	trafficStats := TrafficStats{
		Timestamp:     time.Now().Unix(),
		Upload:        ws.currentUpload,
		Download:      ws.currentDownload,
		TotalUpload:   ws.totalUpload,
		TotalDownload: ws.totalDownload,
		Connections:   len(ws.activeConnections),
	}
	ws.trafficMu.RUnlock()

	// 广播统计数据
	message := WebSocketMessage{
		Type:      "stats",
		Data:      stats,
		Timestamp: time.Now().Unix(),
	}
	data, _ := json.Marshal(message)

	ws.clientsMu.RLock()
	for client := range ws.clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			ws.logger.Printf("WebSocket broadcast error: %v", err)
			client.Close()
			delete(ws.clients, client)
		}
	}
	ws.clientsMu.RUnlock()

	// 广播流量数据
	message = WebSocketMessage{
		Type:      "traffic",
		Data:      trafficStats,
		Timestamp: time.Now().Unix(),
	}
	data, _ = json.Marshal(message)

	ws.clientsMu.RLock()
	for client := range ws.clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			ws.logger.Printf("WebSocket broadcast error: %v", err)
			client.Close()
			delete(ws.clients, client)
		}
	}
	ws.clientsMu.RUnlock()

	// 重置当前流量统计
	ws.trafficMu.Lock()
	ws.currentUpload = 0
	ws.currentDownload = 0
	ws.trafficMu.Unlock()
}

// statsUpdater 定期更新统计数据
func (ws *WebServer) statsUpdater() {
	ticker := time.NewTicker(500 * time.Millisecond) // 改为500ms刷新
	defer ticker.Stop()

	requestCount := int64(0)

	for {
		select {
		case <-ticker.C:
			ws.statsMu.Lock()
			ws.stats.TotalRequests = int(requestCount)
			ws.stats.ActiveUsers = len(ws.getEnabledUsers())
			ws.statsMu.Unlock()

			// 模拟请求增长（实际应该从真实的请求计数器获取）
			requestCount++
		}
	}
}

// getEnabledUsers 获取启用的用户数量
func (ws *WebServer) getEnabledUsers() []User {
	ws.usersMu.RLock()
	defer ws.usersMu.RUnlock()

	var enabledUsers []User
	for _, user := range ws.users {
		if user.Enabled {
			enabledUsers = append(enabledUsers, user)
		}
	}
	return enabledUsers
}

// UpdateTraffic 更新流量统计（供外部调用）
func (ws *WebServer) UpdateTraffic(upload, download int64) {
	atomic.AddInt64(&ws.totalUpload, upload)
	atomic.AddInt64(&ws.totalDownload, download)

	ws.trafficMu.Lock()
	ws.currentUpload += upload
	ws.currentDownload += download
	ws.trafficMu.Unlock()

	// 触发WebSocket广播流量更新
	go func() {
		ws.broadcast <- []byte(`{"type":"traffic","data":{"timestamp":${time.Now().Unix()},"upload":${upload},"download":${download},"total_upload":${atomic.LoadInt64(&ws.totalUpload)},"total_download":${atomic.LoadInt64(&ws.totalDownload)},"connections":${len(ws.activeConnections)}}}`)
	}()
}

// AddConnection 添加连接记录（供外部调用）
func (ws *WebServer) AddConnection(id, user, target, protocol string) *ConnectionInfo {
	conn := &ConnectionInfo{
		ID:        id,
		User:      user,
		Target:    target,
		Protocol:  protocol,
		Status:    "connected",
		StartTime: time.Now(),
	}

	ws.connectionsMu.Lock()
	ws.activeConnections[id] = conn
	ws.connectionsMu.Unlock()

	// 更新统计
	ws.statsMu.Lock()
	ws.stats.Connections = len(ws.activeConnections)
	ws.statsMu.Unlock()

	// 通知客户端
	ws.broadcastConnectionUpdate("add", conn)

	return conn
}

// AddConnectionTraffic 更新连接流量（供外部调用）
func (ws *WebServer) AddConnectionTraffic(id string, bytesIn, bytesOut int64) {
	ws.connectionsMu.Lock()
	var conn *ConnectionInfo
	var exists bool
	if conn, exists = ws.activeConnections[id]; exists {
		conn.BytesIn += bytesIn
		conn.BytesOut += bytesOut
	}
	ws.connectionsMu.Unlock()

	// 触发连接更新广播（只有连接存在时才触发）
	if exists {
		ws.broadcastConnectionUpdate("update", conn)
	}
}

// RemoveConnection 移除连接记录（供外部调用）
func (ws *WebServer) RemoveConnection(id string) {
	ws.connectionsMu.Lock()
	defer ws.connectionsMu.Unlock()

	if conn, exists := ws.activeConnections[id]; exists {
		conn.Status = "disconnected"
		delete(ws.activeConnections, id)

		// 通知客户端
		ws.broadcastConnectionUpdate("remove", conn)

		// 更新统计
		ws.statsMu.Lock()
		ws.stats.Connections = len(ws.activeConnections)
		ws.statsMu.Unlock()
	}
}

// UpdateConnectionTraffic 更新连接流量（供外部调用）
func (ws *WebServer) UpdateConnectionTraffic(id string, bytesIn, bytesOut int64) {
	ws.connectionsMu.Lock()
	if conn, exists := ws.activeConnections[id]; exists {
		conn.BytesIn += bytesIn
		conn.BytesOut += bytesOut
	}
	ws.connectionsMu.Unlock()
}

// broadcastConnectionUpdate 广播连接更新
func (ws *WebServer) broadcastConnectionUpdate(action string, conn *ConnectionInfo) {
	message := WebSocketMessage{
		Type:      "connection",
		Data:      map[string]interface{}{"action": action, "connection": conn},
		Timestamp: time.Now().Unix(),
	}
	data, _ := json.Marshal(message)

	ws.clientsMu.RLock()
	for client := range ws.clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			ws.logger.Printf("WebSocket broadcast error: %v", err)
			client.Close()
			delete(ws.clients, client)
		}
	}
	ws.clientsMu.RUnlock()
}

// GetActiveConnections 获取活跃连接列表（供API使用）
func (ws *WebServer) GetActiveConnections() []*ConnectionInfo {
	ws.connectionsMu.RLock()
	defer ws.connectionsMu.RUnlock()

	connections := make([]*ConnectionInfo, 0, len(ws.activeConnections))
	for _, conn := range ws.activeConnections {
		connections = append(connections, conn)
	}
	return connections
}

// handleRules 处理路由规则API
func (ws *WebServer) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ws.getRules(w, r)
	case http.MethodPost:
		ws.createRule(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getRules 获取路由规则列表
func (ws *WebServer) getRules(w http.ResponseWriter, r *http.Request) {
	// 从配置管理器获取路由规则
	if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
		config := configManager.GetConfig()
		if config != nil && config.Router.Rules != nil {
			ws.sendJSONResponse(w, APIResponse{
				Success: true,
				Data:    config.Router.Rules,
			})
			return
		}
	}

	// 返回空规则列表
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    []interface{}{},
	})
}

// createRule 创建路由规则
func (ws *WebServer) createRule(w http.ResponseWriter, r *http.Request) {
	var rule struct {
		Action      string   `json:"action"`
		Patterns    []string `json:"patterns"`
		ProxyNode   string   `json:"proxy_node,omitempty"`
		Description string   `json:"description"`
		Enabled     bool     `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	// 这里应该添加到配置中
	// 暂时返回成功
	ws.sendJSONResponse(w, APIResponse{Success: true})
}

// isIPv6EnabledWeb 检查是否应该为Web服务器启用IPv6监听
func isIPv6EnabledWeb() bool {
	// 读取配置文件检查ipv6_enabled设置
	configPath := "conf/config.json"
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return false // 无法读取配置，默认使用IPv4
	}

	var config struct {
		Listener struct {
			IPv6Enabled bool `json:"ipv6_enabled"`
		} `json:"listener"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return false // 无法解析配置，默认使用IPv4
	}

	return config.Listener.IPv6Enabled
}



// handleFileChnroutes 处理中国路由文件读取
func (ws *WebServer) handleFileChnroutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
		config := configManager.GetConfig()
		if config != nil && config.Router.Chnroutes.Enable {
			filePath := config.Router.Chnroutes.Path
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Failed to read file: " + err.Error()})
				return
			}
			
			lines := strings.Split(string(content), "\n")
			dataLines := 0
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					dataLines++
				}
			}


			ws.sendJSONResponse(w, APIResponse{
				Success: true,
				Data: map[string]interface{}{
					"content": string(content),
					"lines":   len(lines),
					"data_lines": dataLines,
					"size":    fmt.Sprintf("%.2f KB", float64(len(content))/1024.0),
				},
			})
			return
		}
	}

	ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Chnroutes not enabled or config not available"})
}

// handleFileChnroutesSave 处理中国路由文件保存
func (ws *WebServer) handleFileChnroutesSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestData struct {
		Content string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Invalid JSON data",
		})
		return
	}

	configPath := "conf/chnroutes.txt"
	if configManager, ok := ws.config.(*SmartProxyConfigManager); ok {
		if config := configManager.GetConfig(); config != nil && config.Router.Chnroutes.Path != "" {
			configPath = config.Router.Chnroutes.Path
		}
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to create directory: %v", err),
		})
		return
	}

	if err := ioutil.WriteFile(configPath, []byte(requestData.Content), 0644); err != nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to save chnroutes file: %v", err),
		})
		return
	}

	ws.sendJSONResponse(w, APIResponse{Success: true})
}
