package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"smartproxy/config"
	"smartproxy/logger"
	"smartproxy/socks5"

	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFiles embed.FS

// WebConfig defines the configuration for the web server.
type WebConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// APIResponse is the standard format for all API responses.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Stats holds statistical information for the web dashboard.
type Stats struct {
	StartTime     time.Time `json:"start_time"`
	Connections   int       `json:"connections"`
	TotalRequests int64     `json:"total_requests"`
	ActiveUsers   int       `json:"active_users"`
	ProxyNodes    int       `json:"proxy_nodes"`
}

// WebServer manages the web management interface.
type WebServer struct {
	config    *config.Manager
	webConfig WebConfig
	port      int
	enabled   bool
	logger    *logger.SlogLogger
	server    *http.Server
	startTime time.Time

	stats   Stats
	statsMu sync.RWMutex

	wsUpgrader websocket.Upgrader
	clients    map[*websocket.Conn]bool
	clientsMu  sync.RWMutex

	activeConnections map[string]*ConnectionInfo
	connectionsMu     sync.RWMutex
}

// ConnectionInfo holds information about an active connection.
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

// NewWebServer creates a new WebServer instance.
func NewWebServer(cfg *config.Manager, webCfg WebConfig, log *logger.SlogLogger) *WebServer {
	if log == nil {
		log = logger.NewLogger().WithField("prefix", "[WebServer]")
	}
	if webCfg.Port == 0 {
		webCfg.Port = 8080
	}

	ws := &WebServer{
		config:    cfg,
		webConfig: webCfg,
		port:      webCfg.Port,
		enabled:   webCfg.Enabled,
		logger:    log,
		startTime: time.Now(),
		stats:     Stats{StartTime: time.Now()},
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		clients:           make(map[*websocket.Conn]bool),
		activeConnections: make(map[string]*ConnectionInfo),
	}

	ws.setupRoutes()
	return ws
}

// loggingMiddleware logs all API requests
func (ws *WebServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}

		// Log the request
		clientIP := r.RemoteAddr
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			clientIP = realIP
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP = strings.Split(xff, ",")[0]
		}

		// Process the request
		next.ServeHTTP(rw, r)

		// Log response
		duration := time.Since(start)
		ws.logger.Info("API %s %s - %d - %v - %s",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration,
			clientIP)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// setupRoutes configures the HTTP routes for the web server.
func (ws *WebServer) setupRoutes() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", ws.handleWebSocket)
	mux.HandleFunc("/api/health", ws.handleHealth)
	mux.HandleFunc("/api/status", ws.handleStatus)
	mux.HandleFunc("/api/stats", ws.handleStats)
	mux.HandleFunc("/api/blacklist", ws.handleBlacklistStats)
	mux.HandleFunc("/api/config", ws.handleConfig)
	mux.HandleFunc("/api/users", ws.handleUsers)
	mux.HandleFunc("/api/rules", ws.handleRules)
	mux.HandleFunc("/api/proxy-nodes", ws.handleProxyNodes)
	mux.HandleFunc("/api/file/chnroutes", ws.handleFileChnroutes)
	mux.HandleFunc("/api/file/chnroutes/save", ws.handleFileChnroutesSave)

	// 内存监控API
	mux.HandleFunc("/api/memory/stats", ws.handleMemoryStats)
	mux.HandleFunc("/api/memory/usage", ws.handleMemoryUsage)
	mux.HandleFunc("/api/memory/efficiency", ws.handleMemoryEfficiency)
	mux.HandleFunc("/api/memory/history", ws.handleMemoryHistory)
	mux.HandleFunc("/api/memory/pools", ws.handleMemoryPools)

	// 流量统计API
	mux.HandleFunc("/api/traffic/stats", ws.handleTrafficStats)

	mux.HandleFunc("/", ws.handleStatic)

	listenAddr := fmt.Sprintf(":%d", ws.port)
	if ws.config != nil && ws.config.GetConfig().Listener.IPv6Enabled {
		listenAddr = fmt.Sprintf("[::]:%d", ws.port)
	}
	ws.server = &http.Server{
		Addr:    listenAddr,
		Handler: ws.corsMiddleware(ws.loggingMiddleware(mux)),
	}
}

// Start begins listening for web requests.
func (ws *WebServer) Start() error {
	if !ws.enabled {
		ws.logger.Info("Web interface disabled")
		return nil
	}
	ws.logger.Info("Starting web server on http://localhost:%d", ws.port)
	go func() {
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			ws.logger.Info("Web server error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the web server.
func (ws *WebServer) Stop() error {
	if ws.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ws.server.Shutdown(ctx)
}

// corsMiddleware adds CORS headers to responses.
func (ws *WebServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sendJSONResponse is a helper to send JSON-formatted API responses.
func (ws *WebServer) sendJSONResponse(w http.ResponseWriter, response APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	if !response.Success {
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(response)
}

// handleHealth provides a simple health check endpoint.
func (ws *WebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: map[string]string{"status": "ok"}})
}

// handleStatus provides basic server status.
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"server_status": "running",
		"start_time":    ws.startTime.Format(time.RFC3339),
		"uptime":        time.Since(ws.startTime).String(),
	}
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: status})
}

// handleBlacklistStats provides blacklist statistics and performance metrics.
func (ws *WebServer) handleBlacklistStats(w http.ResponseWriter, r *http.Request) {
	ws.sendJSONResponse(w, APIResponse{
		Success: false,
		Error:   "Blacklist manager (old version) not available. Please use Blocked Items API.",
	})
}

// handleStats provides server statistics.
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	ws.statsMu.RLock()
	defer ws.statsMu.RUnlock()

	cfg := ws.config.GetConfig()
	enabledUsers := 0
	for _, user := range cfg.SOCKS5.AuthUsers {
		if user.Enabled {
			enabledUsers++
		}
	}

	stats := Stats{
		StartTime:     ws.startTime,
		Connections:   len(ws.activeConnections),
		TotalRequests: atomic.LoadInt64(&ws.stats.TotalRequests),
		ActiveUsers:   enabledUsers,
		ProxyNodes:    len(cfg.Router.ProxyNodes),
	}
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: stats})
}

// handleConfig handles getting and setting the main application config.
func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if ws.config == nil {
			ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
			return
		}
		cfg := ws.config.GetConfig()
		ws.sendJSONResponse(w, APIResponse{Success: true, Data: cfg})
	case http.MethodPost:
		if ws.config == nil {
			ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
			return
		}
		var newConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Invalid JSON data: " + err.Error()})
			return
		}

		// 获取当前配置并进行合并，避免数据丢失
		currentConfig := ws.config.GetConfig()
		mergedConfig := ws.mergeConfigs(currentConfig, &newConfig)

		if err := ws.config.UpdateFullConfig(mergedConfig); err != nil {
			ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Failed to update config: " + err.Error()})
			return
		}
		ws.sendJSONResponse(w, APIResponse{Success: true})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// mergeConfigs merges a new config into the current config, preserving existing data
func (ws *WebServer) mergeConfigs(current, new *config.Config) *config.Config {
	merged := *current // 复制当前配置作为基础

	// 只覆盖新配置中非零值的字段
	if new.Listener.SOCKS5Port != 0 {
		merged.Listener.SOCKS5Port = new.Listener.SOCKS5Port
	}
	if new.Listener.WebPort != 0 {
		merged.Listener.WebPort = new.Listener.WebPort
	}
	if new.Listener.DNSPort != 0 {
		merged.Listener.DNSPort = new.Listener.DNSPort
	}
	// IPv6Enabled是布尔值，直接覆盖
	merged.Listener.IPv6Enabled = new.Listener.IPv6Enabled

	// SOCKS5配置
	// EnableAuth是布尔值，直接覆盖
	merged.SOCKS5.EnableAuth = new.SOCKS5.EnableAuth
	// 如果新的AuthUsers不为空，则覆盖
	if new.SOCKS5.AuthUsers != nil {
		merged.SOCKS5.AuthUsers = new.SOCKS5.AuthUsers
	}

	// Router配置
	if new.Router.Chnroutes.Enable != merged.Router.Chnroutes.Enable {
		merged.Router.Chnroutes.Enable = new.Router.Chnroutes.Enable
	}
	if new.Router.Chnroutes.Path != "" {
		merged.Router.Chnroutes.Path = new.Router.Chnroutes.Path
	}
	if new.Router.Rules != nil {
		merged.Router.Rules = new.Router.Rules
	}
	if new.Router.ProxyNodes != nil {
		merged.Router.ProxyNodes = new.Router.ProxyNodes
	}

	// SmartProxy配置
	// enabled is a boolean, so we check if it has changed from the current state
	if new.SmartProxy.Enabled != merged.SmartProxy.Enabled {
		merged.SmartProxy.Enabled = new.SmartProxy.Enabled
	}
	if new.SmartProxy.TimeoutMs > 0 {
		merged.SmartProxy.TimeoutMs = new.SmartProxy.TimeoutMs
	}
	if new.SmartProxy.BlacklistExpiryMinutes > 0 {
		merged.SmartProxy.BlacklistExpiryMinutes = new.SmartProxy.BlacklistExpiryMinutes
	}
	if new.SmartProxy.ProbingPorts != nil {
		merged.SmartProxy.ProbingPorts = new.SmartProxy.ProbingPorts
	}

	// DNS配置
	// Enabled是布尔值，直接覆盖
	merged.DNS.Enabled = new.DNS.Enabled
	if new.DNS.Cache.MaxSize != 0 {
		merged.DNS.Cache.MaxSize = new.DNS.Cache.MaxSize
	}
	if new.DNS.Cache.DefaultTTL != 0 {
		merged.DNS.Cache.DefaultTTL = new.DNS.Cache.DefaultTTL
	}
	if new.DNS.Cache.CleanupInterval != 0 {
		merged.DNS.Cache.CleanupInterval = new.DNS.Cache.CleanupInterval
	}
	if new.DNS.Groups != nil {
		merged.DNS.Groups = new.DNS.Groups
	}
	if new.DNS.HijackRules != nil {
		merged.DNS.HijackRules = new.DNS.HijackRules
	}
	// Logging配置
	if new.Logging.Level != "" {
		merged.Logging.Level = new.Logging.Level
	}
	if new.Logging.OutputFile != "" {
		merged.Logging.OutputFile = new.Logging.OutputFile
	}
	// 其他布尔值直接覆盖
	merged.Logging.EnableTime = new.Logging.EnableTime
	merged.Logging.EnableColors = new.Logging.EnableColors
	merged.Logging.Prefix = new.Logging.Prefix

	return &merged
}

// handleUsers serves the list of authenticated users.
func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ws.config == nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
		return
	}
	users := ws.config.GetAuthUsers()
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: users})
}

// handleRules serves the list of router rules.
func (ws *WebServer) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ws.config == nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
		return
	}
	rules := ws.config.GetRouterRules()
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: rules})
}

// handleProxyNodes serves the list of proxy nodes.
func (ws *WebServer) handleProxyNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ws.config == nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
		return
	}
	nodes := ws.config.GetProxyNodes()
	ws.sendJSONResponse(w, APIResponse{Success: true, Data: nodes})
}

// handleFileChnroutes handles reading the chnroutes file.
func (ws *WebServer) handleFileChnroutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ws.config == nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Config manager not initialized"})
		return
	}
	cfg := ws.config.GetConfig()
	if !cfg.Router.Chnroutes.Enable {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Chnroutes not enabled"})
		return
	}
	content, err := ioutil.ReadFile(cfg.Router.Chnroutes.Path)
	if err != nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Failed to read file: " + err.Error()})
		return
	}
	lines := strings.Split(string(content), "\n")
	dataLines := 0
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			dataLines++
		}
	}
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"content": string(content), "lines": len(lines), "size": fmt.Sprintf("%.2f KB", float64(len(content))/1024.0)},
	})
}

// handleFileChnroutesSave handles writing to the chnroutes file.
func (ws *WebServer) handleFileChnroutesSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var requestData struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Invalid JSON data"})
		return
	}
	configPath := "conf/chnroutes.txt"
	if ws.config != nil {
		if cfg := ws.config.GetConfig(); cfg != nil && cfg.Router.Chnroutes.Path != "" {
			configPath = cfg.Router.Chnroutes.Path
		}
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Failed to create directory: " + err.Error()})
		return
	}
	if err := ioutil.WriteFile(configPath, []byte(requestData.Content), 0644); err != nil {
		ws.sendJSONResponse(w, APIResponse{Success: false, Error: "Failed to save chnroutes file: " + err.Error()})
		return
	}
	ws.sendJSONResponse(w, APIResponse{Success: true})
}

// handleStatic serves static files.
func (ws *WebServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestedPath := r.URL.Path
	if queryIndex := strings.Index(requestedPath, "?"); queryIndex != -1 {
		requestedPath = requestedPath[:queryIndex]
	}
	requestedPath = strings.TrimPrefix(requestedPath, "/")
	if requestedPath == "" {
		requestedPath = "index.html"
	}
	data, err := staticFiles.ReadFile("static/" + requestedPath)
	if err != nil {
		if strings.Contains(requestedPath, ".") {
			http.NotFound(w, r)
			return
		}
		indexData, indexErr := staticFiles.ReadFile("static/index.html")
		if indexErr != nil {
			http.Error(w, "Internal server error: index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(indexData)
		return
	}
	contentType := ws.getContentType(requestedPath)
	w.Header().Set("Content-Type", contentType)
	if !strings.HasSuffix(requestedPath, ".html") {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	}
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// getContentType determines the MIME type of a file based on its extension.
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
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

// handleWebSocket handles WebSocket connections for real-time updates.
func (ws *WebServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		ws.logger.Info("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	ws.clientsMu.Lock()
	ws.clients[conn] = true
	ws.clientsMu.Unlock()

	defer func() {
		ws.clientsMu.Lock()
		delete(ws.clients, conn)
		ws.clientsMu.Unlock()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// handleMemoryStats 处理内存统计请求
func (ws *WebServer) handleMemoryStats(w http.ResponseWriter, r *http.Request) {
	monitor := socks5.GetGlobalMemoryMonitor()
	if monitor == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Memory monitor not initialized",
		})
		return
	}

	stats := monitor.GetStats()
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// handleMemoryUsage 处理内存使用报告请求
func (ws *WebServer) handleMemoryUsage(w http.ResponseWriter, r *http.Request) {
	monitor := socks5.GetGlobalMemoryMonitor()
	if monitor == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Memory monitor not initialized",
		})
		return
	}

	report := monitor.GetMemoryUsageReport()
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    report,
	})
}

// handleMemoryEfficiency 处理内存效率报告请求
func (ws *WebServer) handleMemoryEfficiency(w http.ResponseWriter, r *http.Request) {
	monitor := socks5.GetGlobalMemoryMonitor()
	if monitor == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Memory monitor not initialized",
		})
		return
	}

	efficiency := monitor.GetMemoryEfficiency()
	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    efficiency,
	})
}

// handleMemoryHistory 处理内存历史记录请求
func (ws *WebServer) handleMemoryHistory(w http.ResponseWriter, r *http.Request) {
	monitor := socks5.GetGlobalMemoryMonitor()
	if monitor == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Memory monitor not initialized",
		})
		return
	}

	// 获取查询参数
	limitParam := r.URL.Query().Get("limit")
	limit := 50 // 默认返回最近50条记录
	if limitParam != "" {
		if parsedLimit, err := json.Number(limitParam).Int64(); err == nil && parsedLimit > 0 {
			limit = int(parsedLimit)
		}
	}

	history := monitor.GetHistory()

	// 根据limit参数返回指定数量的记录
	if len(history) > limit {
		history = history[len(history)-limit:]
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"total_records": len(monitor.GetHistory()),
			"limit":         limit,
			"history":       history,
		},
	})
}

// handleMemoryPools 处理内存池统计请求
func (ws *WebServer) handleMemoryPools(w http.ResponseWriter, r *http.Request) {
	// 获取全局缓冲区池和连接池的统计信息
	bufferStats := socks5.GetBufferPoolStats()
	connectionStats := socks5.GetConnectionPoolStats()

	// 计算缓冲区池命中率
	var bufferHitRate float64
	if bufferStats.TotalRequests > 0 {
		bufferHitRate = float64(bufferStats.Hits) / float64(bufferStats.TotalRequests) * 100
	}

	// 转换内存使用为MB
	var bufferMemoryMB float64
	if bufferStats.TotalMemoryUsed > 0 {
		bufferMemoryMB = float64(bufferStats.TotalMemoryUsed) / 1024 / 1024
	}

	pools := map[string]interface{}{
		"buffer_pool": map[string]interface{}{
			"active_objects":    bufferStats.ActiveObjects,
			"pooled_objects":    bufferStats.PooledObjects,
			"total_requests":    bufferStats.TotalRequests,
			"hits":              bufferStats.Hits,
			"misses":            bufferStats.Misses,
			"evictions":         bufferStats.Evictions,
			"total_memory_used": bufferStats.TotalMemoryUsed,
			"pool_memory_used":  bufferStats.PoolMemoryUsed,
			"max_pool_size":     bufferStats.MaxPoolSize,
			"last_access":       bufferStats.LastAccess.Format(time.RFC3339),
			"hit_rate_percent":  bufferHitRate,
			"total_memory_mb":   bufferMemoryMB,
		},
		"connection_pool": map[string]interface{}{
			"active_connections":  connectionStats.ActiveConnections,
			"pooled_connections":  connectionStats.PooledConnections,
			"total_requests":      connectionStats.TotalRequests,
			"hits":                connectionStats.Hits,
			"misses":              connectionStats.Misses,
			"created_connections": connectionStats.CreatedConnections,
			"reused_connections":  connectionStats.ReusedConnections,
			"hit_rate_percent":    socks5.GetConnectionHitRate(),
			"reuse_rate_percent":  socks5.GetConnectionReuseRate(),
			"pool_efficiency":     calculatePoolEfficiency(connectionStats),
			"last_access":         connectionStats.LastAccess.Format(time.RFC3339),
		},
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    pools,
	})
}

// calculatePoolEfficiency 计算连接池效率
// 对于sync.Pool，我们通过池中的对象数量与创建的总对象数来评估效率
func calculatePoolEfficiency(stats *socks5.ConnectionPoolStats) float64 {
	if stats.CreatedConnections == 0 {
		return 0
	}
	// 池效率 = 池中对象数 / 创建的总对象数
	// 这表示有多少创建的对象被保留在池中供重用
	return float64(stats.PooledConnections) / float64(stats.CreatedConnections) * 100
}

// handleTrafficStats 处理流量统计请求
func (ws *WebServer) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	monitor := socks5.GetGlobalTrafficMonitor()
	if monitor == nil {
		ws.sendJSONResponse(w, APIResponse{
			Success: false,
			Error:   "Traffic monitor not initialized",
		})
		return
	}

	stats := monitor.GetStats()

	// 转换为 MB
	data := map[string]interface{}{
		"total_upload":       stats.TotalUpload,
		"total_download":     stats.TotalDownload,
		"active_connections": stats.ActiveConnections,
		// 添加便于前端使用的字段
		"total_upload_mb":   float64(stats.TotalUpload) / 1024 / 1024,
		"total_download_mb": float64(stats.TotalDownload) / 1024 / 1024,
	}

	ws.sendJSONResponse(w, APIResponse{
		Success: true,
		Data:    data,
	})
}
