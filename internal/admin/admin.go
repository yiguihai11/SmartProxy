package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"smartproxy/internal/chnroute"

	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/logbuf"
	"smartproxy/internal/relay"
	"smartproxy/internal/route"
	"smartproxy/internal/rules"
	"smartproxy/internal/safego"
	"smartproxy/internal/udp"
	"smartproxy/internal/upstream"
	"smartproxy/internal/version"
)

type Server struct {
	sockPath     string
	tcpPort      int
	router       *route.Router
	mgr          *upstream.Manager
	dns          *dns.Handler
	chnroute     *chnroute.Trie
	logBuf       *logbuf.RingBuffer
	adminAuth    *config.AdminAuthConf
	startTime    time.Time
	reloadConfig func()
	configSrc    func() *config.Config
	configPath   string
	refreshInt   int
	statsMu      sync.Mutex
	stats        cachedStats

	stopCh    chan struct{}
	listener  net.Listener
	tcpLn     net.Listener
	server    *http.Server
	tcpServer *http.Server

	tlsEnabled   bool
	certFile     string
	keyFile      string
	tlsExtraSANs []string
	// certPEM is the public certificate in use (auto-generated or custom), captured at
	// buildTLSConfig for the /admin.crt download. Empty when HTTPS is not in use.
	certPEM []byte

}

type cachedStats struct {
	allocMB      string
	cpuPercent   float64
	gcCount      uint32
	gcPause      string
	updatedAt    time.Time
	prevCPUTime  time.Duration
	prevSampleAt time.Time
}

func New(sockPath string, router *route.Router, mgr *upstream.Manager, dnsHandler *dns.Handler, ct *chnroute.Trie) *Server {
	return &Server{sockPath: sockPath, router: router, mgr: mgr, dns: dnsHandler, chnroute: ct, logBuf: logbuf.Default, startTime: time.Now(), stopCh: make(chan struct{})}
}

func (s *Server) SetLogBuffer(buf *logbuf.RingBuffer) {
	s.logBuf = buf
}

func (s *Server) SetAdminAuth(auth *config.AdminAuthConf) {
	s.adminAuth = auth
}

func (s *Server) SetReloadConfig(fn func()) {
	s.reloadConfig = fn
}

func (s *Server) SetConfigSrc(fn func() *config.Config) {
	s.configSrc = fn
}

func (s *Server) SetConfigPath(path string) {
	s.configPath = path
}
func (s *Server) Start() error {
	mux := s.setupMux()

	if s.sockPath != "" {
		dir := filepath.Dir(s.sockPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		os.Remove(s.sockPath)

		ln, err := net.Listen("unix", s.sockPath)
		if err != nil {
			return err
		}
		os.Chmod(s.sockPath, 0666)
		s.listener = ln
		s.server = &http.Server{Handler: mux}
		slog.Info("admin server started", "socket", s.sockPath)
		go s.server.Serve(ln)
	}

	// Refresh process stats every 30 seconds (to avoid triggering STW on every SSE push)
	s.refreshStats()
	safego.Go("admin.statsRefresher", func() {
		interval := s.refreshInt
		if interval < 1 {
			interval = 3
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.refreshStats()
			case <-s.stopCh:
				return
			}
		}
	})

	if s.tcpPort > 0 {
		addr := fmt.Sprintf(":%d", s.tcpPort)
		tcpLn, err := net.Listen("tcp", addr)
		if err != nil {
			slog.Warn("admin TCP listen failed", "port", s.tcpPort, "error", err)
		} else {
			s.tcpLn = tcpLn
			if s.tlsEnabled {
				tlsCfg, err := s.buildTLSConfig()
				if err != nil {
					// A bad cert (e.g. unreadable configured files) must not take the
					// panel down: fall back to plain HTTP so it stays reachable.
					slog.Warn("admin TLS setup failed, falling back to plain HTTP", "error", err)
					s.tcpServer = &http.Server{Handler: s.authMiddleware(mux)}
					slog.Info("admin HTTP server started", "port", s.tcpPort)
					go s.tcpServer.Serve(tcpLn)
				} else {
					// One port, two protocols: TLS handshakes are served as HTTPS,
					// plaintext requests are 301-redirected to https (see tls.go).
					s.tcpServer = &http.Server{Handler: s.tlsDispatch(mux)}
					slog.Info("admin HTTPS server started (HTTP redirects to https)", "port", s.tcpPort)
					go s.tcpServer.Serve(&splitListener{Listener: tcpLn, tlsCfg: tlsCfg})
				}
			} else {
				// The TCP port requires authentication
				s.tcpServer = &http.Server{Handler: s.authMiddleware(mux)}
				slog.Info("admin HTTP server started", "port", s.tcpPort)
				go s.tcpServer.Serve(tcpLn)
			}
		}
	}
	return nil
}

// tlsDispatch routes a TCP-port request by transport: real TLS (handshaked by
// http.Server, r.TLS set) is served through the authenticated mux; plaintext HTTP
// is bounced to the https:// URL on the same host:port with the original path.
func (s *Server) tlsDispatch(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			s.authMiddleware(mux).ServeHTTP(w, r)
			return
		}
		host := r.Host
		if host == "" {
			host = "localhost"
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.server != nil {
		s.server.Close()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.tcpServer != nil {
		s.tcpServer.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	if s.sockPath != "" {
		os.Remove(s.sockPath)
	}
}
func (s *Server) setupMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/blacklist", s.handleBlacklist)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/cache", s.handleCache)
	mux.HandleFunc("/dns/static", s.handleDNSStatic)
	mux.HandleFunc("/route", s.handleRoute)
	mux.HandleFunc("/dashboard", s.handleDashboard)
	mux.HandleFunc("/cache/flush", s.handleCacheFlush)
	mux.HandleFunc("/config/reload", s.handleConfigReload)
	mux.HandleFunc("/acl", s.handleACL)
	mux.HandleFunc("/chnroute", s.handleChnroute)
	mux.HandleFunc("/health/proxy", s.handleHealthProxy)
	mux.HandleFunc("/health/reset-auto", s.handleHealthResetAuto)
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/files", s.handleFiles)
	mux.HandleFunc("/files/validate", s.handleFileValidate)
	mux.HandleFunc("/files/create", s.handleFileCreate)
	mux.HandleFunc("/acl/add", s.handleACLAdd)
	mux.HandleFunc("/cm.js", s.handleCMJS)
	mux.HandleFunc("/cm.css", s.handleCMCSS)
	mux.HandleFunc("/json.js", s.handleJSONJS)
	mux.HandleFunc("/dracula.css", s.handleDraculaCSS)
	mux.HandleFunc("/simple.js", s.handleSimpleJS)
	mux.HandleFunc("/chart.js", s.handleChartJS)
	mux.HandleFunc("/jsqr.js", s.handleJsqrJS)
	mux.HandleFunc("/qrcode.js", s.handleQRCodeJS)
	mux.HandleFunc("/logs", s.handleLogs)
	mux.HandleFunc("/logs/clear", s.handleLogsClear)
	mux.HandleFunc("/terminal/clear", s.handleTerminalClear)
	mux.HandleFunc("/admin.crt", s.handleAdminCert)
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/events", s.handleEvents)

	return mux
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.adminAuth != nil && s.adminAuth.Enabled && s.adminAuth.Username != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != s.adminAuth.Username || p != s.adminAuth.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Admin Console"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) SetTCPPort(port int) {
	s.tcpPort = port
}

func (s *Server) SetRefreshInterval(sec int) {
	if sec < 1 {
		sec = 3
	}
	s.refreshInt = sec
}

func (s *Server) refreshStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	now := time.Now()
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	s.stats.allocMB = formatMB(m.Alloc)
	s.stats.gcCount = m.NumGC
	if m.NumGC > 0 {
		s.stats.gcPause = formatDuration(time.Duration(m.PauseNs[(m.NumGC-1)&255]))
	} else {
		s.stats.gcPause = "0"
	}
	s.stats.updatedAt = now

	// Calculate CPU usage based on delta sampling
	currCPUTime, err := getProcessCPUTime()
	if err == nil {
		if !s.stats.prevSampleAt.IsZero() {
			deltaWall := now.Sub(s.stats.prevSampleAt).Seconds()
			deltaCPU := (currCPUTime - s.stats.prevCPUTime).Seconds()
			if deltaWall > 0.1 && deltaCPU >= 0 {
				numCPU := float64(runtime.NumCPU())
				if numCPU < 1 {
					numCPU = 1
				}
				pct := (deltaCPU / (deltaWall * numCPU)) * 100.0
				if pct < 0 {
					pct = 0
				} else if pct > 100.0 {
					pct = 100.0
				}
				s.stats.cpuPercent = pct
			}
		} else {
			uptime := now.Sub(s.startTime).Seconds()
			if uptime > 0.5 {
				numCPU := float64(runtime.NumCPU())
				if numCPU < 1 {
					numCPU = 1
				}
				pct := (currCPUTime.Seconds() / (uptime * numCPU)) * 100.0
				if pct < 0 {
					pct = 0
				} else if pct > 100.0 {
					pct = 100.0
				}
				s.stats.cpuPercent = pct
			} else {
				s.stats.cpuPercent = 0.0
			}
		}
		s.stats.prevCPUTime = currCPUTime
		s.stats.prevSampleAt = now
	}
}

func (s *Server) getStatsSnapshot() (allocMB string, cpuPercent float64, gcCount uint32, gcPause string) {
	s.statsMu.Lock()
	allocMB = s.stats.allocMB
	cpuPercent = s.stats.cpuPercent
	gcCount = s.stats.gcCount
	gcPause = s.stats.gcPause
	s.statsMu.Unlock()
	return
}

// ---- stats ----

type StatsResponse struct {
	TCP     TCPStats     `json:"tcp"`
	UDP     UDPStats     `json:"udp"`
	Process ProcessStats `json:"process"`
}

type ProcessStats struct {
	Goroutines   int     `json:"goroutines"`
	GoMaxProcs   int     `json:"gomaxprocs"`
	AllocMB      string  `json:"alloc_mb"`
	TotalAllocMB string  `json:"total_alloc_mb"`
	NumGC        uint32  `json:"num_gc"`
	LastGCPause  string  `json:"last_gc_pause"`
	CPUPercent   float64 `json:"cpu_percent"`
	Uptime       string  `json:"uptime"`
}

type TCPStats struct {
	ProxyBytesUp    int64 `json:"proxy_bytes_up"`
	ProxyBytesDown  int64 `json:"proxy_bytes_down"`
	DirectBytesUp   int64 `json:"direct_bytes_up"`
	DirectBytesDown int64 `json:"direct_bytes_down"`
	ActiveConns     int32 `json:"active_conns"`
}

type UDPStats struct {
	ProxyBytesUp    int64 `json:"proxy_bytes_up"`
	ProxyBytesDown  int64 `json:"proxy_bytes_down"`
	DirectBytesUp   int64 `json:"direct_bytes_up"`
	DirectBytesDown int64 `json:"direct_bytes_down"`
	ActiveSessions  int32 `json:"active_sessions"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	allocMB, cpuPercent, gcCount, gcPause := s.getStatsSnapshot()
	json.NewEncoder(w).Encode(StatsResponse{
		TCP: TCPStats{
			ProxyBytesUp:    relay.ProxyBytesUp.Load(),
			ProxyBytesDown:  relay.ProxyBytesDown.Load(),
			DirectBytesUp:   relay.DirectBytesUp.Load(),
			DirectBytesDown: relay.DirectBytesDown.Load(),
			ActiveConns:     relay.ActiveConns.Load(),
		},
		UDP: UDPStats{
			ProxyBytesUp:    udp.ProxyBytesUp.Load(),
			ProxyBytesDown:  udp.ProxyBytesDown.Load(),
			DirectBytesUp:   udp.DirectBytesUp.Load(),
			DirectBytesDown: udp.DirectBytesDown.Load(),
			ActiveSessions:  udp.ActiveSessions.Load(),
		},
		Process: ProcessStats{
			Goroutines:   runtime.NumGoroutine(),
			GoMaxProcs:   runtime.GOMAXPROCS(0),
			AllocMB:      allocMB,
			TotalAllocMB: formatMB(m.TotalAlloc),
			NumGC:        gcCount,
			LastGCPause:  gcPause,
			CPUPercent:   cpuPercent,
			Uptime:       formatUptime(time.Since(s.startTime)),
		},
	})
}

// ---- blacklist ----

type BlacklistEntry struct {
	Type       string `json:"type"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	LastReason string `json:"last_reason"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (s *Server) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		ipEntries, domainEntries := s.router.BlacklistSnapshot()

		entries := make([]BlacklistEntry, 0, len(ipEntries)+len(domainEntries))
		for _, e := range ipEntries {
			entries = append(entries, BlacklistEntry{
				Type: "ip", Host: e.Host, Port: e.Port,
				LastReason: e.LastReason, ExpiresAt: e.ExpiresAt,
			})
		}
		for _, e := range domainEntries {
			entries = append(entries, BlacklistEntry{
				Type: "domain", Host: e.Host, Port: e.Port,
				LastReason: e.LastReason, ExpiresAt: e.ExpiresAt,
			})
		}

		json.NewEncoder(w).Encode(entries)

	case http.MethodDelete:
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host query param", http.StatusBadRequest)
			return
		}
		typ := r.URL.Query().Get("type")
		s.router.RemoveFromBlacklist(host, 0, typ)
		slog.Info("admin: removed from blacklist", "host", host, "type", typ)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- health ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"strategy": s.mgr.Strategy(),
		"proxies":  s.mgr.Proxies(),
	})
}

// ---- cache ----

func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		if r.URL.Query().Get("list") == "1" {
			json.NewEncoder(w).Encode(s.dns.CacheEntries())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"entries": s.dns.CacheLen(),
		})

	case http.MethodDelete:
		qname := r.URL.Query().Get("qname")
		if qname == "" {
			http.Error(w, "missing qname query param", http.StatusBadRequest)
			return
		}
		var qtype uint16 = 1 // default: A record
		if qt := r.URL.Query().Get("qtype"); qt != "" {
			if n, err := strconv.Atoi(qt); err == nil {
				qtype = uint16(n)
			}
		}
		s.dns.CacheRemove(qname, qtype)
		slog.Info("admin: removed DNS cache entry", "qname", qname, "qtype", qtype)
		w.WriteHeader(http.StatusNoContent)

	case http.MethodPost:
		// Pin a cached answer as a persistent static record: the edited address is
		// written into dns.static_records, then hot-applied by the config file
		// watcher (same reload path as handleConfig — no manual reloadConfig here,
		// which would double-trigger a full engine reload). Static records are
		// checked before the cache on both TUN and UDP paths, so once the reload
		// lands the new address wins over any cached answer.
		if s.configSrc == nil {
			http.Error(w, "config not available", http.StatusServiceUnavailable)
			return
		}
		if s.configPath == "" || s.reloadConfig == nil {
			http.Error(w, "config write not available", http.StatusServiceUnavailable)
			return
		}
		var req struct {
			Qname string        `json:"qname"`
			Qtype uint16        `json:"qtype"`
			IP    config.IPList `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Qname = strings.TrimSpace(req.Qname)
		if req.Qname == "" {
			http.Error(w, "qname must not be empty", http.StatusBadRequest)
			return
		}
		if len(req.IP) == 0 {
			http.Error(w, "ip must contain at least one IP address", http.StatusBadRequest)
			return
		}
		var ips []net.IP
		for _, raw := range req.IP {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				http.Error(w, "ip must be a valid IP address", http.StatusBadRequest)
				return
			}
			// The address family must match the cached row's type (A→IPv4, AAAA→IPv6).
			switch req.Qtype {
			case mdns.TypeA:
				if ip.To4() == nil {
					http.Error(w, "A record requires an IPv4 address", http.StatusBadRequest)
					return
				}
			case mdns.TypeAAAA:
				if ip.To4() != nil {
					http.Error(w, "AAAA record requires an IPv6 address", http.StatusBadRequest)
					return
				}
			default:
				http.Error(w, "only A/AAAA records can be pinned", http.StatusBadRequest)
				return
			}
			ips = append(ips, ip)
		}
		_, verr, werr := s.saveConfig(func(c *config.Config) {
			c.DNS.StaticRecords = config.SetStaticRecordIPs(c.DNS.StaticRecords, req.Qname, ips)
		})
		if verr != nil {
			http.Error(w, "validation failed: "+verr.Error(), http.StatusBadRequest)
			return
		}
		if werr != nil {
			http.Error(w, "write failed: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		// The static record now supersedes the cache entry, so drop it to keep the
		// panel's cache view consistent with what is actually served.
		s.dns.CacheRemove(req.Qname, req.Qtype)
		slog.Info("admin: pinned DNS answer as static record",
			"qname", req.Qname, "qtype", req.Qtype, "ips", req.IP)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"host":   req.Qname,
			"ip":     req.IP,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- route ----

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"loaded":  !s.chnroute.IsEmpty(),
		"entries": s.chnroute.Count(),
		"v4":      s.chnroute.CountV4(),
		"v6":      s.chnroute.CountV6(),
	})
}

// ---- cache flush ----

func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.dns.CacheClear()
	slog.Info("admin: DNS cache flushed")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ---- health proxy toggle ----

func (s *Server) handleHealthProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	alias := r.URL.Query().Get("alias")
	action := r.URL.Query().Get("action")
	circuit := r.URL.Query().Get("circuit")
	if alias == "" {
		http.Error(w, "need ?alias=xx", http.StatusBadRequest)
		return
	}
	if action != "enable" && action != "disable" && action != "auto" {
		http.Error(w, "need ?action=enable|disable|auto", http.StatusBadRequest)
		return
	}
	if circuit == "" {
		circuit = "both"
	}
	if circuit != "tcp" && circuit != "udp" && circuit != "both" {
		http.Error(w, "need ?circuit=tcp|udp|both", http.StatusBadRequest)
		return
	}
	err := s.mgr.SetCircuitHealth(alias, circuit, action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	slog.Info("admin: proxy health set", "alias", alias, "circuit", circuit, "action", action)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleHealthResetAuto implements the panel's "one-click recover nodes": circuits the
// health checker auto-opened (probe failures) are returned to closed; manual pins are
// untouched. Recovery is temporary — another failure re-opens them through the normal flow.
func (s *Server) handleHealthResetAuto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n := s.mgr.ResetAutoOpenedCircuits()
	slog.Info("admin: reset auto-opened circuits", "count", n)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "reset": n})
}

// ---- config reload ----

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reloadConfig == nil {
		http.Error(w, "config reload not available", http.StatusServiceUnavailable)
		return
	}
	s.reloadConfig()
	slog.Info("admin: config reloaded")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		if s.configSrc == nil {
			http.Error(w, "config not available", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(s.configSrc())

	case http.MethodPut:
		if s.configPath == "" || s.reloadConfig == nil {
			http.Error(w, "config write not available", http.StatusServiceUnavailable)
			return
		}
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := cfg.Validate(); err != nil {
			http.Error(w, "validation failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		indented, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			http.Error(w, "format error", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(s.configPath, indented, 0644); err != nil {
			http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: config saved to disk", "path", s.configPath)
		// Reload is owned by the config file watcher (fsnotify watches configPath),
		// which fires on this write. Calling reloadConfig here as well would
		// double-trigger a full upstream/engine reload on every save.
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// saveConfig copies the live config, applies mutate to the copy, validates it,
// and writes it to disk — the same persistence path as handleConfig, where the
// actual reload is owned by the config file watcher (fsnotify) so no manual
// reloadConfig call happens here. Returns the updated copy plus two errors:
// validationErr (client-facing, 400) and writeErr (server-facing, 500).
func (s *Server) saveConfig(mutate func(c *config.Config)) (*config.Config, error, error) {
	next := *s.configSrc()
	mutate(&next)
	if err := next.Validate(); err != nil {
		return nil, err, nil
	}
	indented, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(s.configPath, indented, 0644); err != nil {
		return nil, nil, err
	}
	slog.Info("admin: config saved to disk", "path", s.configPath)
	return &next, nil, nil
}

// ---- static DNS records ----

// handleDNSStatic manages dns.static_records (hosts-override) directly:
//
//	GET    → the configured record list
//	POST   → upsert {host, ip}, where ip is a single address or an array; each
//	         address replaces only its own family (A→v4, AAAA→v6) on that host
//	DELETE → ?host=X[&ip=Y]; with ip the single address is dropped (empty record
//	         is removed), without ip the whole host record is dropped
//
// Mutations persist to config.json and hot-apply via the config file watcher.
func (s *Server) handleDNSStatic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	requireWrite := func() bool {
		if s.configSrc == nil {
			http.Error(w, "config not available", http.StatusServiceUnavailable)
			return false
		}
		if s.configPath == "" || s.reloadConfig == nil {
			http.Error(w, "config write not available", http.StatusServiceUnavailable)
			return false
		}
		return true
	}

	switch r.Method {
	case http.MethodGet:
		if s.configSrc == nil {
			http.Error(w, "config not available", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(s.configSrc().DNS.StaticRecords)

	case http.MethodPost:
		if !requireWrite() {
			return
		}
		var req struct {
			Host string        `json:"host"`
			IP   config.IPList `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Host = strings.TrimSpace(req.Host)
		if req.Host == "" {
			http.Error(w, "host must not be empty", http.StatusBadRequest)
			return
		}
		if len(req.IP) == 0 {
			http.Error(w, "ip must not be empty", http.StatusBadRequest)
			return
		}
		ips := make([]net.IP, 0, len(req.IP))
		for _, s := range req.IP {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				http.Error(w, "ip must be a valid IP address: "+strings.TrimSpace(s), http.StatusBadRequest)
				return
			}
			ips = append(ips, ip)
		}
		next, verr, werr := s.saveConfig(func(c *config.Config) {
			for _, ip := range ips {
				c.DNS.StaticRecords = config.SetStaticRecordIP(c.DNS.StaticRecords, req.Host, ip)
			}
		})
		if verr != nil {
			http.Error(w, "validation failed: "+verr.Error(), http.StatusBadRequest)
			return
		}
		if werr != nil {
			http.Error(w, "write failed: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: static record upserted", "host", req.Host, "ip", req.IP)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"records": next.DNS.StaticRecords,
		})

	case http.MethodPut:
		// Edit an existing record: replaces old_host's record (and any record
		// already carrying host) with a fresh record holding exactly ip — so the
		// address list can be swapped wholesale, unlike POST's family-aware merge.
		if !requireWrite() {
			return
		}
		var req struct {
			OldHost string        `json:"old_host"`
			Host    string        `json:"host"`
			IP      config.IPList `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.OldHost = strings.TrimSpace(req.OldHost)
		req.Host = strings.TrimSpace(req.Host)
		if req.OldHost == "" {
			http.Error(w, "old_host must not be empty", http.StatusBadRequest)
			return
		}
		if req.Host == "" {
			http.Error(w, "host must not be empty", http.StatusBadRequest)
			return
		}
		ips := make([]net.IP, 0, len(req.IP))
		for _, s := range req.IP {
			ip := net.ParseIP(strings.TrimSpace(s))
			if ip == nil {
				http.Error(w, "ip must be a valid IP address: "+strings.TrimSpace(s), http.StatusBadRequest)
				return
			}
			ips = append(ips, ip)
		}
		next, verr, werr := s.saveConfig(func(c *config.Config) {
			c.DNS.StaticRecords = config.ReplaceStaticRecord(c.DNS.StaticRecords, req.OldHost, req.Host, ips)
		})
		if verr != nil {
			http.Error(w, "validation failed: "+verr.Error(), http.StatusBadRequest)
			return
		}
		if werr != nil {
			http.Error(w, "write failed: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: static record replaced", "old_host", req.OldHost, "host", req.Host, "ip", req.IP)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"records": next.DNS.StaticRecords,
		})

	case http.MethodDelete:
		if !requireWrite() {
			return
		}
		host := strings.TrimSpace(r.URL.Query().Get("host"))
		if host == "" {
			http.Error(w, "missing host query param", http.StatusBadRequest)
			return
		}
		var next *config.Config
		var verr, werr error
		if ipStr := strings.TrimSpace(r.URL.Query().Get("ip")); ipStr != "" {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				http.Error(w, "invalid ip query param", http.StatusBadRequest)
				return
			}
			next, verr, werr = s.saveConfig(func(c *config.Config) {
				c.DNS.StaticRecords = config.RemoveStaticRecordIP(c.DNS.StaticRecords, host, ip)
			})
		} else {
			next, verr, werr = s.saveConfig(func(c *config.Config) {
				c.DNS.StaticRecords = config.RemoveStaticRecord(c.DNS.StaticRecords, host)
			})
		}
		if verr != nil {
			http.Error(w, "validation failed: "+verr.Error(), http.StatusBadRequest)
			return
		}
		if werr != nil {
			http.Error(w, "write failed: "+werr.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: static record removed", "host", host)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"records": next.DNS.StaticRecords,
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(version.Info())
}

// handleAdminCert serves the certificate a device must install as a trusted CA, as PEM for
// download (Android / iOS / desktop). With a baked CA present this is the CA certificate
// itself — the stable trust anchor; otherwise the self-signed admin cert. Only the public
// certificate is served — never the private key. Available whenever HTTPS is in use
// (auto-generated or custom cert files); 404 with a hint when HTTPS is off (buildTLSConfig
// never ran) so the panel stays plain HTTP.
func (s *Server) handleAdminCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(s.certPEM) == 0 {
		http.Error(w, "admin HTTPS is not enabled (admin_https=false or TLS setup failed); no certificate to download", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="admin.crt"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(s.certPEM)))
	w.Write(s.certPEM)
}

// ---- file browser ----

type FileEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
}

type FileListResponse struct {
	Path    string      `json:"path"`
	Parent  string      `json:"parent"`
	Entries []FileEntry `json:"entries"`
}

func (s *Server) writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleFiles lists directory contents; when path is empty, it starts from the
// program's working directory.
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			s.writeJSONError(w, http.StatusInternalServerError, "cannot get working directory: "+err.Error())
			return
		}
		path = cwd
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	abs = filepath.Clean(abs)

	dirEntries, err := os.ReadDir(abs)
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case os.IsPermission(err):
			code = http.StatusForbidden
		case os.IsNotExist(err):
			code = http.StatusNotFound
		}
		s.writeJSONError(w, code, err.Error())
		return
	}

	resp := FileListResponse{Path: abs}
	if parent := filepath.Dir(abs); parent != abs {
		resp.Parent = parent
	}
	for _, e := range dirEntries {
		fe := FileEntry{Name: e.Name(), IsDir: e.IsDir()}
		if !fe.IsDir {
			if info, err := e.Info(); err == nil {
				fe.Size = info.Size()
			}
		}
		resp.Entries = append(resp.Entries, fe)
	}
	// Directories first, each group sorted by name (os.ReadDir already sorts by file name)
	sort.SliceStable(resp.Entries, func(i, j int) bool {
		if resp.Entries[i].IsDir != resp.Entries[j].IsDir {
			return resp.Entries[i].IsDir
		}
		return resp.Entries[i].Name < resp.Entries[j].Name
	})
	json.NewEncoder(w).Encode(resp)
}

// handleFileValidate checks whether the selected file can be used as chnroute/ACL.
func (s *Server) handleFileValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	typ := r.URL.Query().Get("type") // "chnroute" | "acl"
	path := r.URL.Query().Get("path")
	if path == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": "missing path"})
		return
	}
	var err error
	switch typ {
	case "chnroute":
		var trie *chnroute.Trie
		trie, err = chnroute.Load(path)
		if err == nil && trie.IsEmpty() {
			err = fmt.Errorf("no valid CIDR entries found")
		}
	case "acl":
		_, err = rules.New(path)
	default:
		err = fmt.Errorf("unknown type %q", typ)
	}
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// handleFileCreate creates an empty file at the given absolute path. The file
// must not already exist — existing files are never overwritten (O_EXCL).
func (s *Server) handleFileCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}
	abs, err := filepath.Abs(req.Path)
	if err != nil {
		s.writeJSONError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	abs = filepath.Clean(abs)

	parent := filepath.Dir(abs)
	if info, err := os.Stat(parent); err != nil {
		code := http.StatusBadRequest
		if !os.IsNotExist(err) {
			code = http.StatusInternalServerError
		}
		s.writeJSONError(w, code, "parent directory not accessible: "+err.Error())
		return
	} else if !info.IsDir() {
		s.writeJSONError(w, http.StatusBadRequest, "not a directory: "+parent)
		return
	}

	f, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		code := http.StatusInternalServerError
		switch {
		case os.IsExist(err):
			code = http.StatusConflict
		case os.IsPermission(err):
			code = http.StatusForbidden
		}
		s.writeJSONError(w, code, err.Error())
		return
	}
	f.Close()
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "path": abs})
}

func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	if s.configSrc == nil {
		http.Error(w, "config not available", http.StatusServiceUnavailable)
		return
	}
	path := s.configSrc().Routing.ACLFile
	if path == "" {
		http.Error(w, "acl path not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)

	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(path, body, 0644); err != nil {
			http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: ACL file saved", "path", path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type ACLAddRequest struct {
	Entries []ACLEntry `json:"entries"`
}

type ACLEntry struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	Action   string `json:"action"`
	Upstream string `json:"upstream"`
}

func (s *Server) handleACLAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ACLAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if s.configSrc == nil {
		http.Error(w, "config not available", http.StatusServiceUnavailable)
		return
	}
	path := s.configSrc().Routing.ACLFile
	if path == "" {
		http.Error(w, "ACL file not configured", http.StatusServiceUnavailable)
		return
	}

	if len(req.Entries) > 200 {
		http.Error(w, "batch too large: max 200 entries per request", http.StatusBadRequest)
		return
	}

	existingRaw, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	existingSet := make(map[string]bool)
	for _, line := range strings.Split(string(existingRaw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		existingSet[trimmed] = true
	}

	var lines []string
	for _, e := range req.Entries {
		if e.Type != "domain" && e.Type != "ip" {
			http.Error(w, "invalid type: must be domain or ip", http.StatusBadRequest)
			return
		}
		if e.Action != "allow" && e.Action != "block" && e.Action != "proxy" {
			http.Error(w, "invalid action: must be allow, block, or proxy", http.StatusBadRequest)
			return
		}
		line := e.Action + " " + e.Type + " " + e.Value
		if e.Action == "proxy" {
			if e.Upstream == "" {
				http.Error(w, "upstream is required for proxy action", http.StatusBadRequest)
				return
			}
			line += " " + e.Upstream
		}
		if !existingSet[line] {
			lines = append(lines, line)
			existingSet[line] = true
		}
	}

	if len(lines) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
			"count":  0,
			"notice": "all entries already exist, nothing added",
		})
		return
	}

	content := "\n" + strings.Join(lines, "\n") + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		http.Error(w, "append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	skipped := len(req.Entries) - len(lines)
	slog.Info("admin: ACL entries appended", "path", path, "added", len(lines), "skipped_duplicates", skipped)

	if s.reloadConfig != nil {
		s.reloadConfig()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"count":   len(lines),
		"skipped": skipped,
	})
}

func (s *Server) handleChnroute(w http.ResponseWriter, r *http.Request) {
	if s.configSrc == nil {
		http.Error(w, "config not available", http.StatusServiceUnavailable)
		return
	}
	path := s.configSrc().Routing.ChnrouteFile
	if path == "" {
		http.Error(w, "chnroute path not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)

	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		// Parse and validate the uploaded content first: reject the write if it
		// contains no valid CIDR prefixes (parse-then-write).
		trie, err := chnroute.Parse(body)
		if err != nil {
			http.Error(w, "parse failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		if trie.IsEmpty() {
			http.Error(w, "no valid CIDR entries found in uploaded content", http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(path, body, 0644); err != nil {
			http.Error(w, "write failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		slog.Info("admin: chnroute file saved", "path", path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// 纯 Go 面板还原:M5 精简手机面板已删除,手机浏览器落点 / 与 /dashboard
	// 一样服务完整桌面面板 dashboard.html(纯 Go 端点,写 config.json + watcher 热重载)。
	s.handleDashboard(w, r)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	interval := s.refreshInt
	if interval < 1 {
		interval = 3
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			data := s.gatherLiveData()
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", b)

			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) gatherLiveData() map[string]interface{} {
	ipBL, domBL := s.router.BlacklistSnapshot()
	blReasons := make(map[string]int)
	for _, e := range ipBL {
		blReasons[e.LastReason]++
	}
	for _, e := range domBL {
		blReasons[e.LastReason]++
	}
	allocMB, cpuPercent, gcCount, gcPause := s.getStatsSnapshot()
	return map[string]interface{}{
		"stats": map[string]interface{}{
			"goroutines":      runtime.NumGoroutine(),
			"uptime":          formatUptime(time.Since(s.startTime)),
			"alloc_mb":        allocMB,
			"cpu_percent":     cpuPercent,
			"gc_count":        gcCount,
			"gc_pause":        gcPause,
			"tcp_conns":       relay.ActiveConns.Load(),
			"udp_sessions":    udp.ActiveSessions.Load(),
			"tcp_proxy_up":    relay.ProxyBytesUp.Load(),
			"tcp_proxy_down":  relay.ProxyBytesDown.Load(),
			"tcp_direct_up":   relay.DirectBytesUp.Load(),
			"tcp_direct_down": relay.DirectBytesDown.Load(),
			"udp_proxy_up":    udp.ProxyBytesUp.Load(),
			"udp_proxy_down":  udp.ProxyBytesDown.Load(),
			"udp_direct_up":   udp.DirectBytesUp.Load(),
			"udp_direct_down": udp.DirectBytesDown.Load(),
		},
		"route": map[string]interface{}{
			"loaded":  !s.chnroute.IsEmpty(),
			"entries": s.chnroute.Count(),
			"v4":      s.chnroute.CountV4(),
			"v6":      s.chnroute.CountV6(),
		},
		"cache": map[string]interface{}{
			"entries": s.dns.CacheLen(),
		},
		"bl_total":   len(ipBL) + len(domBL),
		"bl_reasons": blReasons,
		"health": map[string]interface{}{
			"strategy": s.mgr.Strategy(),
			"proxies":  s.mgr.Proxies(),
		},
	}
}
func formatMB(b uint64) string {
	const mb = 1024 * 1024
	if b == 0 {
		return "0"
	}
	return fmt.Sprintf("%.1f", float64(b)/float64(mb))
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	if d < time.Microsecond {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fµs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.2fms", float64(d.Milliseconds()))
}

func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd%dh%dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh%dm", hours, mins)
}


func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	levelFilter := strings.ToUpper(r.URL.Query().Get("level"))
	sinceID, _ := strconv.ParseUint(r.URL.Query().Get("since_id"), 10, 64)

	buf := s.logBuf
	if buf == nil {
		buf = logbuf.Default
	}

	var entries []logbuf.LogEntry
	if sinceID > 0 {
		entries = buf.GetSince(sinceID)
	} else {
		entries = buf.GetAll()
	}

	if levelFilter != "" && levelFilter != "ALL" {
		filtered := make([]logbuf.LogEntry, 0, len(entries))
		for _, e := range entries {
			if strings.EqualFold(e.Level, levelFilter) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}
func (s *Server) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	buf := s.logBuf
	if buf == nil {
		buf = logbuf.Default
	}
	buf.Clear()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleTerminalClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	os.Stdout.Write([]byte("\033[2J\033[H\033[3J"))
	os.Stdout.Sync()
	if err := exec.Command("clear").Run(); err != nil {
		fmt.Fprint(os.Stdout, "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
