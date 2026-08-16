package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/engine"
	"smartproxy/internal/logbuf"
	"smartproxy/internal/route"
	"smartproxy/internal/upstream"
)

var (
	globalEngine  *engine.Engine
	engineMu      sync.Mutex
	cancelFunc    context.CancelFunc
	routerWatcher *config.Watcher
)

// AndroidBridge 在 Kotlin 侧实现并于 App 启动时注册(M5,§4.4)。纯 Go 面板还原后,
// /api/prefs、/api/vpn 桥接端点已删除,桥仅保留 Vpn(action):
// configReload 检测到隧道参数变更时经它触发 Android 侧 VPN 重启(重建 VpnService
// 才生效的字段)。仅用 string,gobind 双向编组支持;接口必须在本 bound 包内。
type AndroidBridge interface {
	Vpn(action string) string
}

var (
	bridge   AndroidBridge
	bridgeMu sync.RWMutex
)

// SetAndroidBridge 注册 Kotlin 实现(Kotlin 线程设置,configReload 线程读取,加锁)。
func SetAndroidBridge(b AndroidBridge) {
	bridgeMu.Lock()
	bridge = b
	bridgeMu.Unlock()
}

func currentBridge() AndroidBridge {
	bridgeMu.RLock()
	defer bridgeMu.RUnlock()
	return bridge
}

func StartRouter(configPath string, tunFd int, tunEnabled bool) error {
	slog.Info("[Go-Bridge] StartRouter called", "configPath", configPath, "tunFd", tunFd, "tunEnabled", tunEnabled)
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalEngine != nil {
		slog.Warn("[Go-Bridge] StartRouter failed: router is already running")
		return fmt.Errorf("router is already running")
	}

	// 从文件加载配置(与桌面端 config.Load 同路径):Kotlin 侧把最终 config 落到
	// filesDir/config.json 再传路径,引擎不再收 JSON 串;config.Load 会补默认值。
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("[Go-Bridge] StartRouter failed to load config", "error", err)
		return fmt.Errorf("failed to load config: %w", err)
	}

	// 与桌面 main.go 一致:slog 输出同时进 logbuf.Default 环形缓冲,纯 Go 面板的
	// Logs 页(GET /logs)才能读到;否则 logbuf 恒空,面板显示 "No logs available"。
	// 包装会转发到 stdout(logcat GoLog tag 不受影响)。
	slog.SetDefault(slog.New(logbuf.NewSlogHandlerLevel(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		logbuf.Default, slog.LevelInfo,
	)))

	// 服务模式(Android §8):tunEnabled=false = 仅代理(SOCKS5)——不建 TUN 隧道,只跑
	// 引擎 SOCKS5。config.json 的 listen.port 默认 0(隧道模式禁 SOCKS5,避免 LAN 代理),
	// 这里补默认 1080;host 强制 127.0.0.1,防无鉴权 SOCKS5 暴露到局域网。admin 不受影响:
	// 管理面板固定绑 ":AdminPort"(不读 Listen.Host),局域网扫码照常可达。
	cfg.TUN.Enabled = tunEnabled
	cfg.TUN.FileDescriptor = tunFd
	cfg.TUN.AutoRoute = false
	if !tunEnabled {
		cfg.Listen.Host = "127.0.0.1"
		if cfg.Listen.Port == 0 {
			cfg.Listen.Port = 1080
		}
	}

	eng, err := engine.New(cfg, "")
	if err != nil {
		slog.Error("[Go-Bridge] StartRouter failed to create engine", "error", err)
		return err
	}

	// 纯 Go 面板机制(与 cmd/smartproxy/main.go L138-233 对齐):面板 PUT /config
	// 写 configPath → fsnotify 监听目录 → configReload 热重载。此前移动端从未装配
	// (SetReloadFn/SetConfigPath 缺省),/config 一律 503,面板只能走 /api/prefs 桥。
	//
	// 注意 cfgDir 保持空串:engine.New 对 routing 相对路径做 filepath.Join(cfgDir, p),
	// 传 Dir(configPath) 会把 cacheDir 绝对路径接成假路径;config.json 里的 routing
	// 路径本就绝对化(ConfigProvider.ensureConfig),resolveFile 直接透传。
	aclPath := cfg.Routing.ACLFile
	watcher := config.NewWatcher()
	watcher.AddFile("config", configPath)
	watcher.AddFile("acl", aclPath)
	watcher.AddFile("chnroute", cfg.Routing.ChnrouteFile)

	configReload := func() {
		newCfg, err := config.Load(configPath)
		if err != nil {
			slog.Error("failed to reload config", "path", configPath, "error", err)
			return
		}
		if err := newCfg.Validate(); err != nil {
			slog.Error("reloaded config validation failed, keeping old config", "error", err)
			return
		}

		upstreamCfg := upstream.UpstreamConfig{
			Default:     newCfg.Upstream.Default,
			HealthCheck: newCfg.Upstream.HealthCheck,
		}
		for _, p := range newCfg.Upstream.Proxies {
			upstreamCfg.Proxies = append(upstreamCfg.Proxies, upstream.ProxyEntry{
				Alias: p.Alias,
				URL:   p.URL,
			})
		}

		oldCfg := cfg
		oldChnFile, oldACLFile := cfg.Routing.ChnrouteFile, cfg.Routing.ACLFile
		cfg = newCfg
		eng.Config.Store(cfg)
		eng.UpstreamMgr.Reload(upstreamCfg)

		// Hot-reload chnroute / ACL when their paths change, so that choosing a
		// file and saving takes effect immediately.
		resolveFile := func(p string) string {
			if filepath.IsAbs(p) {
				return p
			}
			return filepath.Join("", p)
		}
		if cfg.Routing.ChnrouteFile != oldChnFile {
			if trie, err := chnroute.Load(resolveFile(cfg.Routing.ChnrouteFile)); err != nil {
				slog.Error("failed to reload chnroute from new path", "path", cfg.Routing.ChnrouteFile, "error", err)
			} else {
				eng.Chnroute.Pull(trie)
				slog.Info("chnroute reloaded from new path", "path", cfg.Routing.ChnrouteFile)
			}
		}
		if cfg.Routing.ACLFile != oldACLFile {
			if err := eng.RuleEng.Reload(resolveFile(cfg.Routing.ACLFile)); err != nil {
				slog.Error("failed to reload ACL from new path", "path", cfg.Routing.ACLFile, "error", err)
			} else {
				slog.Info("ACL reloaded from new path", "path", cfg.Routing.ACLFile)
			}
		}

		smartTimeout := time.Duration(cfg.SmartProxy.Timeout) * time.Second
		blacklistTTL := time.Duration(cfg.SmartProxy.BlacklistTTL) * time.Second
		eng.Router.UpdateConfig(smartTimeout, blacklistTTL)

		preferMode, preferPorts := dns.ParseSpeedCheckMode(cfg.DNS.SpeedCheckMode)
		eng.DNSHandler.UpdateConfig(
			cfg.DNS.Foreign.IPv4, cfg.DNS.Foreign.IPv6,
			cfg.DNS.QueryTimeout, dns.BlockedIPv4, dns.BlockedIPv6,
			cfg.DNS.Enabled,
			preferMode != dns.PreferNone, preferMode, preferPorts,
		)
		eng.DNSHandler.SetStaticRecords(cfg.DNS.StaticRecordsMap())
		if eng.AdminServer() != nil {
			eng.AdminServer().SetAdminAuth(cfg.Listen.AdminAuth)
		}

		// TUN 隧道参数 / admin 端口证书不能热重载(establish 时固化),必须重建
		// VpnService。经桥触发 Android 侧重启(VpnControl → stop + delayed start,
		// 异步,不阻塞 watcher;桥未注册时跳过)。
		if needsRestart(oldCfg, newCfg) {
			if b := currentBridge(); b != nil {
				if msg := b.Vpn("restart"); msg != "" {
					slog.Warn("config changed fields requiring restart; auto-restart failed", "err", msg)
				}
			}
		}

		slog.Info("config reloaded")
	}
	watcher.SetConfigReloader(configReload)
	eng.SetReloadFn(configReload)
	eng.SetConfigPath(configPath)

	watcher.SetACLReloader(func() {
		if err := eng.RuleEng.Reload(aclPath); err != nil {
			slog.Error("failed to reload ACL", "error", err)
		} else {
			slog.Info("ACL rules reloaded")
		}
	})
	watcher.SetChnRouteReloader(func() {
		newTrie, err := chnroute.Load(cfg.Routing.ChnrouteFile)
		if err != nil {
			slog.Error("failed to reload chnroute", "error", err)
			return
		}
		eng.Chnroute.Pull(newTrie)
		slog.Info("chnroute reloaded")
	})
	watcher.Start()
	routerWatcher = watcher

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		slog.Error("[Go-Bridge] StartRouter eng.Start failed", "error", err)
		cancel()
		return err
	}

	globalEngine = eng
	cancelFunc = cancel
	slog.Info("[Go-Bridge] StartRouter completed successfully")
	return nil
}

func StopRouter() {
	slog.Info("[Go-Bridge] StopRouter called, waiting for engineMu lock...")
	engineMu.Lock()
	defer engineMu.Unlock()
	slog.Info("[Go-Bridge] Acquired engineMu lock")
	// 先停 watcher:Stop 会等其 goroutine(含在途 configReload)退出,再停引擎,
	// 避免 configReload 闭包引用已停止的 engine。
	if routerWatcher != nil {
		slog.Info("[Go-Bridge] Stopping routerWatcher...")
		routerWatcher.Stop()
		routerWatcher = nil
		slog.Info("[Go-Bridge] routerWatcher stopped")
	} else {
		slog.Info("[Go-Bridge] routerWatcher is nil, skipping")
	}

	if globalEngine != nil {
		slog.Info("[Go-Bridge] Cancelling context & stopping globalEngine...")
		cancelFunc()
		globalEngine.Stop()
		globalEngine = nil
		cancelFunc = nil
		slog.Info("[Go-Bridge] globalEngine stopped successfully")
	} else {
		slog.Info("[Go-Bridge] globalEngine is nil, skipping")
	}
	slog.Info("[Go-Bridge] StopRouter completed")
}

func IsRunning() bool {
	engineMu.Lock()
	defer engineMu.Unlock()
	return globalEngine != nil
}

// needsRestart 判断配置变更是否需要重建 VpnService(Android 特有;纯 Go 桌面无此
// 概念,main.go 只做热重载)。热重载能覆盖的(admin_auth、dns.foreign、smart_proxy、
// upstream)不算;TUN 隧道参数与 admin 端口/证书在 establish() 时固化,变了只能重启。
func needsRestart(oldCfg, newCfg *config.Config) bool {
	oldT, newT := oldCfg.TUN, newCfg.TUN
	if oldT.MTU != newT.MTU || oldT.Stack != newT.Stack ||
		!reflect.DeepEqual(oldT.Inet4Address, newT.Inet4Address) ||
		!reflect.DeepEqual(oldT.Inet6Address, newT.Inet6Address) ||
		!reflect.DeepEqual(oldT.DNSServers, newT.DNSServers) {
		return true
	}
	oldL, newL := oldCfg.Listen, newCfg.Listen
	if oldL.AdminPort != newL.AdminPort || oldL.AdminHTTPS != newL.AdminHTTPS ||
		oldL.AdminCertFile != newL.AdminCertFile || oldL.AdminKeyFile != newL.AdminKeyFile ||
		!reflect.DeepEqual(oldL.AdminCertSANs, newL.AdminCertSANs) {
		return true
	}
	return false
}

// 不导出:gomobile bind 只绑定导出类型。GetStatus 返回 JSON 串,无需把
// internal/route.BlacklistEntry 暴露成 Java 类(跨包绑定徒增 AAR 面)。
type routerStatus struct {
	IsRunning       bool                   `json:"is_running"`
	IPBlacklist     []route.BlacklistEntry `json:"ip_blacklist"`
	DomainBlacklist []route.BlacklistEntry `json:"domain_blacklist"`
}

func GetStatus() (string, error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalEngine == nil {
		return `{"is_running":false}`, nil
	}
	ipBL, domainBL := globalEngine.Router.BlacklistSnapshot()
	status := routerStatus{
		IsRunning:       true,
		IPBlacklist:     ipBL,
		DomainBlacklist: domainBL,
	}
	data, err := json.Marshal(status)
	if err != nil {
		return "", fmt.Errorf("failed to marshal status: %v", err)
	}
	return string(data), nil
}
