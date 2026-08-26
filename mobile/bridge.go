package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
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
	uidResolver   UIDResolver
)

// UIDResolver 让 Go TUN 路径按连接反查所属 app UID(per-app「禁止联网」拦截)。
// gomobile 会把该接口绑定成 Java 接口,Kotlin 侧实现并回注册:
//
//	Mobile.setUIDResolver(UIDResolver)
//
// proto: 6=TCP, 17=UDP;四元组即连接两端地址。返回 UID,未知返回 -1。
// 实现见 Android UIDResolver.kt(API29+ ConnectivityManager.getConnectionOwnerUid,
// API26-28 回退 /proc/net 解析)。
type UIDResolver interface {
	ResolveUID(proto int32, localIP string, localPort int32, remoteIP string, remotePort int32) int32
}

// SetUIDResolver 注册 UID 反查回调(Android 侧 establish 前调用一次;可重复调用覆盖)。
// StartRouter 启动引擎时把它注入 TUN handler。
func SetUIDResolver(r UIDResolver) {
	uidResolver = r
	slog.Info("[Go-Bridge] SetUIDResolver called", "set", r != nil)
}

// Android→Go 反向桥已删除(2026-08,停 VPN 后图标赖着不掉排查):configReload 曾经
// AndroidBridge.Vpn("restart") 触发 Android 侧自动重启,但该异步重启循环存在竞态——
// 用户显式停止后仍可能在 delayed start 把隧道拉起,状态栏图标不消失。现改为 App 侧
// 显式重建(ACTION_RESTART,主线程原子停→建),Go 侧不再向 Android 发任何命令。

func StartRouter(configPath string, tunFd int, tunEnabled bool) error {
	slog.Info("[Go-Bridge] StartRouter called", "configPath", configPath, "tunFd", tunFd, "tunEnabled", tunEnabled)
	engineMu.Lock()
	defer engineMu.Unlock()

	// tunFd 经 detachFd 交给 Go 后,Kotlin 不再能关它;真正把 fd 交出去是
	// eng.Start 建 TUN 栈那一刻。此前的任何错误返回都必须由 Go 侧关闭,
	// 否则每次失败的 start 泄漏一个 tun fd(报告 P1#10)。
	closeFdOnErr := func(err error) error {
		if tunFd > 0 {
			unix.Close(tunFd)
		}
		return err
	}

	if globalEngine != nil {
		slog.Warn("[Go-Bridge] StartRouter failed: router is already running")
		return closeFdOnErr(fmt.Errorf("router is already running"))
	}

	// 从文件加载配置(与桌面端 config.Load 同路径):Kotlin 侧把最终 config 落到
	// filesDir/config.json 再传路径,引擎不再收 JSON 串;config.Load 会补默认值。
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("[Go-Bridge] StartRouter failed to load config", "error", err)
		return closeFdOnErr(fmt.Errorf("failed to load config: %w", err))
	}

	// 与桌面 main.go 一致:slog 输出同时进 logbuf.Default 环形缓冲,纯 Go 面板的
	// Logs 页(GET /logs)才能读到;否则 logbuf 恒空,面板显示 "No logs available"。
	// 包装会转发到 stdout(logcat GoLog tag 不受影响)。
	// Level=Debug:App 侧 Logcat 页要求"详细到调试级别",TUN 热路径的连接级日志
	// (NewConnectionEx 的 slog.Debug)也一并可见。
	slog.SetDefault(slog.New(logbuf.NewSlogHandlerLevel(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		logbuf.Default, slog.LevelDebug,
	)))

	// 服务模式(Android §8):tunEnabled=false = 仅代理(SOCKS5)——不建 TUN 隧道,只跑
	// 引擎 SOCKS5。config.json 的 listen.port 写死 1080 作 SOCKS5 文档占位(host "::"
	// 全接口双栈、auth 空 = 无鉴权,局域网可达——用户对仅代理模式的显式选择);但引擎
	// 只要 listen.port>0 就绑 SOCKS5、不分模式,所以 VPN 模式(tunEnabled)必须显式归零,
	// 隧道模式才不暴露无鉴权代理。老设备 config 缺省 port=0 时仅代理补 1080。
	// admin 不受影响:管理面板固定绑 ":AdminPort"(不读 Listen.Host)。
	cfg.TUN.Enabled = tunEnabled
	cfg.TUN.FileDescriptor = tunFd
	cfg.TUN.AutoRoute = false
	if tunEnabled {
		cfg.Listen.Port = 0
	} else if cfg.Listen.Port == 0 {
		cfg.Listen.Port = 1080
	}

	eng, err := engine.New(cfg, "")
	if err != nil {
		slog.Error("[Go-Bridge] StartRouter failed to create engine", "error", err)
		return closeFdOnErr(err)
	}

	// 注入 UID 反查回调(per-app「禁止联网」):Kotlin 侧 establish 前 setUIDResolver 注册,
	// TUN handler 按连接回问 Android 连接所属 UID,命中 config.tun.blocked_uids 即拦截。
	// nil(桌面端/未注册)= 功能关闭,不影响其它路径。
	if uidResolver != nil {
		res := uidResolver
		eng.SetUIDResolver(func(proto int32, localIP string, localPort int32, remoteIP string, remotePort int32) int32 {
			return res.ResolveUID(proto, localIP, localPort, remoteIP, remotePort)
		})
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
				Alias:    p.Alias,
				URL:      p.URL,
				UDPInTCP: p.UDPInTCP,
			})
		}

		oldChnFile, oldACLFile := cfg.Routing.ChnrouteFile, cfg.Routing.ACLFile
		cfg = newCfg
		eng.Config.Store(cfg)
		// TUN 模式必须同步热更:tunHandler 从自己的 config 指针读 SmartProxy 开关/端口,
		// 只 Store eng.Config 会让这些改动在 TUN 路径永不生效(仅 SOCKS5 生效)。
		eng.TUNHandler.ReloadConfig(cfg)
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
				// 把 fsnotify 重指向新路径并注册其目录,后续编辑新文件才触发热重载
				// (loop() 只在 Start 时建过内核 watch,不 ReplaceFile 新目录永远不报事件)。
				watcher.ReplaceFile("chnroute", cfg.Routing.ChnrouteFile)
				slog.Info("chnroute reloaded from new path", "path", cfg.Routing.ChnrouteFile)
			}
		}
		if cfg.Routing.ACLFile != oldACLFile {
			if err := eng.RuleEng.Reload(resolveFile(cfg.Routing.ACLFile)); err != nil {
				slog.Error("failed to reload ACL from new path", "path", cfg.Routing.ACLFile, "error", err)
			} else {
				aclPath = cfg.Routing.ACLFile // 闭包(SetACLReloader)按引用捕获,必须更新
				watcher.ReplaceFile("acl", cfg.Routing.ACLFile)
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

		// 隧道参数 / admin 端口证书不能热重载(establish 时固化),Android 侧不再自动
		// 重启(自动重启循环删除:用户停止后可能被 delayed start 拉起,图标赖着不掉)。
		// 这类变更经 App 首页 IPv4/IPv6 开关显式重建,或下次手动连接生效。
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
		// eng.Start 失败时 TUN 栈可能已部分建立也可能没有;fd 是否被接管不确定,
		// 保守起见不在这里补关(避免双关),交给引擎自身的清理路径。
		return err
	}

	// TUN 模式下 fd 已交给 gvisor 栈(TUN 栈持有并负责关闭);仅代理模式
	// (tunEnabled=false)没有 TUN 栈,fd 无人接管,成功路径也要关掉。
	if !tunEnabled {
		if tunFd > 0 {
			unix.Close(tunFd)
		}
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

// SetConnStatsEnabled 开关连接监控(「联网状态」页):页面打开采集、关闭即停。
// 不开页面引擎零开销;由联网状态页 onCreate/onDestroy 调用。
func SetConnStatsEnabled(enabled bool) {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalEngine == nil {
		return
	}
	globalEngine.SetConnStatsEnabled(enabled)
}

// GetConnectionStats 返回按 app(uid)分组的连接快照 JSON,供「联网状态」页每秒轮询。
// 引擎未运行返回 {"apps":[]}。
func GetConnectionStats() (string, error) {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalEngine == nil {
		return `{"apps":[]}`, nil
	}
	return globalEngine.ConnectionStats(), nil
}
