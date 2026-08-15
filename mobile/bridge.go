package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"smartproxy/internal/config"
	"smartproxy/internal/engine"
	"smartproxy/internal/route"
)

var (
	globalEngine *engine.Engine
	engineMu     sync.Mutex
	cancelFunc   context.CancelFunc
)

// AndroidBridge 在 Kotlin 侧实现并于 App 启动时注册(M5,§4.4):
// admin 面板端点(/api/prefs、/api/vpn)经它回调 Android 运行时——读写
// SharedPreferences、启停 VPN。
//
// §5 应用内化后,应用枚举/图标已移入 App 内(不再经面板),故桥只保留偏好与启停。
// 仅用 string / bool,gobind 双向编组支持;接口必须在本 bound 包内。
// internal/admin 定义结构等价的未导出 interface(admin 不能 import mobile 防环),
// 由 StartRouter 把本接口实例赋给它(方法集相同,编译期检查)。
type AndroidBridge interface {
	GetPrefs() string
	SetPrefs(json string) string
	IsRunning() bool
	Vpn(action string) string
}

var (
	bridge   AndroidBridge
	bridgeMu sync.RWMutex
)

// SetAndroidBridge 注册 Kotlin 实现(Kotlin 线程设置,StartRouter/HTTP 线程读取,加锁)。
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

func StartRouter(configPath string, tunFd int) error {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalEngine != nil {
		return fmt.Errorf("router is already running")
	}

	// 从文件加载配置(与桌面端 config.Load 同路径):Kotlin 侧把最终 config 落到
	// filesDir/config.json 再传路径,引擎不再收 JSON 串;config.Load 会补默认值。
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg.TUN.Enabled = true
	cfg.TUN.FileDescriptor = tunFd
	cfg.TUN.AutoRoute = false

	eng, err := engine.New(cfg, "")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		return err
	}

	globalEngine = eng
	cancelFunc = cancel

	// M5:把 Kotlin 注册的 bridge 挂到 admin server,面板端点经它回调 Android。
	// admin server 在 eng.Start 内创建,此刻已可取得;admin 的结构 interface
	// 与本接口方法集相同,接口赋值编译期检查,无 any/断言。
	if srv := eng.AdminServer(); srv != nil {
		srv.SetAndroidBridge(currentBridge())
	}
	return nil
}

func StopRouter() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalEngine != nil {
		// 拆桥:引擎停止后 admin server 关闭,面板不可达;先摘 bridge 防悬空调用。
		if srv := globalEngine.AdminServer(); srv != nil {
			srv.SetAndroidBridge(nil)
		}
		cancelFunc()
		globalEngine.Stop()
		globalEngine = nil
		cancelFunc = nil
	}
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
