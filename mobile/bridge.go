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

func StartRouter(configJson string, tunFd int) error {
	engineMu.Lock()
	defer engineMu.Unlock()

	if globalEngine != nil {
		return fmt.Errorf("router is already running")
	}

	var cfg config.Config
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg.TUN.Enabled = true
	cfg.TUN.FileDescriptor = tunFd
	cfg.TUN.AutoRoute = false

	eng, err := engine.New(&cfg, "")
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
	return nil
}

func StopRouter() {
	engineMu.Lock()
	defer engineMu.Unlock()
	if globalEngine != nil {
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
