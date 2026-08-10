package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/engine"
	"smartproxy/internal/logbuf"
	"smartproxy/internal/upstream"
	"smartproxy/internal/version"
)

var logger *slog.Logger

// quiet is a cross-platform shared variable: the -quiet flag is registered in
// daemon_posix.go, and main.go references it globally.
// It cannot be declared only in daemon_posix.go (!windows build tag), otherwise
// Windows builds would fail with undefined.
var quiet bool

type colorWriter struct {
	out   *os.File
	plain bool
}

func (cw *colorWriter) Write(p []byte) (int, error) {
	if cw.plain {
		return cw.out.Write(p)
	}
	s := string(p)
	s = strings.ReplaceAll(s, "level=DEBUG", "level=\033[36mDEBUG\033[0m")
	s = strings.ReplaceAll(s, "level=INFO", "level=\033[32mINFO\033[0m")
	s = strings.ReplaceAll(s, "level=WARN", "level=\033[33mWARN\033[0m")
	s = strings.ReplaceAll(s, "level=ERROR", "level=\033[31mERROR\033[0m")
	return cw.out.Write([]byte(s))
}

func newLogger(level string) *slog.Logger {
	return newNamedLogger(level, false)
}

func newNamedLogger(level string, quiet bool) *slog.Logger {
	var lvl slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "INFO":
		lvl = slog.LevelInfo
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	shanghaiLoc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		slog.Warn("failed to load Asia/Shanghai timezone, falling back to UTC", "error", err)
		shanghaiLoc = time.UTC
	}

	var baseHandler slog.Handler
	if !quiet {
		fi, _ := os.Stdout.Stat()
		isTerm := fi != nil && (fi.Mode()&os.ModeCharDevice) != 0
		baseHandler = slog.NewTextHandler(&colorWriter{out: os.Stdout, plain: !isTerm}, &slog.HandlerOptions{
			Level: lvl,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					t := a.Value.Time().In(shanghaiLoc)
					return slog.Attr{Key: slog.TimeKey, Value: slog.StringValue(t.Format("2006-01-02 15:04:05"))}
				}
				return a
			},
		})
	}
	return slog.New(logbuf.NewSlogHandlerLevel(baseHandler, logbuf.Default, lvl))
}

func setupLogger(level string, quiet bool) *slog.Logger {
	return newNamedLogger(level, quiet)
}

func setLogLevel(level string) {
	logger = newNamedLogger(level, quiet)
	slog.SetDefault(logger)
}

func main() {
	var cfgPath string
	var showVersion bool

	registerDaemonFlags()
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.StringVar(&cfgPath, "config", "config.json", "path to config file")
	flag.Parse()
	if showVersion {
		fmt.Println(version.String())
		return
	}
	handleDaemon()

	logger = setupLogger("INFO", quiet)
	slog.SetDefault(logger)
	slog.Info("smartproxy starting", "version", version.Version, "commit", version.GitCommit, "built", version.BuildTime)

	if flag.NArg() > 0 && cfgPath == "config.json" {
		cfgPath = flag.Arg(0)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "error", err)
		os.Exit(1)
	}
	setLogLevel(cfg.LogLevel)

	cfgDir := filepath.Dir(cfgPath)

	eng, err := engine.New(cfg, cfgDir)
	if err != nil {
		slog.Error("failed to create engine", "error", err)
		os.Exit(1)
	}

	aclPath := cfg.Routing.ACLFile
	watcher := config.NewWatcher()
	watcher.AddFile("config", cfgPath)
	watcher.AddFile("acl", aclPath)
	watcher.AddFile("chnroute", cfg.Routing.ChnrouteFile)
	configReload := func() {
		newCfg, err := config.Load(cfgPath)
		if err != nil {
			slog.Error("failed to reload config", "path", cfgPath, "error", err)
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

		oldChnFile, oldACLFile := cfg.Routing.ChnrouteFile, cfg.Routing.ACLFile
		cfg = newCfg
		eng.Config.Store(cfg)
		setLogLevel(cfg.LogLevel)
		eng.UpstreamMgr.Reload(upstreamCfg)

		// Hot-reload chnroute / ACL when their paths change, so that choosing a
		// file and saving takes effect immediately.
		resolveFile := func(p string) string {
			if filepath.IsAbs(p) {
				return p
			}
			return filepath.Join(cfgDir, p)
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

		slog.Info("config reloaded")
	}
	watcher.SetConfigReloader(configReload)
	eng.SetReloadFn(configReload)
	eng.SetConfigPath(cfgPath)

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := eng.Start(ctx); err != nil {
		slog.Error("failed to start engine", "error", err)
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh
	slog.Info("shutting down...")
	cancel()
	eng.Stop()
	slog.Info("server stopped")
}
