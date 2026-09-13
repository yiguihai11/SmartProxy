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

	"smartproxy/internal/config"
	"smartproxy/internal/engine"
	"smartproxy/internal/logbuf"
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
	return slog.New(logbuf.NewSlogHandlerLevel(baseHandler, logbuf.Default, lvl).WithLocation(shanghaiLoc))
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

	watcher := config.NewWatcher()
	watcher.AddFile("config", cfgPath)
	watcher.AddFile("acl", cfg.Routing.ACLFile)
	watcher.AddFile("chnroute", cfg.Routing.ChnrouteFile)
	configReload := func() {
		newCfg, err := config.Load(cfgPath)
		if err != nil {
			slog.Error("failed to reload config", "path", cfgPath, "error", err)
			return
		}
		oldCfg := eng.Config.Load()
		if err := eng.ReloadConfig(newCfg, cfgDir); err != nil {
			slog.Error("failed to apply config reload", "error", err)
			return
		}
		setLogLevel(newCfg.LogLevel)
		if oldCfg != nil {
			if newCfg.Routing.ACLFile != oldCfg.Routing.ACLFile {
				watcher.ReplaceFile("acl", newCfg.Routing.ACLFile)
			}
			if newCfg.Routing.ChnrouteFile != oldCfg.Routing.ChnrouteFile {
				watcher.ReplaceFile("chnroute", newCfg.Routing.ChnrouteFile)
			}
		}
		slog.Info("config reloaded")
	}
	watcher.SetConfigReloader(configReload)
	eng.SetReloadFn(configReload)
	eng.SetConfigPath(cfgPath)

	watcher.SetACLReloader(func() {
		if err := eng.ReloadACL(); err != nil {
			slog.Error("failed to reload ACL", "error", err)
		} else {
			slog.Info("ACL rules reloaded")
		}
	})
	watcher.SetChnRouteReloader(func() {
		if err := eng.ReloadChnroute(); err != nil {
			slog.Error("failed to reload chnroute", "error", err)
		} else {
			slog.Info("chnroute reloaded")
		}
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
