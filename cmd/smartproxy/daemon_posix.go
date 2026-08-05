//go:build !windows

package main

import (
	"flag"
	"log"
	"os"

	"github.com/sevlyar/go-daemon"
)

var (
	runDaemon bool
	pidFile   string
	logFile   string
)

func registerDaemonFlags() {
	flag.BoolVar(&runDaemon, "daemon", false, "run as daemon")
	flag.StringVar(&pidFile, "pid", "", "pid file path (optional)")
	flag.StringVar(&logFile, "log", "", "log file path (optional)")
	flag.BoolVar(&quiet, "quiet", false, "suppress log output (daemon mode)")
}

func handleDaemon() {
	if !runDaemon {
		return
	}

	cntxt := &daemon.Context{
		WorkDir: "./",
		Umask:   027,
	}
	if pidFile != "" {
		cntxt.PidFileName = pidFile
		cntxt.PidFilePerm = 0644
	}
	if quiet && logFile == "" {
		cntxt.LogFileName = "/dev/null"
	} else if logFile != "" {
		cntxt.LogFileName = logFile
		cntxt.LogFilePerm = 0640
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatal("Unable to run: ", err)
	}
	if d != nil {
		// Reborn returns a non-nil *os.Process in the parent process. The parent's
		// job (spawning the daemon child) is done and it must exit: if it merely
		// returned, control would go back to main and continue starting the service,
		// so the parent would run in the foreground while the child exits due to a
		// port conflict (turning daemon mode into a race).
		os.Exit(0)
	}
	defer cntxt.Release()
}
