package config

import (
	"log/slog"
	"path/filepath"
	"sync"

	"smartproxy/internal/safego"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	mu     sync.Mutex
	files  map[string]string
	stopCh chan struct{}
	wg     sync.WaitGroup
	// addDirCh carries directory paths that must be registered with the kernel
	// fsnotify watch after Start (used by ReplaceFile when a reloaded config points
	// at a file in a new directory). Buffered so the send from a reload callback
	// (which runs on the loop goroutine) never blocks.
	addDirCh chan string

	onConfigReload   func()
	onACLReload      func()
	onChnRouteReload func()
}

func NewWatcher() *Watcher {
	return &Watcher{
		files:    make(map[string]string),
		stopCh:   make(chan struct{}),
		addDirCh: make(chan string, 8),
	}
}

func (w *Watcher) AddFile(name, path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	w.files[name] = absPath
}

// ReplaceFile re-points a watched file to a new path after Start and registers the new
// directory with fsnotify if it is not already watched. Used when a hot reload switches
// the ACL/chnroute file: without it, the new path would be in w.files but the kernel
// would never report events for its directory (the initial watch set is built once in
// loop()). Name must match the one passed to AddFile.
func (w *Watcher) ReplaceFile(name, path string) {
	w.AddFile(name, path)
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	select {
	case w.addDirCh <- filepath.Dir(absPath):
	default:
	}
}

func (w *Watcher) SetConfigReloader(fn func()) {
	w.onConfigReload = fn
}

func (w *Watcher) SetACLReloader(fn func()) {
	w.onACLReload = fn
}

func (w *Watcher) SetChnRouteReloader(fn func()) {
	w.onChnRouteReload = fn
}

func (w *Watcher) Start() {
	w.wg.Add(1)
	safego.Go("config.watcher.loop", w.loop)
}

func (w *Watcher) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *Watcher) loop() {
	defer w.wg.Done()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create fsnotify watcher", "error", err)
		return
	}
	defer watcher.Close()

	dirs := make(map[string]bool)
	w.mu.Lock()
	for _, path := range w.files {
		dir := filepath.Dir(path)
		if !dirs[dir] {
			if err := watcher.Add(dir); err != nil {
				slog.Error("failed to watch directory", "dir", dir, "error", err)
			} else {
				dirs[dir] = true
				slog.Debug("watching directory", "dir", dir)
			}
		}
	}
	w.mu.Unlock()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			w.mu.Lock()
			var nameMatched string
			for name, path := range w.files {
				if event.Name == path {
					nameMatched = name
					break
				}
			}
			w.mu.Unlock()

			if nameMatched != "" {
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					slog.Info("detected file change, reloading", "path", event.Name, "name", nameMatched)
					w.trigger(nameMatched)
				}
			}

		case dir := <-w.addDirCh:
			// dirs is loop-local: after Start's initial scan this goroutine is the only
			// reader/writer, so no lock is needed here.
			if dirs[dir] {
				continue
			}
			if err := watcher.Add(dir); err != nil {
				slog.Error("failed to watch new directory", "dir", dir, "error", err)
			} else {
				dirs[dir] = true
				slog.Info("now watching directory", "dir", dir)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Error("fsnotify error", "error", err)

		case <-w.stopCh:
			return
		}
	}
}

func (w *Watcher) trigger(name string) {
	switch name {
	case "config":
		if w.onConfigReload != nil {
			w.onConfigReload()
		}
	case "acl":
		if w.onACLReload != nil {
			w.onACLReload()
		}
	case "chnroute":
		if w.onChnRouteReload != nil {
			w.onChnRouteReload()
		}
	}
}
