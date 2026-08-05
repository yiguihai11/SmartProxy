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

	onConfigReload   func()
	onACLReload      func()
	onChnRouteReload func()
}

func NewWatcher() *Watcher {
	return &Watcher{
		files:  make(map[string]string),
		stopCh: make(chan struct{}),
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
