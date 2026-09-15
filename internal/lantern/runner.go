package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Runner manages an in-process sing-box instance running compiled as a Go library.
type Runner struct {
	socksPort int
	instance  *box.Box
	mu        sync.Mutex
}

// NewRunner creates a new in-process sing-box runner.
func NewRunner(socksPort int) *Runner {
	if socksPort <= 0 {
		socksPort = 1080
	}
	return &Runner{
		socksPort: socksPort,
	}
}

// Start launches the in-process sing-box instance with the given nodes.
func (r *Runner) Start(ctx context.Context, nodes []json.RawMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.instance != nil {
		_ = r.instance.Close()
		r.instance = nil
	}

	cfgBytes, err := BuildCompleteSingBoxConfig(nodes, r.socksPort)
	if err != nil {
		return fmt.Errorf("failed to build sing-box config: %w", err)
	}

	boxCtx := include.Context(ctx)
	var opts option.Options
	if err := opts.UnmarshalJSONContext(boxCtx, cfgBytes); err != nil {
		return fmt.Errorf("failed to parse sing-box options: %w", err)
	}

	instance, err := box.New(box.Options{
		Context: boxCtx,
		Options: opts,
	})
	if err != nil {
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	r.instance = instance
	return nil
}

// UpdateNodes reloads the in-process sing-box instance with new nodes.
func (r *Runner) UpdateNodes(ctx context.Context, nodes []json.RawMessage) error {
	return r.Start(ctx, nodes)
}

// Close gracefully terminates the in-process sing-box instance.
func (r *Runner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.instance != nil {
		err := r.instance.Close()
		r.instance = nil
		return err
	}
	return nil
}
