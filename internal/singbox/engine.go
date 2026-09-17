package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

var (
	globalEngine     *Engine
	globalEngineOnce sync.Once
)

// GlobalEngine returns the global singleton sing-box outbound engine.
func GlobalEngine() *Engine {
	globalEngineOnce.Do(func() {
		globalEngine = NewEngine()
	})
	return globalEngine
}

// Engine manages an in-process sing-box instance with zero inbounds,
// purely serving as an Outbound dialer for SmartProxy.
type Engine struct {
	mu        sync.RWMutex
	instance  *box.Box
	outbounds map[string]json.RawMessage
}

// NewEngine creates a new Engine.
func NewEngine() *Engine {
	return &Engine{
		outbounds: make(map[string]json.RawMessage),
	}
}

// RegisterOutbound adds or replaces a single outbound by tag.
func (e *Engine) RegisterOutbound(tag string, rawJSON []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	old, exists := e.outbounds[tag]
	if exists && bytes.Equal(old, rawJSON) && e.instance != nil {
		return nil
	}
	e.outbounds[tag] = rawJSON
	if err := e.rebuildLocked(context.Background()); err != nil {
		if exists {
			e.outbounds[tag] = old
		} else {
			delete(e.outbounds, tag)
		}
		return err
	}
	return nil
}

// RegisterOutbounds registers multiple outbounds, optionally replacing existing ones.
func (e *Engine) RegisterOutbounds(outbounds []json.RawMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, raw := range outbounds {
		var meta struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &meta); err == nil && meta.Tag != "" {
			e.outbounds[meta.Tag] = raw
		}
	}
	return e.rebuildLocked(context.Background())
}

// UnregisterOutbound removes an outbound by tag.
func (e *Engine) UnregisterOutbound(tag string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.outbounds, tag)
	return e.rebuildLocked(context.Background())
}

// SetOutbounds replaces all registered outbounds with the given map.
func (e *Engine) SetOutbounds(outbounds map[string]json.RawMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.outbounds = make(map[string]json.RawMessage, len(outbounds))
	for k, v := range outbounds {
		e.outbounds[k] = v
	}
	return e.rebuildLocked(context.Background())
}

// SyncOutbounds reconciles registered outbounds to match the desired map.
// If the desired outbounds are identical to the currently running set, it returns immediately without rebuilding.
func (e *Engine) SyncOutbounds(desired map[string]json.RawMessage) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.outbounds) == len(desired) && e.instance != nil {
		identical := true
		for k, v := range desired {
			old, exists := e.outbounds[k]
			if !exists || !bytes.Equal(old, v) {
				identical = false
				break
			}
		}
		if identical {
			return nil
		}
	}

	e.outbounds = make(map[string]json.RawMessage, len(desired))
	for k, v := range desired {
		e.outbounds[k] = v
	}
	return e.rebuildLocked(context.Background())
}

func (e *Engine) rebuildLocked(ctx context.Context) error {
	var outboundList []json.RawMessage

	// Always provide a default direct outbound
	directOutbound := []byte(`{"type":"direct","tag":"direct"}`)
	outboundList = append(outboundList, directOutbound)

	for _, raw := range e.outbounds {
		outboundList = append(outboundList, raw)
	}

	cfg := map[string]any{
		"log": map[string]any{
			"level": "warn",
		},
		"outbounds": outboundList,
	}

	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal sing-box config: %w", err)
	}

	boxCtx := include.Context(ctx)
	var opts option.Options
	if err := opts.UnmarshalJSONContext(boxCtx, cfgBytes); err != nil {
		return fmt.Errorf("failed to parse sing-box options: %w", err)
	}

	newInstance, err := box.New(box.Options{
		Context: boxCtx,
		Options: opts,
	})
	if err != nil {
		return fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	oldInstance := e.instance
	e.instance = nil
	if oldInstance != nil {
		_ = oldInstance.Close()
	}

	if err := newInstance.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box instance: %w", err)
	}

	e.instance = newInstance
	slog.Debug("sing-box outbound engine rebuilt", "outbounds", len(e.outbounds))
	return nil
}

// GetOutbound retrieves an outbound by its tag.
func (e *Engine) GetOutbound(tag string) (adapter.Outbound, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.instance == nil {
		return nil, errors.New("sing-box engine not started")
	}

	outbound, ok := e.instance.Outbound().Outbound(tag)
	if !ok {
		return nil, fmt.Errorf("outbound %q not found in sing-box engine", tag)
	}
	return outbound, nil
}

// DialContext connects to destination through the outbound specified by tag.
func (e *Engine) DialContext(ctx context.Context, tag string, network string, destination string) (net.Conn, error) {
	outbound, err := e.GetOutbound(tag)
	if err != nil {
		return nil, err
	}

	dest := M.ParseSocksaddr(destination)
	return outbound.DialContext(ctx, network, dest)
}

// ListenPacket listens for packets for destination through the outbound specified by tag.
func (e *Engine) ListenPacket(ctx context.Context, tag string, destination string) (net.PacketConn, error) {
	outbound, err := e.GetOutbound(tag)
	if err != nil {
		return nil, err
	}

	dest := M.ParseSocksaddr(destination)
	return outbound.ListenPacket(ctx, dest)
}

// Close terminates the sing-box instance and releases resources.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.instance != nil {
		err := e.instance.Close()
		e.instance = nil
		return err
	}
	return nil
}
