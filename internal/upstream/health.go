package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/safego"

	"smartproxy/internal/config"
)

type ProxyState int

const (
	StateClosed ProxyState = iota
	StateOpen
	StateHalfOpen
)

type ProxyHealth struct {
	mu                   sync.RWMutex
	state                ProxyState
	consecutiveFailures  int
	consecutiveSuccesses int
	lastAttempt          time.Time
	openSince            time.Time
	latency              time.Duration
}

func (ph *ProxyHealth) Latency() time.Duration {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	return ph.latency
}

func (ph *ProxyHealth) SetManualState(available bool) {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	if available {
		ph.state = StateClosed
		ph.consecutiveFailures = 0
	} else {
		ph.state = StateOpen
		ph.consecutiveFailures = 0
		ph.consecutiveSuccesses = 0
	}
}

func (ph *ProxyHealth) reset() {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	ph.state = StateClosed
	ph.consecutiveFailures = 0
	ph.consecutiveSuccesses = 0
	ph.lastAttempt = time.Time{}
	ph.openSince = time.Time{}
	ph.latency = 0
}

func (ph *ProxyHealth) IsAvailable() bool {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	if ph.state == StateClosed {
		return true
	}
	if ph.state == StateHalfOpen {
		return true
	}
	return false
}

type ProxyHealthSnapshot struct {
	State                string        `json:"state"`
	Available            bool          `json:"available"`
	Latency              time.Duration `json:"latency"`
	ConsecutiveFailures  int           `json:"consecutive_failures"`
	ConsecutiveSuccesses int           `json:"consecutive_successes"`
	LastAttempt          string        `json:"last_attempt,omitempty"`
	OpenSince            string        `json:"open_since,omitempty"`
}

func (ph *ProxyHealth) Snapshot() ProxyHealthSnapshot {
	ph.mu.RLock()
	defer ph.mu.RUnlock()
	state := "closed"
	if ph.state == StateOpen {
		state = "open"
	} else if ph.state == StateHalfOpen {
		state = "half_open"
	}
	s := ProxyHealthSnapshot{
		State:                state,
		Available:            ph.state != StateOpen,
		Latency:              ph.latency,
		ConsecutiveFailures:  ph.consecutiveFailures,
		ConsecutiveSuccesses: ph.consecutiveSuccesses,
	}
	if !ph.lastAttempt.IsZero() {
		s.LastAttempt = ph.lastAttempt.Format(time.RFC3339)
	}
	if !ph.openSince.IsZero() {
		s.OpenSince = ph.openSince.Format(time.RFC3339)
	}
	return s
}

type HealthChecker struct {
	cfg     atomic.Pointer[config.HealthCheckConf]
	proxies []*Proxy
	stopCh  chan struct{}
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewHealthChecker(cfg config.HealthCheckConf, proxies []*Proxy) *HealthChecker {
	ctx, cancel := context.WithCancel(context.Background())
	hc := &HealthChecker{
		proxies: proxies,
		stopCh:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
	hc.cfg.Store(&cfg)
	return hc
}

func (hc *HealthChecker) Start() {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	if cfg.AutoDisableSingle && len(hc.proxies) <= 1 {
		slog.Info("health check disabled: only one upstream proxy")
		return
	}

	for _, p := range hc.proxies {
		hc.wg.Add(1)
		safego.Go("upstream.health.checkLoop", func() { hc.checkLoop(p) })
	}
}

func (hc *HealthChecker) Stop() {
	hc.cancel()
	close(hc.stopCh)
	hc.wg.Wait()
}

func (hc *HealthChecker) Reload(cfg config.HealthCheckConf, proxies []*Proxy) {
	hc.Stop()
	hc.cfg.Store(&cfg)
	hc.proxies = proxies
	hc.stopCh = make(chan struct{})
	hc.ctx, hc.cancel = context.WithCancel(context.Background())
	hc.Start()
}

func (hc *HealthChecker) checkLoop(p *Proxy) {
	defer hc.wg.Done()

	select {
	case <-time.After(time.Duration(time.Now().UnixNano()%2000) * time.Millisecond):
	case <-hc.stopCh:
		return
	}

	for {
		cfg := hc.cfg.Load()
		interval := time.Duration(cfg.Interval) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}

		hc.checkProxy(p)

		select {
		case <-time.After(interval):
		case <-hc.stopCh:
			return
		}
	}
}

func (hc *HealthChecker) checkProxy(p *Proxy) {
	// udp_only upstreams have no TCP listener: the TCP HTTP probe would always fail and
	// open the circuit, killing their UDP relay. Skip them entirely; UDP liveness is
	// handled at relay time by UDPAssociate and the pool's probe.
	if p.IsUDPOnly() {
		return
	}
	cfg := hc.cfg.Load()

	p.health.mu.RLock()
	state := p.health.state
	openSince := p.health.openSince
	p.health.mu.RUnlock()

	if state == StateOpen {
		if time.Since(openSince) < time.Duration(cfg.OpenCoolDown)*time.Second {
			return
		}
	}

	ctx, cancel := context.WithTimeout(hc.ctx, time.Duration(cfg.Timeout)*time.Second)
	defer cancel()

	start := time.Now()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port := 80
			if p := parsePort(portStr); p > 0 {
				port = p
			}
			return p.Connect(ctx, host, port)
		},
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", cfg.URL, nil)
	var success bool
	var doErr error
	if err == nil {
		resp, err := client.Do(req)
		doErr = err
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				success = true
			} else {
				doErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			}
		}
	} else {
		doErr = err
	}

	latency := time.Since(start)

	if success {
		hc.RecordSuccess(p, latency)
	} else {
		hc.RecordFailure(p, doErr)
	}
}

func (hc *HealthChecker) RecordSuccess(p *Proxy, latency time.Duration) {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	ph := &p.health
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.lastAttempt = time.Now()
	if latency > 0 {
		if ph.latency == 0 {
			ph.latency = latency
		} else {

			ph.latency = (ph.latency*3 + latency) / 4
		}
	}

	switch ph.state {
	case StateClosed:
		ph.consecutiveFailures = 0
	case StateOpen:

	case StateHalfOpen:
		ph.consecutiveSuccesses++
		if ph.consecutiveSuccesses >= cfg.SuccessesThreshold {
			ph.state = StateClosed
			ph.consecutiveFailures = 0
			ph.consecutiveSuccesses = 0
			slog.Info("proxy recovered", "url", p.URL, "latency", latency)
		}
	}
}

func (hc *HealthChecker) RecordFailure(p *Proxy, err error) {
	cfg := hc.cfg.Load()
	if !cfg.Enabled {
		return
	}
	ph := &p.health
	ph.mu.Lock()
	defer ph.mu.Unlock()

	ph.lastAttempt = time.Now()

	switch ph.state {
	case StateClosed:
		ph.consecutiveFailures++
		if ph.consecutiveFailures >= cfg.FailuresThreshold {
			ph.state = StateOpen
			ph.openSince = time.Now()
			slog.Warn("proxy circuit opened", "url", p.URL, "failures", ph.consecutiveFailures, "error", err)
		}
	case StateOpen:
		if time.Since(ph.openSince) >= time.Duration(cfg.OpenCoolDown)*time.Second {
			ph.state = StateHalfOpen
			ph.consecutiveSuccesses = 0
			ph.consecutiveFailures = 0
			slog.Info("proxy circuit half-open", "url", p.URL)
		}
	case StateHalfOpen:
		ph.state = StateOpen
		ph.openSince = time.Now()
		ph.consecutiveSuccesses = 0
		slog.Warn("proxy circuit re-opened", "url", p.URL, "error", err)
	}
}
