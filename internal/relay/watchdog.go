package relay

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"smartproxy/internal/netutil"
)

// StallCallback is invoked when a watchdog detects a silent drop / GFW stall or early reset.
type StallCallback func(host string, port int, domain, reason string)

// WatchdogConfig configures the early-stage connection watchdog.
type WatchdogConfig struct {
	Timeout time.Duration
	Host    string
	Port    int
	Domain  string
	OnStall StallCallback
}

// RelayOption configures optional behavior on TCPRelay.
type RelayOption func(*relayOptions)

type relayOptions struct {
	watchdog *WatchdogConfig
}

// WithWatchdog enables the early-stage watchdog on direct connections to detect
// GFW silent drops / blackholes and early resets.
func WithWatchdog(cfg WatchdogConfig) RelayOption {
	return func(o *relayOptions) {
		o.watchdog = &cfg
	}
}

type watchdogState int32

const (
	watchdogArmed watchdogState = iota
	watchdogDisarmed
	watchdogTriggered
)

// watchdogConn wraps the direct remote connection to monitor early data transfer.
// If the connection stalls (e.g. GFW blackhole silent drop) or encounters an early RST,
// it triggers the OnStall callback (recording to dynamic blacklist) and forcefully resets
// the client connection with TCP RST, preventing the client from hanging for 90+ seconds.
type watchdogConn struct {
	net.Conn
	client net.Conn
	cfg    WatchdogConfig
	state  atomic.Int32

	timer   *time.Timer
	timerMu sync.Mutex

	inFlight      atomic.Bool // true only while a client request is awaiting remote response
	clientWritten atomic.Bool
	totalRemote   atomic.Int64
	triggerOnce   sync.Once
}

func newWatchdogConn(client, remote net.Conn, cfg WatchdogConfig) *watchdogConn {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	w := &watchdogConn{
		Conn:   remote,
		client: client,
		cfg:    cfg,
	}
	w.state.Store(int32(watchdogArmed))
	// Do NOT unconditionally start the timer on creation. An established connection
	// sitting idle (e.g. Keep-Alive connection pool, speculative pre-connect) is NOT
	// a stall. The timer is armed only when client writes request data awaiting a response.
	return w
}

func (w *watchdogConn) Write(p []byte) (int, error) {
	if len(p) > 0 && w.state.Load() == int32(watchdogArmed) {
		w.clientWritten.Store(true)
		w.inFlight.Store(true)
		// Arm or reset the watchdog timer before writing, so that an immediate
		// remote response (e.g. on fast links or pipes) does not race with inFlight.
		w.armTimer(w.cfg.Timeout)
	}
	n, err := w.Conn.Write(p)
	if err != nil {
		w.inFlight.Store(false)
		w.stopTimer()
		w.handleError("write", err)
		return n, err
	}
	return n, nil
}

func (w *watchdogConn) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if err != nil {
		w.handleError("read", err)
		return n, err
	}
	if n > 0 && w.state.Load() == int32(watchdogArmed) {
		// Remote returned response data! Cancel the watchdog timer immediately.
		w.inFlight.Store(false)
		w.stopTimer()

		total := w.totalRemote.Add(int64(n))
		// If total response data exceeds 8KB, stream is proven healthy and fully disarmed.
		if total > 8*1024 {
			w.disarm()
		}
	}
	return n, nil
}

func (w *watchdogConn) disarm() {
	if w.state.CompareAndSwap(int32(watchdogArmed), int32(watchdogDisarmed)) {
		w.inFlight.Store(false)
		w.stopTimer()
	}
}

func (w *watchdogConn) stopTimer() {
	w.timerMu.Lock()
	defer w.timerMu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
	}
}

func (w *watchdogConn) armTimer(d time.Duration) {
	w.timerMu.Lock()
	defer w.timerMu.Unlock()
	if w.state.Load() != int32(watchdogArmed) {
		return
	}
	if w.timer == nil {
		w.timer = time.AfterFunc(d, func() {
			if w.inFlight.Load() {
				w.trigger("gfw_silent_drop_watchdog")
			}
		})
	} else {
		w.timer.Stop()
		w.timer.Reset(d)
	}
}

func (w *watchdogConn) trigger(reason string) {
	w.triggerOnce.Do(func() {
		w.state.Store(int32(watchdogTriggered))
		w.stopTimer()

		slog.Warn("watchdog detected GFW stall/abort on direct connection",
			"reason", reason,
			"host", w.cfg.Host,
			"port", w.cfg.Port,
			"domain", w.cfg.Domain,
			"remote_bytes", w.totalRemote.Load(),
			"client_written", w.clientWritten.Load(),
			"timeout", w.cfg.Timeout,
		)

		if w.cfg.OnStall != nil {
			w.cfg.OnStall(w.cfg.Host, w.cfg.Port, w.cfg.Domain, reason)
		}

		// Forcefully reset the client connection with TCP RST so modern browsers/curl/git
		// immediately abort the hung connection and retry (hitting dynamic blacklist -> proxy),
		// instead of spinning for 90 seconds.
		if w.client != nil {
			netutil.ResetConn(w.client)
		}
		if w.Conn != nil {
			netutil.ResetConn(w.Conn)
		}
	})
}

func (w *watchdogConn) handleError(direction string, err error) {
	if err == nil || err == io.EOF || errors.Is(err, net.ErrClosed) {
		return
	}
	if w.state.Load() != int32(watchdogArmed) {
		return
	}
	if isGFWAbort(err) {
		w.trigger("gfw_rst_injected")
	}
}

func isGFWAbort(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection refused")
}

// UnderlyingConn allows netutil.ResetConn to unwrap the real *net.TCPConn and apply tcp.SetLinger(0).
func (w *watchdogConn) UnderlyingConn() net.Conn {
	return w.Conn
}

func (w *watchdogConn) Close() error {
	w.stopTimer()
	return w.Conn.Close()
}

func (w *watchdogConn) CloseWrite() error {
	if cw, ok := w.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (w *watchdogConn) CloseRead() error {
	if cr, ok := w.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return nil
}
