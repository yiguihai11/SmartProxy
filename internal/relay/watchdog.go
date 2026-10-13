package relay

import (
	"errors"
	"fmt"
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

// DisarmThresholdBytes is the amount of response data from the remote server required
// to prove a direct TCP connection healthy and disarm the watchdog (default 300 bytes).
const DisarmThresholdBytes int64 = 300

func formatThreshold(bytes int64) string {
	if bytes >= 1024 && bytes%1024 == 0 {
		return fmt.Sprintf("%dKB", bytes/1024)
	}
	return fmt.Sprintf("%dB", bytes)
}

// StallCallback is invoked when a watchdog detects a silent drop / GFW stall or early reset.
type StallCallback func(host string, port int, domain, reason string)

// WatchdogConfig configures the early-stage connection watchdog.
type WatchdogConfig struct {
	Timeout time.Duration
	Host    string
	Port    int
	Domain  string
	OnStall StallCallback
	// RSTGraceWindow bounds how long after a response an RST is still attributed
	// to GFW (an injected reset can arrive a few hundred ms after a partial
	// response, once inFlight has already cleared). Zero defaults to 3s.
	RSTGraceWindow time.Duration
}

// RelayOption configures optional behavior on TCPRelay.
type RelayOption func(*relayOptions)

type relayOptions struct {
	watchdog         *WatchdogConfig
	halfCloseTimeout time.Duration
}

// WithWatchdog enables the early-stage watchdog on direct connections to detect
// GFW silent drops / blackholes and early resets.
func WithWatchdog(cfg WatchdogConfig) RelayOption {
	return func(o *relayOptions) {
		o.watchdog = &cfg
	}
}

// WithHalfCloseTimeout sets the grace period allowed for the remaining direction to
// finish after one direction has completed.
func WithHalfCloseTimeout(timeout time.Duration) RelayOption {
	return func(o *relayOptions) {
		o.halfCloseTimeout = timeout
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
	roundTrips    atomic.Int32 // counts completed request-response round trips
	triggerOnce   sync.Once

	// lastInFlight is the unix-nano timestamp of the most recent moment a request
	// was in flight (set on request Write, refreshed when the response starts).
	lastInFlight atomic.Int64
}

func newWatchdogConn(client, remote net.Conn, cfg WatchdogConfig) *watchdogConn {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.RSTGraceWindow <= 0 {
		cfg.RSTGraceWindow = 3 * time.Second
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
		w.lastInFlight.Store(time.Now().UnixNano())
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
		// Refresh lastInFlight first: an injected RST landing just after a partial
		// response must still fall inside the RST grace window.
		wasInFlight := w.inFlight.Swap(false)
		if wasInFlight {
			w.roundTrips.Add(1)
		}
		w.lastInFlight.Store(time.Now().UnixNano())
		w.stopTimer()

		total := w.totalRemote.Add(int64(n))
		// If total response data exceeds DisarmThresholdBytes (300B), stream is proven healthy and fully disarmed.
		if total > DisarmThresholdBytes {
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
				// If remote has ALREADY returned response data (e.g. 237B HTTP 304, 444B ip.sb),
				// the connection is proven reachable and healthy. A timeout on a subsequent
				// client write is simply an unacknowledged control frame (e.g. HTTP/2 SETTINGS
				// ACK 188B, WINDOW_UPDATE) or keep-alive packet where the server does not reply.
				// We MUST disarm instead of falsely accusing GFW of silent dropping!
				if w.totalRemote.Load() > 0 || w.roundTrips.Load() > 0 {
					w.disarm()
					return
				}

				remoteBytes := w.totalRemote.Load()
				threshStr := formatThreshold(DisarmThresholdBytes)
				var reason, cause string
				if remoteBytes == 0 {
					reason = fmt.Sprintf("gfw_silent_drop_watchdog (timeout %v, 0B received)", w.cfg.Timeout)
					cause = fmt.Sprintf("in-flight request timed out after %v with 0 bytes received from remote (complete GFW silent drop)", w.cfg.Timeout)
				} else {
					reason = fmt.Sprintf("gfw_silent_drop_watchdog (timeout %v, %dB received < %s threshold)", w.cfg.Timeout, remoteBytes, threshStr)
					cause = fmt.Sprintf("in-flight request timed out after %v: remote returned %d bytes (< %s disarm threshold %d B), subsequent response stalled", w.cfg.Timeout, remoteBytes, threshStr, DisarmThresholdBytes)
				}
				w.trigger(reason, cause)
			}
		})
	} else {
		w.timer.Stop()
		w.timer.Reset(d)
	}
}

func (w *watchdogConn) trigger(reason, cause string) {
	w.triggerOnce.Do(func() {
		w.state.Store(int32(watchdogTriggered))
		w.stopTimer()

		remoteBytes := w.totalRemote.Load()
		slog.Warn("watchdog detected GFW stall/abort on direct connection",
			"reason", reason,
			"cause", cause,
			"host", w.cfg.Host,
			"port", w.cfg.Port,
			"domain", w.cfg.Domain,
			"remote_bytes", remoteBytes,
			"disarm_threshold_bytes", DisarmThresholdBytes,
			"round_trips", w.roundTrips.Load(),
			"client_written", w.clientWritten.Load(),
			"in_flight", w.inFlight.Load(),
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
		// Require a real request before attributing the reset. An RST on a
		// connection that never sent anything (refused pre-connect, server
		// dropping an idle socket) is an ordinary network event.
		if !w.clientWritten.Load() {
			slog.Debug("ignoring RST on connection with no request sent", "error", err)
			return
		}
		remoteBytes := w.totalRemote.Load()
		threshStr := formatThreshold(DisarmThresholdBytes)
		if w.inFlight.Load() {
			cause := fmt.Sprintf("remote connection reset/aborted (%v) while request was in-flight (%d bytes received from remote)", err, remoteBytes)
			reason := fmt.Sprintf("gfw_rst_injected (%v while request in-flight, %dB received)", err, remoteBytes)
			w.trigger(reason, cause)
			return
		}
		if w.recentlyInFlight() {
			cause := fmt.Sprintf("remote connection reset/aborted (%v) within %v grace window after receiving %d bytes (< %s threshold)", err, w.cfg.RSTGraceWindow, remoteBytes, threshStr)
			reason := fmt.Sprintf("gfw_rst_injected (%v within %v grace window, %dB received)", err, w.cfg.RSTGraceWindow, remoteBytes)
			w.trigger(reason, cause)
			return
		}
		// Outside both, this is a keep-alive / load-balancer close during idle — do not learn it.
		slog.Debug("ignoring RST during idle (no request recently in flight)",
			"error", err, "grace", w.cfg.RSTGraceWindow)
	}
}

// recentlyInFlight reports whether a request was awaiting (or had just started
// receiving a response) within the configured RST grace window.
func (w *watchdogConn) recentlyInFlight() bool {
	last := w.lastInFlight.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) <= w.cfg.RSTGraceWindow
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
	// If client is half-closing the write stream, client has finished sending data.
	// If remote already delivered response data or completed a round-trip, this was
	// a successful exchange; disarm watchdog to prevent trailing timeouts on teardown.
	if w.totalRemote.Load() > 0 || w.roundTrips.Load() > 0 {
		w.disarm()
	}
	if cw, ok := w.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (w *watchdogConn) CloseRead() error {
	w.stopTimer()
	if cr, ok := w.Conn.(closeReader); ok {
		return cr.CloseRead()
	}
	return nil
}
