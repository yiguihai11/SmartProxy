package route

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/safego"

	"smartproxy/internal/chnroute"
	"smartproxy/internal/fwmark"
	"smartproxy/internal/rules"
	"smartproxy/internal/upstream"
)

type routerConfig struct {
	smartTimeout time.Duration
	blacklistTTL time.Duration
}

type Router struct {
	cfg         atomic.Pointer[routerConfig]
	chnroute    *chnroute.Trie
	upstreamMgr *upstream.Manager

	domainBlacklist *Blacklist
	ipBlacklist     *Blacklist

	cleanupStopCh chan struct{}
	cleanupWg     sync.WaitGroup
}

func New(cn *chnroute.Trie, mgr *upstream.Manager,
	_ bool, smartTimeout time.Duration,
	_ []int, blacklistTTL time.Duration) *Router {

	r := &Router{
		chnroute:        cn,
		upstreamMgr:     mgr,
		domainBlacklist: NewBlacklist("domain"),
		ipBlacklist:     NewBlacklist("ip"),
	}
	r.cfg.Store(&routerConfig{
		smartTimeout: smartTimeout,
		blacklistTTL: blacklistTTL,
	})
	return r
}

func (r *Router) UpdateConfig(smartTimeout, blacklistTTL time.Duration) {
	r.cfg.Store(&routerConfig{
		smartTimeout: smartTimeout,
		blacklistTTL: blacklistTTL,
	})
	slog.Info("router config updated", "smartTimeout", smartTimeout, "blacklistTTL", blacklistTTL)
}

func (r *Router) IsDomestic(ip string) bool {
	addr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return false
	}
	return r.chnroute.Contains(addr.IP)
}

func (r *Router) IsDomesticByIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		return r.chnroute.Contains(ip)
	}
	return false
}

func (r *Router) isDomesticHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return r.chnroute.Contains(ip)
	}
	return false
}

func (r *Router) EstablishConnection(ctx context.Context, host string, port int,
	domain string, engine *rules.Engine) (net.Conn, bool, error) {

	result, selected := r.upstreamMgr.SelectProxy(host, port, domain, engine)
	switch {
	case result == "direct":
		slog.Info("proxy rule forces direct connection", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, 10*time.Second)
		return conn, false, err
	case result != "fallback":
		slog.Info("using proxy alias from rule", "url", selected.URL, "host", host, "port", port, "domain", domain)
		conn, err := selected.Connect(ctx, host, port)
		return conn, true, err
	}

	if r.isDomesticHost(host) {
		slog.Info("using direct connection (domestic)", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, 10*time.Second)
		return conn, false, err
	}

	slog.Info("using upstream proxy (non-smart)", "host", host, "port", port, "domain", domain)
	conn, status := r.upstreamMgr.Connect(ctx, host, port, domain, engine)
	if status != "proxy" {
		return nil, false, errors.New("failed to connect via upstream")
	}
	return conn, true, nil
}

func simplifyError(err error, host string, port int) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "i/o timeout"
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection reset by peer") {
		return "connection reset by peer"
	}
	if strings.Contains(errStr, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(errStr, "no route to host") {
		return "no route to host"
	}
	if strings.Contains(errStr, "network is unreachable") {
		return "network unreachable"
	}
	if strings.Contains(errStr, "host is down") {
		return "host is down"
	}
	prefix := fmt.Sprintf("dial tcp %s:%d: ", host, port)
	if strings.HasPrefix(errStr, prefix) {
		return strings.TrimPrefix(errStr, prefix)
	}
	readPrefix := fmt.Sprintf("read tcp %s:%d->%s:%d: ", host, port, host, port)
	if strings.HasPrefix(errStr, readPrefix) {
		return strings.TrimPrefix(errStr, readPrefix)
	}
	if idx := strings.Index(errStr, ": "); idx != -1 {
		return errStr[idx+2:]
	}
	return errStr
}

// SmartConnectWithFallback returns (connection, r2c prefix, isProxy, error). The prefix only
// carries the first response byte already read when the smart-direct connection verification
// succeeds: relay replays it before continuing to splice, avoiding a wrapping connection that
// would break zero-copy.
func (r *Router) SmartConnectWithFallback(ctx context.Context, host string, port int,
	domain string, firstPkt []byte, engine *rules.Engine) (net.Conn, []byte, bool, error) {

	cfg := r.cfg.Load()

	result, selected := r.upstreamMgr.SelectProxy(host, port, domain, engine)
	switch {
	case result == "direct":
		slog.Info("proxy rule forces direct connection", "host", host, "port", port, "domain", domain)
		conn, err := dialTCP(ctx, host, port, cfg.smartTimeout)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, false, nil
	case result != "fallback":
		slog.Info("using proxy alias from rule", "url", selected.URL, "host", host, "port", port, "domain", domain)
		conn, err := selected.Connect(ctx, host, port)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, true, nil
	}

	if (domain != "" && r.domainBlacklist.IsBlacklisted(domain, port)) || r.ipBlacklist.IsBlacklisted(host, port) {
		slog.Info("dynamic blacklist matched, using proxy directly", "host", host, "port", port, "domain", domain)
		conn, err := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if err != nil {
			return nil, nil, false, err
		}
		if _, err := conn.Write(firstPkt); err != nil {
			conn.Close()
			return nil, nil, false, err
		}
		return conn, nil, true, nil
	}

	slog.Info("attempting smart proxy direct connection", "host", host, "port", port, "domain", domain, "timeout", cfg.smartTimeout)
	conn, err := dialTCP(ctx, host, port, cfg.smartTimeout)
	if err != nil {
		shortReason := simplifyError(err, host, port)
		slog.Warn("direct connection failed, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
		r.addToBlacklists(host, port, domain, shortReason)

		proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if pErr != nil {
			return nil, nil, false, fmt.Errorf("direct failed (%v) and proxy fallback failed (%v)", err, pErr)
		}
		if _, err := proxyConn.Write(firstPkt); err != nil {
			proxyConn.Close()
			return nil, nil, false, err
		}
		return proxyConn, nil, true, nil
	}

	if _, err := conn.Write(firstPkt); err != nil {
		conn.Close()
		shortReason := simplifyError(err, host, port)
		slog.Warn("direct connection failed after write, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
		r.addToBlacklists(host, port, domain, shortReason)

		proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if pErr != nil {
			return nil, nil, false, fmt.Errorf("direct write failed (%v) and proxy fallback failed (%v)", err, pErr)
		}
		if _, err := proxyConn.Write(firstPkt); err != nil {
			proxyConn.Close()
			return nil, nil, false, err
		}
		return proxyConn, nil, true, nil
	}

	conn.SetReadDeadline(time.Now().Add(cfg.smartTimeout))
	oneByte := make([]byte, 1)
	_, readErr := io.ReadFull(conn, oneByte)
	conn.SetReadDeadline(time.Time{})

	if readErr != nil {
		conn.Close()
		shortReason := simplifyError(readErr, host, port)
		slog.Warn("direct connection failed on read verify, falling back to proxy", "host", host, "port", port, "domain", domain, "reason", shortReason)
		r.addToBlacklists(host, port, domain, shortReason)

		proxyConn, pErr := r.upstreamMgr.ConnectDefault(ctx, host, port)
		if pErr != nil {
			return nil, nil, false, fmt.Errorf("direct read failed (%v) and proxy fallback failed (%v)", readErr, pErr)
		}
		if _, err := proxyConn.Write(firstPkt); err != nil {
			proxyConn.Close()
			return nil, nil, false, err
		}
		return proxyConn, nil, true, nil
	}

	slog.Info("direct connection successfully verified, keeping direct", "host", host, "port", port, "domain", domain)
	// Return the raw connection plus the first byte already read, which relay replays before
	// splicing, avoiding a prefixedConn that would break zero-copy.
	return conn, oneByte, false, nil
}
func (r *Router) addToBlacklists(host string, port int, domain, reason string) {
	cfg := r.cfg.Load()

	r.ipBlacklist.Add(host, port, cfg.blacklistTTL, reason)

	if domain != "" {
		r.domainBlacklist.Add(domain, port, cfg.blacklistTTL, reason)
	}
}

func (r *Router) BlacklistSnapshot() (ipEntries, domainEntries []BlacklistEntry) {
	return r.ipBlacklist.Entries(), r.domainBlacklist.Entries()
}

func (r *Router) RemoveFromBlacklist(host string, port int, typ string) {
	switch typ {
	case "ip":
		r.ipBlacklist.Remove(host, port)
	case "domain":
		r.domainBlacklist.Remove(host, port)
	default:
		r.ipBlacklist.Remove(host, port)
		r.domainBlacklist.Remove(host, port)
	}
}

func (r *Router) StartCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	r.cleanupStopCh = make(chan struct{})
	r.cleanupWg.Add(1)
	safego.Go("route.router.cleanup", func() {
		defer r.cleanupWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.domainBlacklist.cleanExpired()
				r.ipBlacklist.cleanExpired()
			case <-r.cleanupStopCh:
				slog.Debug("cleanup goroutine stopped")
				return
			}
		}
	})
}

func (r *Router) StopCleanup() {
	if r.cleanupStopCh != nil {
		close(r.cleanupStopCh)
	}
	r.cleanupWg.Wait()
}

func dialTCP(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout, Control: fwmark.Control}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	// Align with proxy connections (upstream/proxy.go dial): direct connections also disable
	// Nagle and enable KeepAlive to reduce small-packet latency.
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	return conn, nil
}
