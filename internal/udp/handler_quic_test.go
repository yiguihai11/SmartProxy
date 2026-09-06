package udp

import (
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"smartproxy/internal/route"
	"smartproxy/internal/upstream"
)

// closeTracker 包一个 net.Conn 并记录 Close 是否被调用,用来断言 QUIC 判死热切 / 丢会话时
// 旧直连 socket 被拆除(不留死直连)。quicFlowDead 在调用 goroutine 内同步 Close,无并发。
type closeTracker struct {
	net.Conn
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return c.Conn.Close()
}

// deadTCPPort 返回一个当前无人监听的 loopback TCP 端口。
func deadTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// setupQUICFlowDeadTest 搭一个最小 Handler(真实内存黑名单 Router + 注入的 upstream.Manager)
// 和一个处于「直连观察中」(framed=false) 的 QUIC 会话,已注册进 sessions 表。
func setupQUICFlowDeadTest(t *testing.T, mgr *upstream.Manager) (*Handler, *udpSession, *closeTracker, udpSessionKey) {
	t.Helper()
	router := route.New(nil, nil, false, time.Second, nil, time.Hour)
	h := &Handler{
		router:      router,
		upstreamMgr: mgr,
		sessions:    make(map[udpSessionKey]*udpSession),
		stopCh:      make(chan struct{}),
	}
	pipeA, pipeB := net.Pipe()
	t.Cleanup(func() { pipeA.Close(); pipeB.Close() })
	old := &closeTracker{Conn: pipeA}
	key := udpSessionKey{targetIP: "203.0.113.7", targetPort: 443}
	sess := &udpSession{
		flowID:     42,
		log:        slog.With("flow", 42),
		key:        key,
		timeout:    time.Minute,
		clientAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
	}
	sess.snap.Store(&udpOutbound{conn: old, framed: false})
	h.sessions[key] = sess
	return h, sess, old, key
}

// 判死后代理拨号成功:出向热切为 framed 代理、旧直连关闭、IP+SNI 写入动态黑名单。
// 代理节点指向一个无人监听的 TCP 端口 —— SOCKS5 握手失败后 raw UDP relay fallback
// (UDP dial fire-and-forget 必成功),据此拿到一个非 nil 代理 conn,聚焦验证 quicFlowDead
// 本身的热切逻辑,与底层 relay 类型无关。
func TestQUICFlowDead_ProxyDialSucceeds_SwitchesAndBlacklists(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Proxies: []upstream.ProxyEntry{
			{Alias: "raw", URL: "socks5://127.0.0.1:" + strconv.Itoa(deadTCPPort(t))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	h, sess, old, key := setupQUICFlowDeadTest(t, mgr)
	const ip, port, sni = "203.0.113.7", 443, "example.com"

	h.quicFlowDead(sess, key, ip, port, sni, "timeout")

	if !h.router.IsIPBlacklisted(ip, port) {
		t.Error("IP should be on dynamic blacklist after QUIC judged dead")
	}
	if !h.router.IsDomainBlacklisted(sni, port) {
		t.Error("SNI domain should be on dynamic blacklist after QUIC judged dead")
	}
	if cur := sess.snap.Load(); !cur.framed {
		t.Error("session outbound should switch to framed proxy after dead verdict")
	}
	if !old.closed {
		t.Error("old direct socket should be closed after switching to proxy")
	}
}

// 判死后代理拨号失败(无可用 UDP 上游):不留死直连 —— 会话被 drop(下次客户端重传会因
// 动态黑名单建新会话直接走代理),旧直连关闭;黑名单在拨号之前已写入,仍然生效。
func TestQUICFlowDead_ProxyDialFails_DropsSessionAndBlacklists(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{}) // 只有 direct,无 UDP 代理
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	h, sess, old, key := setupQUICFlowDeadTest(t, mgr)
	const ip, port, sni = "203.0.113.8", 443, "example.org"

	h.quicFlowDead(sess, key, ip, port, sni, "retransmit")

	if !h.router.IsIPBlacklisted(ip, port) {
		t.Error("IP must be blacklisted before dial, so it stays blacklisted even when proxy dial fails")
	}
	h.sessionsMu.RLock()
	_, present := h.sessions[key]
	h.sessionsMu.RUnlock()
	if present {
		t.Error("dead session should be dropped when proxy dial fails so retransmission opens a fresh proxy session")
	}
	if !old.closed {
		t.Error("old direct socket should be closed when session is dropped")
	}
}
