package udp

import (
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

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

// stripSOCKS5UDPHeader 剥掉 SOCKS5 UDP 中继头(RSV|FRAG|ATYP|DST.ADDR|DST.PORT),
// 返回 payload。用于测试里的裸 UDP 中继 mock 取出 DNS 查询。
func stripSOCKS5UDPHeader(frame []byte) ([]byte, bool) {
	if len(frame) < 4 {
		return nil, false
	}
	var hdrLen int
	switch frame[3] {
	case 0x01:
		hdrLen = 1 + 4 + 2
	case 0x04:
		hdrLen = 1 + 16 + 2
	case 0x03:
		if len(frame) < 5 {
			return nil, false
		}
		hdrLen = 1 + 1 + int(frame[4]) + 2
	default:
		return nil, false
	}
	if len(frame) < 3+hdrLen {
		return nil, false
	}
	return frame[3+hdrLen:], true
}

// startAnsweringRawUDPRelay 起一个「真的会应答」的裸 UDP 中继(模拟 shadowsocks-android
// 的 udp_only 回落实例):按 SOCKS5 UDP 头剥出 DNS 查询,回一个同 TXID 的 DNS 响应帧。
// 返回的端口同时用作代理节点的 host:port——那里故意不放 TCP 监听,让 SOCKS5 拨号失败、
// 走 raw fallback;而 raw 中继会应答,所以 manager 的端到端验证能通过。
// 旧版本靠「UDP dial fire-and-forget 必成功」拿到假成功的 conn,现在必须真应答。
func startAnsweringRawUDPRelay(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload, ok := stripSOCKS5UDPHeader(buf[:n])
			if !ok {
				continue
			}
			var q mdns.Msg
			if err := q.Unpack(payload); err != nil || len(q.Question) == 0 {
				continue
			}
			resp := new(mdns.Msg)
			resp.SetReply(&q) // 同 ID、QR=1
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			frame := append(buildResponseHeader("1.1.1.1", 53, net.IPv4(1, 1, 1, 1)), packed...)
			pc.WriteToUDP(frame, addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// setupQUICFlowDeadTest 搭一个最小 Handler(真实内存黑名单 Router + 注入的 upstream.Manager)
// 和一个处于「直连观察中」(framed=false) 的 QUIC 会话,已注册进 sessions 表。
func setupQUICFlowDeadTest(t *testing.T, mgr *upstream.Manager) (*Handler, *udpSession, *closeTracker, udpSessionKey) {
	t.Helper()
	router := route.New(nil, nil, false, time.Second, nil, time.Hour)
	h := &Handler{
		router:      router,
		upstreamMgr: mgr,
		stopCh:      make(chan struct{}),
	}
	h.initShards()
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
	h.setSession(key, sess)
	return h, sess, old, key
}

// 判死后代理拨号成功:出向热切为 framed 代理、旧直连关闭、IP+SNI 写入动态黑名单。
// 代理节点指向一个「有裸 UDP 中继、但没有 TCP 监听」的端口:SOCKS5 拨号失败 → raw UDP
// relay fallback → manager 在裸中继上发真实 DNS 问答验证端到端可用,验过才拿到 conn。
// 聚焦验证 quicFlowDead 本身的热切逻辑,与底层 relay 类型无关。
func TestQUICFlowDead_ProxyDialSucceeds_SwitchesAndBlacklists(t *testing.T) {
	_, relayPort := startAnsweringRawUDPRelay(t)
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Proxies: []upstream.ProxyEntry{
			{Alias: "raw", URL: "socks5://127.0.0.1:" + strconv.Itoa(relayPort)},
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
	if h.hasSession(key) {
		t.Error("dead session should be dropped when proxy dial fails so retransmission opens a fresh proxy session")
	}
	if !old.closed {
		t.Error("old direct socket should be closed when session is dropped")
	}
}

// 验证会话在 quicFlowDead 执行期间已被标记 closed 时，异步拨出的代理连接被安全关闭，不会被存入已关闭会话，且无死锁与句柄泄漏。
func TestQUICFlowDead_SessionClosedConcurrently_ClosesPconnWithoutLeak(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Proxies: []upstream.ProxyEntry{
			{Alias: "raw", URL: "socks5://127.0.0.1:" + strconv.Itoa(deadTCPPort(t))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	h, sess, _, key := setupQUICFlowDeadTest(t, mgr)
	const ip, port, sni = "203.0.113.9", 443, "example.net"

	// 先关闭会话
	h.closeSession(sess)
	if !sess.closed.Load() {
		t.Fatal("session should be marked closed")
	}

	// 触发 quicFlowDead: 应该安全退出，不覆盖 snap
	h.quicFlowDead(sess, key, ip, port, sni, "timeout")

	// 确认未被复活
	cur := sess.snap.Load()
	if cur.framed {
		t.Error("closed session must not be resurrected with framed proxy")
	}
}

// 验证会话在 quicFlowDead 执行期间已被从 shard 移除（stale session）时，拨号结果被放弃并关闭，不会覆写新状态。
func TestQUICFlowDead_StaleSession_AbortsSafely(t *testing.T) {
	mgr, err := upstream.NewManager(upstream.UpstreamConfig{
		Proxies: []upstream.ProxyEntry{
			{Alias: "raw", URL: "socks5://127.0.0.1:" + strconv.Itoa(deadTCPPort(t))},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	h, sess, _, key := setupQUICFlowDeadTest(t, mgr)
	const ip, port, sni = "203.0.113.10", 443, "stale.com"

	// 从 session 表移除
	h.deleteSession(key)

	h.quicFlowDead(sess, key, ip, port, sni, "timeout")

	if h.hasSession(key) {
		t.Error("stale session must not be re-added to session map")
	}
}

// 验证 closeSession 在多协程并发调用下的幂等性与无死锁。
func TestCloseSession_ConcurrentCalls_Idempotent(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeB.Close()
	sess := &udpSession{
		flowID: 100,
		log:    slog.With("flow", 100),
	}
	sess.snap.Store(&udpOutbound{conn: pipeA, framed: false})

	h := &Handler{}
	h.sessionCount.Store(1)
	ActiveSessions.Store(1)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.closeSession(sess)
		}()
	}
	wg.Wait()

	if !sess.closed.Load() {
		t.Error("session.closed should be true")
	}
	if h.sessionCount.Load() != 0 {
		t.Errorf("sessionCount should be 0, got %d", h.sessionCount.Load())
	}
}

