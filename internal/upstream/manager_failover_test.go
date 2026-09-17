package upstream

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// startHangListener 接受 TCP 连接后什么都不发(模拟握手阶段被黑洞/半死节点),
// 直到连接被对端关闭或 listener 关闭。
func startHangListener(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				// 阻塞读;对冲赢家产生后 attemptCtx 取消会关掉连接,这里立刻解除阻塞。
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

// startClosedListener 占住一个端口后立刻关掉:拨它立即 connection refused,
// 模拟快速失败的死节点。
func startClosedListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// newFailoverManager 构造关掉健康探测的管理器。serverCleanups 必须排在 m.Stop
// 之后执行(t.Cleanup 是 LIFO):挂死 listener 的 wg.Wait 要等 m.Stop 取消 geo
// 探测上下文、对端连接关闭后才能返回,顺序反了每个测试白等 8s 探测超时。
func newFailoverManager(t *testing.T, urls []string, serverCleanups ...func()) *Manager {
	t.Helper()
	for _, c := range serverCleanups {
		t.Cleanup(c)
	}
	entries := make([]ProxyEntry, len(urls))
	for i, u := range urls {
		entries[i] = ProxyEntry{Alias: string(rune('a'+i)) + "node", URL: u}
	}
	m, err := NewManager(UpstreamConfig{
		Proxies:     entries,
		HealthCheck: config.HealthCheckConf{Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Stop)
	// 测试里把对冲节奏压到毫秒级,不等线上默认的 1.5s。
	m.dialHedgeDelay = 50 * time.Millisecond
	m.dialAttemptTimeout = 3 * time.Second
	return m
}

// TestConnectDefault_HedgedFailover 回归 v2ex 案例:首个节点 SYN/握手被挂住满 10s,
// 旧实现串行 failover 让用户干等。对冲拨号必须在 hedgeDelay 后并发拨备节点并快速胜出。
func TestConnectDefault_HedgedFailover(t *testing.T) {
	hangAddr, hangDone := startHangListener(t)
	goodAddr, goodDone := startSOCKS5Mock(t)

	m := newFailoverManager(t, []string{
		"socks5://" + hangAddr,
		"socks5://" + goodAddr,
	}, hangDone, goodDone)

	start := time.Now()
	conn, err := m.ConnectDefault(context.Background(), "example.com", 443)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected hedged failover to succeed, got %v", err)
	}
	defer conn.Close()
	if elapsed >= time.Second {
		t.Errorf("failover took %v, hedge should win in ~%v", elapsed, m.dialHedgeDelay)
	}
}

// TestConnectDefault_AllDeadBounded 全部节点都死时,总耗时必须被 attemptTimeout+
// 错位窗口兜住(两个节点最坏 ~350ms),绝不允许退回每个节点 10s 的串行等待。
func TestConnectDefault_AllDeadBounded(t *testing.T) {
	hangA, doneA := startHangListener(t)
	hangB, doneB := startHangListener(t)

	m := newFailoverManager(t, []string{
		"socks5://" + hangA,
		"socks5://" + hangB,
	}, doneA, doneB)
	m.dialAttemptTimeout = 300 * time.Millisecond

	start := time.Now()
	_, err := m.ConnectDefault(context.Background(), "example.com", 443)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error when all upstreams are dead")
	}
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("all-dead failover took %v, want < 1.5s", elapsed)
	}
}

// TestConnectDefault_FastFailureSkipsHedgeWindow 前一个节点快速拒连时,备胎必须
// 立刻启动,不能傻等下一个 hedge 窗口。
func TestConnectDefault_FastFailureSkipsHedgeWindow(t *testing.T) {
	goodAddr, goodDone := startSOCKS5Mock(t)

	m := newFailoverManager(t, []string{
		"socks5://" + startClosedListener(t),
		"socks5://" + startClosedListener(t),
		"socks5://" + goodAddr,
	}, goodDone)
	// hedge 窗口故意设得很长:备胎提前启动只能走"在途全挂立即拨下一个"的路径。
	m.dialHedgeDelay = 10 * time.Second

	start := time.Now()
	conn, err := m.ConnectDefault(context.Background(), "example.com", 443)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected failover through two refused nodes to succeed, got %v", err)
	}
	defer conn.Close()
	if elapsed >= 500*time.Millisecond {
		t.Errorf("fast-fail chain took %v, refused nodes should skip the hedge window", elapsed)
	}
}

// TestConnectDefault_DeadAttemptsFeedBreaker 等待结果期间真实失败的拨号必须喂熔断器:
// FailuresThreshold=1 时,两个死节点各超时一次后都应跳闸,后续选路直接跳过它们。
func TestConnectDefault_DeadAttemptsFeedBreaker(t *testing.T) {
	hangA, doneA := startHangListener(t)
	hangB, doneB := startHangListener(t)
	t.Cleanup(doneA)
	t.Cleanup(doneB)

	entries := []ProxyEntry{
		{Alias: "dead-a", URL: "socks5://" + hangA},
		{Alias: "dead-b", URL: "socks5://" + hangB},
	}
	m, err := NewManager(UpstreamConfig{
		Proxies: entries,
		HealthCheck: config.HealthCheckConf{
			Enabled: true, FailuresThreshold: 1, SuccessesThreshold: 1, Timeout: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 停掉后台探测,避免它抢先改动熔断器状态;Stop 会把首次探测闸门全部放行。
	// 这里不挂 t.Cleanup(m.Stop):listener 清理已先注册,LIFO 下 Stop 先执行。
	m.healthChecker.Stop()
	for _, p := range m.defaultProxies {
		p.health.ResetFailures()
	}
	t.Cleanup(m.Stop)
	m.dialHedgeDelay = 50 * time.Millisecond
	m.dialAttemptTimeout = 300 * time.Millisecond

	if _, err := m.ConnectDefault(context.Background(), "example.com", 443); err == nil {
		t.Fatal("expected all-dead error")
	}
	for _, p := range m.defaultProxies {
		if state := p.health.Snapshot().State; state != "open" {
			t.Errorf("proxy %s breaker state=%s, want open after a dead dial", p.Name, state)
		}
	}
}

// TestConnectDefault_SingleNodeKeepsLegacyTimeout 单节点没有备胎,不应用对冲和更紧的
// 5s 单次预算,保持历史的 10s 容忍(慢目标 CONNECT 也可能成立)。
func TestConnectDefault_SingleNodeKeepsLegacyTimeout(t *testing.T) {
	goodAddr, goodDone := startSOCKS5Mock(t)

	m := newFailoverManager(t, []string{"socks5://" + goodAddr}, goodDone)
	m.dialAttemptTimeout = 100 * time.Millisecond // 单节点路径不得使用这个值

	conn, err := m.ConnectDefault(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatalf("single healthy node should connect, got %v", err)
	}
	conn.Close()
}
