package tun

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"smartproxy/internal/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isPipeClosed 用「过去截止时间 + Read」探测 net.Pipe 一端是否已关:
// 已关 → 立即返回 io.ErrClosedPipe;未关 → 截止超时(os.ErrDeadlineExceeded)。
func isPipeClosed(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	var b [1]byte
	_, err := c.Read(b[:])
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// newKillHandler 搭最小 TUNHandler:规则引擎 + 连接监控 + 活跃注册表。
func newKillHandler(t *testing.T, acl string) *TUNHandler {
	t.Helper()
	re, err := rules.New(acl)
	require.NoError(t, err)
	h := &TUNHandler{ruleEng: re}
	h.connStats = NewConnStats()
	h.liveTCP = newLiveTCP(h.connStats)
	return h
}

// ── 注册表 ─────────────────────────────────────────────────────────────────

func TestLiveTCP_AddRemoveSnapshot(t *testing.T) {
	cs := NewConnStats()
	lt := newLiveTCP(cs)

	app1, remote1 := net.Pipe()
	hd1 := lt.add(app1, "1.2.3.4", 443, nil)
	hd1.setRemote(remote1)
	app2, remote2 := net.Pipe()
	hd2 := lt.add(app2, "9.9.9.9", 80, nil)
	hd2.setRemote(remote2)

	snap := lt.snapshot()
	require.Len(t, snap, 2)

	lt.remove(hd1)
	assert.Len(t, lt.snapshot(), 1)
	lt.remove(hd2)
	assert.Empty(t, lt.snapshot())

	// remove 幂等:relay 返回的 defer 与 kill 后的立即注销可能重复调。
	lt.remove(hd1)
	assert.Empty(t, lt.snapshot())
}

func TestLiveTCP_ConcurrentAddRemoveSnapshot(t *testing.T) {
	cs := NewConnStats()
	lt := newLiveTCP(cs)

	app0, _ := net.Pipe()
	seed := lt.add(app0, "1.2.3.4", 443, nil)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _ := net.Pipe()
			hd := lt.add(a, "1.2.3.4", 443, nil)
			lt.snapshot()
			lt.remove(hd)
		}()
	}
	// 并发快照读(与 add/remove 交错)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				lt.snapshot()
			}
		}
	}()

	wg.Wait()
	close(stop)
	lt.remove(seed)
	assert.Empty(t, lt.snapshot())
}

// ── KillBlockedConnections ─────────────────────────────────────────────────

func TestKillBlockedConnections_HitAndMiss(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	require.NoError(t, os.WriteFile(acl, []byte(
		"block ip 1.2.3.4\n"+
			"block domain blocked.example\n"), 0o644))
	h := newKillHandler(t, acl)

	// 命中 IP 封禁:host 未回填,ip 被 block ip 命中。
	appA, remoteA := net.Pipe()
	hdA := h.liveTCP.add(appA, "1.2.3.4", 443, nil)
	hdA.setRemote(remoteA)

	// 命中域名封禁:host 回填被 block domain 命中(ip 未封)。
	appB, remoteB := net.Pipe()
	hdB := h.liveTCP.add(appB, "9.9.9.9", 443, nil)
	hdB.setHost("blocked.example")
	hdB.setRemote(remoteB)

	// 域名未封但 IP 命中:host 非空仍按 IP 兜底掐断。
	appD, remoteD := net.Pipe()
	hdD := h.liveTCP.add(appD, "1.2.3.4", 80, nil)
	hdD.setHost("allowed.example")
	hdD.setRemote(remoteD)

	// 未命中:host 未回填(按 IP 匹配),ip 未封。
	appC, remoteC := net.Pipe()
	hdC := h.liveTCP.add(appC, "8.8.8.8", 443, nil)
	hdC.setRemote(remoteC)

	h.KillBlockedConnections()

	assert.True(t, isPipeClosed(remoteA), "IP 命中应被掐断")
	assert.True(t, isPipeClosed(remoteB), "域名命中应被掐断")
	assert.True(t, isPipeClosed(remoteD), "域名未封但 IP 命中应被掐断")
	assert.False(t, isPipeClosed(remoteC), "未命中不应被掐断")
	assert.True(t, isPipeClosed(appA), "被掐断连接的应用侧也应关闭")
	assert.False(t, isPipeClosed(appC), "未命中连接的应用侧应保持打开")

	// 被掐断的句柄已立即注销,只剩未命中的 C。
	left := h.liveTCP.snapshot()
	require.Len(t, left, 1)
	assert.True(t, left[0] == hdC)
}

func TestKillBlockedConnections_AfterRuleChange(t *testing.T) {
	dir := t.TempDir()
	acl1 := filepath.Join(dir, "acl1.txt")
	acl2 := filepath.Join(dir, "acl2.txt")
	// acl1 只封无关的 1.1.1.1:证明注册/扫描当时 1.2.3.4 与 blocked.example 未封锁。
	require.NoError(t, os.WriteFile(acl1, []byte("block ip 1.1.1.1\n"), 0o644))
	require.NoError(t, os.WriteFile(acl2, []byte(
		"block ip 1.1.1.1\nblock ip 1.2.3.4\nblock domain blocked.example\n"), 0o644))
	h := newKillHandler(t, acl1)

	appA, remoteA := net.Pipe()
	hdA := h.liveTCP.add(appA, "1.2.3.4", 443, nil)
	hdA.setRemote(remoteA)
	appB, remoteB := net.Pipe()
	hdB := h.liveTCP.add(appB, "9.9.9.9", 443, nil)
	hdB.setHost("blocked.example")
	hdB.setRemote(remoteB)

	// 规则变更前扫描:均未封锁 → 不掐。
	h.KillBlockedConnections()
	assert.False(t, isPipeClosed(remoteA), "1.2.3.4 当时未封锁,不应掐")
	assert.False(t, isPipeClosed(remoteB), "blocked.example 当时未封锁,不应掐")
	assert.Len(t, h.liveTCP.snapshot(), 2)

	// ACL 变更(Reload 新文件)→ 再扫描 → 新增封锁的命中即掐。
	require.NoError(t, h.ruleEng.Reload(acl2))
	h.KillBlockedConnections()
	assert.True(t, isPipeClosed(remoteA), "规则变更后 1.2.3.4 应被掐断")
	assert.True(t, isPipeClosed(remoteB), "规则变更后 blocked.example 应被掐断")
	assert.True(t, isPipeClosed(appA))
	assert.True(t, isPipeClosed(appB))
	assert.Empty(t, h.liveTCP.snapshot(), "掐断后句柄应从注册表移除")
}

// TestKillBlockedConnections_KillDuringSetRemote_RaceFree 压 setRemote/setHost(连接
// goroutine)与 kill(ACL reloader goroutine)并发:host/remote 是 atomic,此测试在
// -race 下跑必须零告警。
func TestKillBlockedConnections_KillDuringSetRemote_RaceFree(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	require.NoError(t, os.WriteFile(acl, []byte("block ip 1.2.3.4\n"), 0o644))
	h := newKillHandler(t, acl)

	const conns = 20
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		app, remote := net.Pipe()
		hd := h.liveTCP.add(app, "1.2.3.4", 443, nil) // ip 恒命中封锁
		wg.Add(1)
		go func(hd *tcpHandle, remote net.Conn) {
			defer wg.Done()
			// 与主 goroutine 的 kill 并发写 host/remote(kill 在读)。
			for j := 0; j < 50; j++ {
				hd.setRemote(remote)
				hd.setHost("blocked.example")
			}
		}(hd, remote)
	}

	// 主 goroutine 反复扫描掐断,与 setRemote/setHost 交错。
	for i := 0; i < 50; i++ {
		h.KillBlockedConnections()
	}
	wg.Wait()
}

func TestKillBlockedConnections_UDP(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	require.NoError(t, os.WriteFile(acl, []byte("block ip 5.6.7.8\n"), 0o644))
	h := newKillHandler(t, acl)

	sessHit := &tunUdpSession{closeCh: make(chan struct{}), ip: "5.6.7.8"}
	sessOK := &tunUdpSession{closeCh: make(chan struct{}), ip: "9.9.9.9"}
	h.udpSessions.Store("hit", sessHit)
	h.udpSessions.Store("ok", sessOK)

	h.KillBlockedConnections()

	select {
	case <-sessHit.closeCh:
	default:
		t.Fatal("命中封禁 IP 的 UDP 会话应被 signalClose")
	}
	select {
	case <-sessOK.closeCh:
		t.Fatal("未命中封禁的 UDP 会话不应被关闭")
	default:
	}
}
