package tun

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── fakes ──────────────────────────────────────────────────────────────────

type fakeNetConn struct {
	readN    int
	readErr  error
	writeN   int
	writeErr error
}

func (c *fakeNetConn) Read(p []byte) (int, error)         { return c.readN, c.readErr }
func (c *fakeNetConn) Write(p []byte) (int, error)        { return c.writeN, c.writeErr }
func (c *fakeNetConn) Close() error                       { return nil }
func (c *fakeNetConn) LocalAddr() net.Addr                { return nil }
func (c *fakeNetConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeNetConn) SetWriteDeadline(t time.Time) error { return nil }

// fakePacketConn 只实现 ReadPacket/WritePacket:countingPacketConn 只调这两个,
// 内嵌 nil N.PacketConn 满足接口即可。
type fakePacketConn struct {
	N.PacketConn
	readPayload []byte
	writeErr    error
}

func (c *fakePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	buffer.Write(c.readPayload)
	return M.Socksaddr{}, nil
}

func (c *fakePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.writeErr
}

// ── 快照解析 ───────────────────────────────────────────────────────────────

type snapApp struct {
	UID   int32         `json:"uid"`
	Up    int64         `json:"up"`
	Down  int64         `json:"down"`
	Conns []snapConnRec `json:"conns"`
}
type snapConnRec struct {
	Proto int32  `json:"proto"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
}

func parseSnapshot(t *testing.T, s string) []snapApp {
	t.Helper()
	var out struct {
		Apps []snapApp `json:"apps"`
	}
	require.NoError(t, json.Unmarshal([]byte(s), &out))
	return out.Apps
}

// ── tests ─────────────────────────────────────────────────────────────────

func TestConnStatsDisabled_NoRecord(t *testing.T) {
	cs := NewConnStats()
	assert.False(t, cs.Enabled())
	// 关闭时数据路径必须零开销:begin 返回 nil,不建记录。
	assert.Nil(t, cs.begin(10123, 6, "1.2.3.4", 443))
	assert.Equal(t, `{"apps":[]}`, cs.Snapshot())
}

func TestConnStatsTCP_DirectionsAndHost(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	rec := cs.begin(10123, 6, "9.9.9.9", 443)
	require.NotNil(t, rec)

	wrapped := cs.wrapTCP(&fakeNetConn{readN: 100, writeN: 200}, rec)
	rbuf := make([]byte, 512)
	n, err := wrapped.Read(rbuf)
	require.NoError(t, err)
	assert.Equal(t, 100, n) // app→remote = 上行
	n, err = wrapped.Write(rbuf)
	require.NoError(t, err)
	assert.Equal(t, 200, n) // remote→app = 下行

	// 未回填 host 时快照显示 IP
	apps := parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1)
	assert.Equal(t, int32(10123), apps[0].UID)
	require.Len(t, apps[0].Conns, 1)
	c := apps[0].Conns[0]
	assert.Equal(t, int32(6), c.Proto)
	assert.Equal(t, "9.9.9.9", c.Host)
	assert.Equal(t, 443, c.Port)
	assert.Equal(t, int64(100), c.Up)
	assert.Equal(t, int64(200), c.Down)

	// smart 路径回填域名后,快照显示域名;app 级总量含存活连接。
	cs.setHost(rec, "example.com")
	apps = parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1)
	assert.Equal(t, "example.com", apps[0].Conns[0].Host)
	assert.Equal(t, int64(100), apps[0].Up)
	assert.Equal(t, int64(200), apps[0].Down)
}

func TestConnStatsUDP_Directions(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	rec := cs.begin(10123, 17, "8.8.8.8", 53)
	require.NotNil(t, rec)

	pc := &fakePacketConn{readPayload: []byte("abcdef")}
	wrapped := cs.wrapUDP(pc, rec)

	// ReadPacket(app 发)= 上行;fake 往 buffer 写 6 字节。
	b := buf.New()
	_, err := wrapped.ReadPacket(b)
	require.NoError(t, err)
	assert.Equal(t, int64(6), rec.up.Load())

	// WritePacket(回给 app)= 下行。
	b2 := buf.New()
	_, err = b2.Write([]byte("hi"))
	require.NoError(t, err)
	require.NoError(t, wrapped.WritePacket(b2, M.Socksaddr{}))

	apps := parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1)
	require.Len(t, apps[0].Conns, 1)
	c := apps[0].Conns[0]
	assert.Equal(t, int32(17), c.Proto)
	assert.Equal(t, int64(6), c.Up)
	assert.Equal(t, int64(2), c.Down)
}

func TestConnStatsIdleRemoval_FoldsBytes(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	// 同一 app 两条连接:一条 idle 超时、一条仍活跃 → idle 字节并入 app 累计,app 继续显示。
	recIdle := cs.begin(10123, 6, "1.2.3.4", 80)
	recLive := cs.begin(10123, 6, "1.2.3.5", 81)
	idleW := cs.wrapTCP(&fakeNetConn{readN: 50}, recIdle)
	liveW := cs.wrapTCP(&fakeNetConn{readN: 100}, recLive)
	rbuf := make([]byte, 512)
	idleW.Read(rbuf) // 上行 50
	liveW.Read(rbuf) // 上行 100

	recIdle.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())
	apps := parseSnapshot(t, cs.Snapshot())

	require.Len(t, apps, 1)
	require.Len(t, apps[0].Conns, 1, "idle 连接应被移除,存活连接保留")
	assert.Equal(t, "1.2.3.5", apps[0].Conns[0].Host)
	assert.Equal(t, int64(150), apps[0].Up, "idle 连接字节并入 app 累计")

	// 最后一条存活连接也 idle → 该 app 无活动,整个从快照消失。
	recLive.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())
	apps = parseSnapshot(t, cs.Snapshot())
	assert.Empty(t, apps, "全部连接 idle 后 app 不应再显示")
}

func TestConnStatsEviction_CapsAtMax(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	// 塞满到上限,lastSeen 全为 now。
	for i := 0; i < connStatsMaxRecords; i++ {
		cs.begin(int32(1000+i%7), 6, "1.2.3.4", 80)
	}

	// 塞满后再登记一条最旧的(5 秒前),随后新连接触发淘汰 → 应逐出最旧那条,而非新增。
	oldRec := cs.begin(9999, 6, "1.2.3.4", 80)
	oldRec.lastSeen.Store(time.Now().Add(-5 * time.Second).Unix())
	_ = cs.begin(1000, 6, "5.6.7.8", 443)

	cs.mu.Lock()
	total := cs.total
	cs.mu.Unlock()
	assert.Equal(t, connStatsMaxRecords, total, "表满后新连接应逐出最旧的")

	// 最旧记录已被逐出:任何 uid 的连接列表里都不再有它。
	cs.mu.Lock()
	found := false
	for _, us := range cs.byUID {
		us.mu.Lock()
		for _, r := range us.conns {
			if r == oldRec {
				found = true
			}
		}
		us.mu.Unlock()
	}
	cs.mu.Unlock()
	assert.False(t, found, "lastSeen 最旧的连接应被逐出")

	// 快照仍可解析;全部连接新鲜,不会被 idle 清扫。
	apps := parseSnapshot(t, cs.Snapshot())
	totalConns := 0
	for _, a := range apps {
		totalConns += len(a.Conns)
		var liveUp int64
		for _, c := range a.Conns {
			liveUp += c.Up
		}
		assert.LessOrEqual(t, liveUp, a.Up, "app 总量应 ≥ 存活连接之和(含淘汰累计)")
	}
	assert.Equal(t, connStatsMaxRecords, totalConns)
}

func TestConnStatsEvictLiveConn_NoDoubleCount(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	// 目标连接 rec(uid 10123)+ 同 uid 另一条保壳(逐出空壳时 uidStats 不删,
	// Remove 才有累计可并入)。
	rec := cs.begin(10123, 6, "1.2.3.4", 443)
	require.NotNil(t, rec)
	_ = cs.begin(10123, 6, "1.2.3.9", 443)

	wrapped := cs.wrapTCP(&fakeNetConn{readN: 100}, rec)
	rbuf := make([]byte, 512)
	n, err := wrapped.Read(rbuf)
	require.NoError(t, err)
	assert.Equal(t, 100, n)
	assert.Equal(t, int64(100), rec.up.Load())

	// Read 会刷新 rec.lastSeen(countingConn 里记 now),所以反查必须放在读之后,
	// 才能让 rec 成为全表最旧 → 表满时必先被逐出。
	rec.lastSeen.Store(time.Now().Add(-100 * time.Second).Unix())

	// 填满表到上限,再 begin 一条触发逐出 → 逐出 rec。
	for i := 0; i < connStatsMaxRecords-2; i++ {
		cs.begin(int32(2000+i%7), 6, "1.2.3.4", 80)
	}
	_ = cs.begin(9999, 6, "5.6.7.8", 443)

	assert.True(t, rec.evicted.Load(), "最旧的活跃连接应被逐出")
	cs.mu.Lock()
	us := cs.byUID[10123]
	require.NotNil(t, us, "同 uid 有保壳连接,uidStats 不应被删")
	us.mu.Lock()
	// rec 已出表,只剩保壳连接。
	foundRec := false
	for _, r := range us.conns {
		if r == rec {
			foundRec = true
		}
	}
	us.mu.Unlock()
	cs.mu.Unlock()
	assert.False(t, foundRec, "逐出后 rec 不应再出现在连接列表")
	// 逐出时已把当时字节(100)并入累计。
	assert.Equal(t, int64(100), us.up.Load())
	assert.Equal(t, int64(100), rec.evictUp.Load())

	// 逐出后连接继续跑:再读 200 字节,rec.up 到 300。
	n, err = wrapped.Read(rbuf)
	require.NoError(t, err)
	assert.Equal(t, 100, n)
	_, _ = wrapped.Read(rbuf) // 第二次读,累计到 300
	assert.Equal(t, int64(300), rec.up.Load())

	// 连接关闭:Remove 只补并入 evict 之后的增量(300-100=200)→ 累计 100+200=300,
	// 不把 evict 前字节二次计入(若双计会是 400)。
	cs.Remove(rec)
	assert.Equal(t, int64(300), us.up.Load())

	var app *snapApp
	for _, a := range parseSnapshot(t, cs.Snapshot()) {
		if a.UID == 10123 {
			app = &a
		}
	}
	require.NotNil(t, app, "快照里应有 uid 10123")
	assert.Equal(t, int64(300), app.Up, "每字节恰好计入一次:100(evict 时)+ 200(关闭时)")
	assert.Len(t, app.Conns, 1, "rec 已逐出,只剩保壳连接")
}

func TestConnStatsReset_Clears(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	cs.begin(10123, 6, "1.2.3.4", 443)

	cs.SetEnabled(false)
	assert.False(t, cs.Enabled())
	cs.mu.Lock()
	assert.Empty(t, cs.byUID)
	assert.Zero(t, cs.total)
	cs.mu.Unlock()
	assert.Equal(t, `{"apps":[]}`, cs.Snapshot())
}

func TestConnStatsIdleRemoval_FiveSeconds(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	// idle 阈值已从 30s 收到 5s:「最后流量后 5 秒再消失」。快照对 idle=5s 的移除,
	// 对 3s 的保留(用户要求 5 秒宽限)。
	fresh := cs.begin(10123, 6, "1.2.3.4", 80)
	aged := cs.begin(10123, 6, "1.2.3.5", 81)
	fresh.lastSeen.Store(time.Now().Add(-3 * time.Second).Unix()) // < 5s:仍显示
	aged.lastSeen.Store(time.Now().Add(-10 * time.Second).Unix()) // > 5s:淡出

	apps := parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1)
	require.Len(t, apps[0].Conns, 1, "5s 内仍保留,超过 5s 淡出")
	assert.Equal(t, "1.2.3.4", apps[0].Conns[0].Host)
}

func TestConnStatsPin_KeepsIdleConn(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	recA := cs.begin(10123, 6, "1.2.3.4", 443) // 被查看的 app
	recB := cs.begin(20234, 6, "1.2.3.5", 443) // 未查看的 app
	recA.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())
	recB.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())

	// 未 pin:两条都 idle → 都淡出,快照空。
	apps := parseSnapshot(t, cs.Snapshot())
	assert.Empty(t, apps, "未 pin 时 idle 连接照常淡出")

	// pin 后重新登记一条 idle 连接:该 app 不淡出,其余(此处无)照常。
	recA2 := cs.begin(10123, 6, "1.2.3.4", 443)
	recA2.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())
	cs.SetPin(10123)
	apps = parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1, "被 pin 的 app 应保留")
	assert.Equal(t, int32(10123), apps[0].UID)
	require.Len(t, apps[0].Conns, 1)
	assert.Equal(t, "1.2.3.4", apps[0].Conns[0].Host)
}

func TestConnStatsPin_UnpinFades(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	rec := cs.begin(10123, 6, "1.2.3.4", 443)
	rec.lastSeen.Store(time.Now().Add(-2 * connStatsIdleRemove).Unix())
	cs.SetPin(10123)

	// pin 中:不淡出。
	apps := parseSnapshot(t, cs.Snapshot())
	require.Len(t, apps, 1)
	require.Len(t, apps[0].Conns, 1)

	// 解除 pin:下次快照按 idle 淡出。
	cs.SetPin(-1)
	apps = parseSnapshot(t, cs.Snapshot())
	assert.Empty(t, apps, "解除 pin 后 idle 连接应淡出")
}

func TestConnStatsPin_ResetOnDisable(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	cs.SetPin(10123)
	cs.SetEnabled(false)
	assert.Equal(t, int32(-1), cs.pinUID.Load(), "关闭监控应复位 pin")
}

func TestConnStatsEviction_PinnedSurvives(t *testing.T) {
	cs := NewConnStats()
	cs.SetEnabled(true)
	defer cs.SetEnabled(false)

	// 塞满:普通 uid 的 lastSeen=now;最后一条是 pin 的 uid 的旧连接。
	for i := 0; i < connStatsMaxRecords-1; i++ {
		cs.begin(int32(1000+i%7), 6, "1.2.3.4", 80)
	}
	pinnedOld := cs.begin(9999, 6, "1.2.3.4", 80)
	pinnedOld.lastSeen.Store(time.Now().Add(-10 * time.Second).Unix())
	cs.SetPin(9999)

	// 新连接触发淘汰:应逐出普通 uid 里最旧的,而不是被 pin 的 9999。
	_ = cs.begin(7777, 6, "5.6.7.8", 443)

	cs.mu.Lock()
	found := false
	for _, us := range cs.byUID {
		us.mu.Lock()
		for _, r := range us.conns {
			if r == pinnedOld {
				found = true
			}
		}
		us.mu.Unlock()
	}
	cs.mu.Unlock()
	assert.True(t, found, "被 pin 的连接不应被逐出")
}
