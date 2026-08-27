package tun

import (
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// 连接监控(「联网状态」页数据源)。懒开关:页面打开才采集,关闭即停;
// 关闭时数据路径零开销(handler 只在 connStats.Enabled() 时 begin/wrap)。
//
// 线程模型:字节计数走 atomic(跨引擎 goroutine);byUID 表走互斥锁短临界区,
// 锁序恒为 cs.mu → us.mu,防死锁。
//
// 淘汰:全局上限 connStatsMaxRecords,满则逐出 lastSeen 最旧;连接 idle 超过
// connStatsIdleRemove 在 Snapshot 时懒清扫(调用方 = UI 1s 轮询,天然只在页面
// 打开时发生),移除时并入该 app 累计。某 app 全部连接都被移除后,该 app 一并
// 从快照消失 ——「无活动的应用不显示」;快照里先报出它最后的累计总量再淡出。
// 被 pin(正在查看)的 app 连接跳过 idle 清扫,查看期间不淡出。
const (
	connStatsMaxRecords = 2000
	// 连接最后一次有流量后保留的时间:超过即视为「已 idle」,Snapshot 懒清扫移除。
	// 用户反馈无流量后消失太快,想要「最后流量后 5 秒再消失」—— 从 30s 收到 5s,
	// 列表只留最近 5 秒仍在动的东西。被 pin 查看的 app 不受此限。
	connStatsIdleRemove = 5 * time.Second
)

// connRecord 是监控里的一条连接(生命周期 = 该连接的观察窗口)。
// host 由 smart 路径 ExtractDomain 结果回填;用 atomic.Pointer 防与快照读竞态
// (handleSmartConnect 在独立 goroutine 里写,Snapshot 在轮询线程读)。
type connRecord struct {
	proto    int32 // 6=TCP, 17=UDP
	uid      int32
	ip       string // 目标 IP(所有连接都有)
	port     int
	host     atomic.Pointer[string] // smart TCP 的域名;空则快照显示 ip
	up       atomic.Int64           // 上行(app→远端)累计字节
	down     atomic.Int64           // 下行(远端→app)累计字节
	lastSeen atomic.Int64           // unix 秒
}

// uidStats 汇总某 app(uid)的累计流量 + 它当前存活/未淘汰的连接。
// up/down 在连接移除时并入(Snapshot 懒清扫 / evictOneLocked),app 级累计跨连接存活。
type uidStats struct {
	uid   int32
	up    atomic.Int64
	down  atomic.Int64
	mu    sync.Mutex
	conns []*connRecord
}

// ConnStats 连接监控器。enabled 关闭时 begin 返回 nil,数据路径零开销。
type ConnStats struct {
	enabled atomic.Bool

	// pinUID:正在查看(展开明细)的 app,其连接不被 idle 清扫 / 不参与逐出
	// (「查看某条明细时不消失」);-1 = 无。查看期间可以没有流量但行保留,
	// 解除 pin 后按 connStatsIdleRemove 正常淡出。页面关闭时一并复位。
	pinUID atomic.Int32

	mu    sync.Mutex
	byUID map[int32]*uidStats
	total int // 存活记录数(上限 connStatsMaxRecords)
}

func NewConnStats() ConnStats {
	cs := ConnStats{byUID: make(map[int32]*uidStats)}
	cs.pinUID.Store(-1)
	return cs
}

func (cs *ConnStats) Enabled() bool { return cs.enabled.Load() }

// SetPin 固定某 app(uid)的连接不被 idle 清扫 / 逐出;-1 解除。「联网状态」页
// 展开某应用明细时 pin 它:正在查看的连接无流量也不消失,收起 / 切到别处后
// 按 5s 宽限淡出。
func (cs *ConnStats) SetPin(uid int32) { cs.pinUID.Store(uid) }

// SetEnabled 开/关监控。关闭时清空全部记录 + 复位 pin:页面重新打开 = 干净重来,
// 防过期 pin 误保留下个会话的连接。
func (cs *ConnStats) SetEnabled(on bool) {
	if on {
		cs.enabled.Store(true)
		return
	}
	cs.enabled.Store(false)
	cs.pinUID.Store(-1)
	cs.mu.Lock()
	cs.byUID = make(map[int32]*uidStats)
	cs.total = 0
	cs.mu.Unlock()
}

// begin 登记一条新连接并返回其记录;监控关闭时返回 nil(数据路径零开销)。
func (cs *ConnStats) begin(uid, proto int32, ip string, port int) *connRecord {
	if !cs.enabled.Load() {
		return nil
	}
	rec := &connRecord{proto: proto, uid: uid, ip: ip, port: port}
	rec.lastSeen.Store(time.Now().Unix())

	cs.mu.Lock()
	if cs.total >= connStatsMaxRecords {
		cs.evictOneLocked()
	}
	us := cs.byUID[uid]
	if us == nil {
		us = &uidStats{uid: uid}
		cs.byUID[uid] = us
	}
	us.mu.Lock()
	us.conns = append(us.conns, rec)
	us.mu.Unlock()
	cs.total++
	cs.mu.Unlock()
	return rec
}

// wrapTCP 把计数 wrapper 包在 TCP 连接上:Read=上行,Write=下行。
func (cs *ConnStats) wrapTCP(conn net.Conn, rec *connRecord) net.Conn {
	return &countingConn{Conn: conn, rec: rec}
}

// wrapUDP 把计数 wrapper 包在 UDP 包连接上:ReadPacket=上行,WritePacket=下行。
func (cs *ConnStats) wrapUDP(conn N.PacketConn, rec *connRecord) N.PacketConn {
	return &countingPacketConn{PacketConn: conn, rec: rec}
}

// setHost 回填 smart 路径提取的域名(仅该路径调用;其余连接 host 落空,快照显示 IP)。
func (cs *ConnStats) setHost(rec *connRecord, host string) {
	if rec == nil || host == "" {
		return
	}
	rec.host.Store(&host)
}

// Snapshot 返回按 app(uid)分组的连接快照 JSON,供 UI 每秒轮询。顺带做懒清扫:
// idle 超时连接移除并并入 app 累计(调用方 = 轮询,天然只在页面打开时发生)。
func (cs *ConnStats) Snapshot() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now().Unix()
	pin := cs.pinUID.Load()
	out := connStatsJSON{Apps: make([]appStatsJSON, 0, len(cs.byUID))}
	for uid, us := range cs.byUID {
		us.mu.Lock()
		kept := us.conns[:0]
		for _, r := range us.conns {
			if r.uid == pin {
				kept = append(kept, r) // 正在查看的 app:无流量也不淡出
				continue
			}
			if now-r.lastSeen.Load() > int64(connStatsIdleRemove.Seconds()) {
				us.up.Add(r.up.Load())
				us.down.Add(r.down.Load())
				cs.total--
			} else {
				kept = append(kept, r)
			}
		}
		us.conns = kept
		if len(kept) == 0 {
			// 全部连接已 idle 移除 → 该 app 无活动,连同最后累计一并淡出。
			delete(cs.byUID, uid)
			us.mu.Unlock()
			continue
		}

		// app 级总量 = 已关闭(并入 us.up/down)+ 存活连接实时值,UI 直接读总量算 δ 网速。
		app := appStatsJSON{UID: uid, Up: us.up.Load(), Down: us.down.Load()}
		app.Conns = make([]connStatsJSONRec, 0, len(kept))
		for _, r := range kept {
			host := r.ip
			if p := r.host.Load(); p != nil && *p != "" {
				host = *p
			}
			app.Up += r.up.Load()
			app.Down += r.down.Load()
			app.Conns = append(app.Conns, connStatsJSONRec{
				Proto: r.proto, Host: host, Port: r.port, Up: r.up.Load(), Down: r.down.Load(),
			})
		}
		us.mu.Unlock()
		out.Apps = append(out.Apps, app)
	}

	b, err := json.Marshal(out)
	if err != nil {
		return `{"apps":[]}`
	}
	return string(b)
}

// evictOneLocked 淘汰全局 lastSeen 最旧的一条记录(表满时),字节并入该 app 累计。
// 前提:已持 cs.mu。
func (cs *ConnStats) evictOneLocked() {
	var victimUs *uidStats
	var victim *connRecord
	var oldest int64 = 1<<62 - 1
	var anyUs *uidStats
	var any *connRecord
	var oldestAny int64 = 1<<62 - 1
	pin := cs.pinUID.Load()
	for _, us := range cs.byUID {
		us.mu.Lock()
		for _, r := range us.conns {
			ls := r.lastSeen.Load()
			if ls < oldestAny {
				oldestAny = ls
				any, anyUs = r, us
			}
			if r.uid == pin {
				continue // 正在查看的 app 不参与逐出
			}
			if ls < oldest {
				oldest = ls
				victim, victimUs = r, us
			}
		}
		us.mu.Unlock()
	}
	if victimUs == nil || victim == nil {
		// 全部被 pin(罕见)→ 兜底逐出全局最旧,保持表有界。
		victim, victimUs = any, anyUs
	}
	if victimUs == nil || victim == nil {
		return
	}
	victimUs.mu.Lock()
	victimUs.up.Add(victim.up.Load())
	victimUs.down.Add(victim.down.Load())
	for i, r := range victimUs.conns {
		if r == victim {
			victimUs.conns = append(victimUs.conns[:i], victimUs.conns[i+1:]...)
			break
		}
	}
	if len(victimUs.conns) == 0 {
		// 该 app 仅此一条连接也被逐出 → 空壳 uid 一并删除,防快照残留陈旧总量。
		delete(cs.byUID, victimUs.uid)
	}
	victimUs.mu.Unlock()
	cs.total--
}

// Remove 立即移除一条连接记录(「封禁」掐断连接时调用):字节并入该 app 累计,
// 行即刻从活跃明细消失,不等 30s idle 淘汰。rec 必须来自本 ConnStats 的 begin。
// 锁序与 Snapshot / evictOneLocked 一致(cs.mu → us.mu)。
func (cs *ConnStats) Remove(rec *connRecord) {
	if rec == nil {
		return
	}
	cs.mu.Lock()
	us := cs.byUID[rec.uid]
	if us == nil {
		cs.mu.Unlock()
		return
	}
	us.mu.Lock()
	for i, r := range us.conns {
		if r == rec {
			us.conns = append(us.conns[:i], us.conns[i+1:]...)
			break
		}
	}
	if len(us.conns) == 0 {
		delete(cs.byUID, rec.uid)
	}
	us.up.Add(rec.up.Load())
	us.down.Add(rec.down.Load())
	us.mu.Unlock()
	cs.total--
	cs.mu.Unlock()
}

// ── 计数 wrapper ──────────────────────────────────────────────────────────

// countingConn 包 net.Conn 计字节:客户端写的(引擎 Read)= 上行,引擎写的(客户端
// Read)= 下行。peek 阶段 ReadClientHello 也经 Read 计数,首包字节不漏。
type countingConn struct {
	net.Conn
	rec *connRecord
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.up.Add(int64(n))
		c.rec.lastSeen.Store(time.Now().Unix())
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.rec.down.Add(int64(n))
		c.rec.lastSeen.Store(time.Now().Unix())
	}
	return n, err
}

// countingPacketConn 包 N.PacketConn 计字节:ReadPacket(app 发)= 上行,
// WritePacket(回给 app)= 下行。
type countingPacketConn struct {
	N.PacketConn
	rec *connRecord
}

func (c *countingPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	addr, err := c.PacketConn.ReadPacket(buffer)
	if n := buffer.Len(); n > 0 {
		c.rec.up.Add(int64(n))
		c.rec.lastSeen.Store(time.Now().Unix())
	}
	return addr, err
}

func (c *countingPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	err := c.PacketConn.WritePacket(buffer, destination)
	if n := buffer.Len(); n > 0 {
		c.rec.down.Add(int64(n))
		c.rec.lastSeen.Store(time.Now().Unix())
	}
	return err
}

// ── JSON 快照结构 ─────────────────────────────────────────────────────────

type connStatsJSON struct {
	Apps []appStatsJSON `json:"apps"`
}

type appStatsJSON struct {
	UID   int32              `json:"uid"`
	Up    int64              `json:"up"`   // app 累计上行(含已关闭连接)
	Down  int64              `json:"down"` // app 累计下行(含已关闭连接)
	Conns []connStatsJSONRec `json:"conns"`
}

type connStatsJSONRec struct {
	Proto int32  `json:"proto"` // 6=TCP, 17=UDP
	Host  string `json:"host"`  // 域名(smart TCP)或目标 IP
	Port  int    `json:"port"`
	Up    int64  `json:"up"`   // 该连接累计上行
	Down  int64  `json:"down"` // 该连接累计下行
}
