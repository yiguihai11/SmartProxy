package tun

import (
	"net"
	"sync"
	"sync/atomic"

	"smartproxy/internal/netutil"
)

// tcpHandle 是单条活跃 TCP 连接的应用侧 + outbound 句柄,供「联网状态」页封禁时
// 主动掐断(对 outbound 发 RST + 关应用侧)。host 在 smart 路径提取域名后回填,
// ip 恒为目标 IP;掐断按 host/ip 匹配 ACL 封锁规则。
//
// host / remote 由连接 goroutine(handleSmartConnect / handleConnect)在发布后写入,
// kill 由 watcher goroutine(ACL reloader)读,二者并发 → 用 atomic 同步(与
// connRecord.host 同风格);app / rec / stats 在 add 入表前固定,发布即安全。
type tcpHandle struct {
	host atomic.Pointer[string] // smart 路径的域名(仅该路径回填,可空)
	ip   string                 // 目标 IP(恒非空)
	port int

	app    net.Conn // 应用侧(gVisor 栈)连接
	remote atomic.Pointer[net.Conn] // outbound 连接(直连或代理);未建立前 nil
	rec    *connRecord
	stats  *ConnStats // 掐断时移除统计记录(rec 非 nil 才用)

	closeOnce sync.Once
}

// setHost 回填 smart 路径提取的域名(仅该路径调用;其余连接 host 落空,按 IP 匹配)。
func (hd *tcpHandle) setHost(host string) {
	if host != "" {
		hd.host.Store(&host)
	}
}

// setRemote 在 outbound 建立后登记,供 kill 对远端发 RST。
func (hd *tcpHandle) setRemote(remote net.Conn) {
	hd.remote.Store(&remote)
}

// hostValue 读回域名(空串 = 未回填)。
func (hd *tcpHandle) hostValue() string {
	if p := hd.host.Load(); p != nil {
		return *p
	}
	return ""
}

// kill 主动掐断:outbound 发 RST(真 RST),应用侧关闭,统计记录即时移除。
// closeOnce 保证并发掐断只执行一次;注册表移除由 KillBlockedConnections 立即完成,
// relay 返回后的 defer remove 幂等。
func (hd *tcpHandle) kill() {
	hd.closeOnce.Do(func() {
		if r := hd.remote.Load(); r != nil {
			netutil.ResetConn(*r)
		}
		hd.app.Close()
		if hd.rec != nil && hd.stats != nil {
			hd.stats.Remove(hd.rec)
		}
	})
}

// liveTCP 是当前活跃 TCP 连接句柄注册表:每连接一次 mutex map add/remove,
// 与现有 Is*Blocked 每连接检查同量级,数据路径(每包)零新增开销。
type liveTCP struct {
	mu    sync.Mutex
	m     map[*tcpHandle]struct{}
	stats *ConnStats
}

func newLiveTCP(cs *ConnStats) *liveTCP {
	return &liveTCP{m: make(map[*tcpHandle]struct{}), stats: cs}
}

// add 登记一条连接(建连即登记,outbound 未建立时 remote 为 nil,掐断只关应用侧)。
func (lt *liveTCP) add(app net.Conn, ip string, port int, rec *connRecord) *tcpHandle {
	hd := &tcpHandle{app: app, ip: ip, port: port, rec: rec, stats: lt.stats}
	lt.mu.Lock()
	lt.m[hd] = struct{}{}
	lt.mu.Unlock()
	return hd
}

// remove 注销一条连接(relay 返回后 defer 调用;kill 后同样会经此路径,幂等)。
func (lt *liveTCP) remove(hd *tcpHandle) {
	lt.mu.Lock()
	delete(lt.m, hd)
	lt.mu.Unlock()
}

// snapshot 在锁外取回全部活跃句柄,供 KillBlockedConnections 遍历掐断
// (掐断涉及网络 Close,不能在持有锁时执行)。
func (lt *liveTCP) snapshot() []*tcpHandle {
	lt.mu.Lock()
	out := make([]*tcpHandle, 0, len(lt.m))
	for hd := range lt.m {
		out = append(out, hd)
	}
	lt.mu.Unlock()
	return out
}
