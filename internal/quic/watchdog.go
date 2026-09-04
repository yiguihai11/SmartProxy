package quic

// Watchdog 监督一条"直连观察中"的 QUIC 流(目标在国外、正走先直连路径)是否被 GFW
// 黑洞:黑洞 = 服务器静默丢流(无 RST、无 ICMP),客户端侧唯一可观测的就是"服务器
// 永不回包"。判死条件按用户拍板用 OR:
//
//	见 Initial 重传(同 DCID + CRYPTO 与已收内容重叠)   OR
//	timeout_ms 窗口内零服务器回包
//
// 服务器回包(任意一包)即解除判死 —— 流是活的,黑洞没发生。
//
// Watchdog 不持有 socket、不做 I/O。判死只回调一次 onDead(reason),由上层 seam 去
// 写动态黑名单并把流热切到 UDP-capable 上游。回包/包到达事件由 seam 在各自读循环里
// 调用喂入。非并发:一条流一个实例。

import (
	"sync"
	"time"

	"smartproxy/internal/dpi"
)

type Watchdog struct {
	timeout time.Duration
	onDead  func(reason string)

	mu    sync.Mutex
	begin time.Time
	reply bool
	dead  bool
	det   *retransDetector
	timer *time.Timer
}

// NewWatchdog 建一个判死窗口 timeout、判死回调 onDead 的观察器。回调可空(仅观察)。
func NewWatchdog(timeout time.Duration, onDead func(reason string)) *Watchdog {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &Watchdog{timeout: timeout, onDead: onDead, det: &retransDetector{}}
}

// Begin 标记观察起点并启动超时计时(该流已开始直连、且未收到任何回包)。
func (w *Watchdog) Begin() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.begin.IsZero() {
		return
	}
	w.begin = time.Now()
	w.timer = time.AfterFunc(w.timeout, func() {
		w.mu.Lock()
		if w.reply || w.dead {
			w.mu.Unlock()
			return
		}
		w.dead = true
		w.mu.Unlock()
		w.die("no server reply within timeout")
	})
}

// OnClientDatagram 处理一个发往目标的客户端 datagram:与已见内容构成 Initial 重传且
// 至今无回包 → 立即判死。segs 为该 datagram 解出的 CRYPTO 分段(可为空,仅校验跳过)。
func (w *Watchdog) OnClientDatagram(dcid []byte, segs []dpi.CryptoSeg) {
	w.mu.Lock()
	if w.dead || w.reply || w.begin.IsZero() {
		w.mu.Unlock()
		return
	}
	if len(dcid) > 0 && w.det.retransmit(dcid, segs) {
		w.dead = true
		w.mu.Unlock()
		w.die("initial retransmission with no server reply")
		return
	}
	w.mu.Unlock()
}

// OnServerReply 收到目标服务器任意回包:流存活,解除判死。
func (w *Watchdog) OnServerReply() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reply = true
	if w.timer != nil {
		w.timer.Stop()
	}
}

// Stop 结束观察(流被切走 / 会话关闭)。判死不回调。
func (w *Watchdog) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dead = true
	if w.timer != nil {
		w.timer.Stop()
	}
}

// Dead 报告是否已判死(供 seam 查询/日志)。
func (w *Watchdog) Dead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dead
}

// Monitoring 报告该观察是否仍处活跃期(已 Begin、未判死、未收到回包)。
// seam 在喂客户端 datagram 前查询:false 时跳过解密/重传检测省 CPU。
func (w *Watchdog) Monitoring() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.begin.IsZero() && !w.dead && !w.reply
}

func (w *Watchdog) die(reason string) {
	if w.onDead != nil {
		w.onDead(reason)
	}
}

// retransDetector 按 DCID 记忆已见 CRYPTO 区间,判断一个 datagram 是否构成重传:
// 其全部 CRYPTO 分段都落在已见区间内(无任何新数据推进)即为重传。分段带新 offset
// (正常补数据/分片前进)视为新数据,并把新增并入已见区间。
type retransDetector struct {
	flows map[string][][2]int // dcid -> 已见 [lo,hi) 区间(不重叠、升序)
}

func (d *retransDetector) retransmit(dcid []byte, segs []dpi.CryptoSeg) bool {
	if len(segs) == 0 {
		return false
	}
	if d.flows == nil {
		d.flows = make(map[string][][2]int)
	}
	id := string(dcid)
	spans := d.flows[id]

	retrans := true
	for _, s := range segs {
		lo, hi := s.Offset, s.Offset+len(s.Data)
		if !coverAll(spans, lo, hi) {
			retrans = false // 有数据推进,本包不算纯重传
			spans = mergeSpan(spans, lo, hi)
		}
	}
	if retrans {
		return true
	}
	d.flows[id] = spans
	return false
}

// coverAll 报告 [lo,hi) 是否被 spans(不重叠、升序)完整覆盖,允许横跨多个区间:
// 推进 covered 指针,凡区间与前缘相接就往后顶,到不了 hi 即存在空洞。
func coverAll(spans [][2]int, lo, hi int) bool {
	covered := lo
	for _, sp := range spans {
		if sp[0] > covered {
			break // 排序保证:后面起点更大,永远补不上空洞
		}
		if sp[1] > covered {
			covered = sp[1]
		}
		if covered >= hi {
			return true
		}
	}
	return covered >= hi
}

// mergeSpan 把 [lo,hi) 并入不重叠升序 spans,必要时吞并相邻/重叠区间。
func mergeSpan(spans [][2]int, lo, hi int) [][2]int {
	out := make([][2]int, 0, len(spans)+1)
	inserted := false
	for _, sp := range spans {
		switch {
		case hi < sp[0] && !inserted: // 新区间在此之前
			out = append(out, [2]int{lo, hi}, sp)
			inserted = true
		case lo <= sp[1] && hi >= sp[0]: // 重叠/相邻 → 吞并
			if lo < sp[0] {
				sp[0] = lo
			}
			if hi > sp[1] {
				sp[1] = hi
			}
			// 尝试向右吞并后续:经典做法是压到 out 后统一合并,
			// 这里简单的单遍吞并靠后面的区间可能仍重叠,改用规整。
			out = append(out, sp)
			inserted = true
		default:
			out = append(out, sp)
		}
	}
	if !inserted {
		out = append(out, [2]int{lo, hi})
	}
	return normalize(out)
}

// normalize 把(可能因吞并产生重叠/乱序的)区间排好并合并。
func normalize(spans [][2]int) [][2]int {
	if len(spans) < 2 {
		return spans
	}
	// 冒泡按 lo 排序(区间数极少,不值得引 sort 依赖)
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j][0] < spans[j-1][0]; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	out := spans[:0]
	cur := spans[0]
	for _, sp := range spans[1:] {
		if sp[0] <= cur[1] { // 重叠/相邻 → 并
			if sp[1] > cur[1] {
				cur[1] = sp[1]
			}
		} else {
			out = append(out, cur)
			cur = sp
		}
	}
	out = append(out, cur)
	return out
}
