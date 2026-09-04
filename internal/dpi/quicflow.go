package dpi

// Assembler 把同一连接上多个 UDP datagram 抠出的 CRYPTO 分片按绝对 offset 重组成
// TLS ClientHello 明文前缀。只服务一个目的：短窗（hold_ms）内攒出足够分析的
// ClientHello，供 ParseClientHello 抠 SNI/ECH —— 拿到即弃。
//
// 分片可能来自同一 datagram 内 coalesced 多包、也可能来自重传（RFC 9002 PTO 后对
// 同一 DCID 重发同 offset 的 CRYPTO）。Assembler 容忍重叠/乱序/缺口：缺口之后的
// 数据在补上前不参与输出（保证输出始终是自 offset 0 起的一段连续明文）。
//
// 非并发：调用方按连接串行喂包，同一连接一个实例。

// Assembler 是有状态重组器。maxBuffered 是重组预算：offset 或累计分片字节越过它即
// 停止吸收，防恶意大 offset 分片拖垮内存（正常 ClientHello 远小于 2KB）。
type Assembler struct {
	max      int
	segs     []CryptoSeg
	bytesFed int
	dropped  bool
	lastLen  int // 上次重组的前缀长度，供 Len() 复用
	lastGen  int
	gen      int
}

// NewAssembler 建一个预算 maxBuffered 字节的重组器。
func NewAssembler(maxBuffered int) *Assembler {
	if maxBuffered < 256 {
		maxBuffered = 256
	}
	return &Assembler{max: maxBuffered}
}

// Feed 吸收一批分片。预算耗尽置 dropped，后续 Feed 忽略；重组输出届时也作废。
func (a *Assembler) Feed(segs []CryptoSeg) {
	if a.dropped || len(segs) == 0 {
		return
	}
	a.gen++
	for _, s := range segs {
		if s.Offset < 0 || s.Offset > a.max || len(s.Data) > a.max {
			a.dropped = true
			return
		}
		a.segs = append(a.segs, s)
		a.bytesFed += len(s.Data)
		if a.bytesFed > a.max*8 { // 重叠重传的宽限预算
			a.dropped = true
			return
		}
	}
}

// Changed 报告自上次 Len()/ClientHello() 后是否喂过新分片（供短窗定时器判定有新数据）。
func (a *Assembler) Changed() bool {
	return a.gen != a.lastGen
}

// ClientHello 返回自 offset 0 起已拼出的连续明文前缀；首片 offset>0 时拿不到头，
// 返回 nil。结果可直接喂 ParseClientHello（容忍截断）。
func (a *Assembler) ClientHello() []byte {
	out := a.reassemble()
	a.lastGen = a.gen
	a.lastLen = len(out)
	return out
}

// Len 返回已拼出的连续前缀长度：>0 表示已定位 ClientHello 头；ParseClientHello 拿
// 空 SNI 时用 Len 区分"明文不足"与"确实没有 SNI / 被 ECH 覆盖"。
func (a *Assembler) Len() int {
	if a.gen == a.lastGen {
		return a.lastLen
	}
	a.ClientHello() // 顺便刷缓存
	return a.lastLen
}

// reassemble 贪心从 offset 0 起拼最长连续前缀：每次挑起点 ≤ 已拼长度、延伸最远的
// 分片，把它超出部分接上；没有能延伸的分片（缺口/到预算顶）即停。正确性靠输出始终
// 连续来保证 —— 重叠与重传天然被"已拼部分"吸收，不会重复。
func (a *Assembler) reassemble() []byte {
	if a.dropped {
		return nil
	}
	best := 0 // [0,best) 已拼
	var out []byte
	for {
		selIdx, selEnd := -1, best
		for i := range a.segs {
			s := &a.segs[i]
			if s.Offset > best {
				continue // 起点在缺口之后，现在拼不上
			}
			if e := s.Offset + len(s.Data); e > selEnd {
				selIdx, selEnd = i, e
			}
		}
		if selIdx < 0 || selEnd <= best {
			break
		}
		if selEnd > a.max {
			selEnd = a.max
		}
		if selEnd <= best {
			break // 只剩越预算部分
		}
		s := &a.segs[selIdx]
		// best 必然落在该分片内：s.Offset ≤ best < selEnd
		out = append(out, s.Data[best-s.Offset:selEnd-s.Offset]...)
		best = selEnd
		if best >= a.max {
			break
		}
	}
	return out
}
