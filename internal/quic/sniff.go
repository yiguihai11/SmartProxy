package quic

// Sniff 是"一条目标流(UDP 五元组 + 目标)的一次性 QUIC 短窗嗅探":吸收到达的前几个
// 客户端 datagram,现场解密 Initial、喂重组器,尽力在窗口内拼出首个 ClientHello 的
// SNI / ECH 判定。
//
// 语义(给上层 seam 的契约):
//   - 首个 datagram 解出客户端 Initial(pkts>0)即置 QUIC;否则整条流视为非 QUIC,
//     上层按普通 UDP 走现有路由,嗅探到此为止。
//   - QUIC 流一旦拼出足够明文(能剥掉 handshake 头)就固化 Ready:SNI / ECH 取一次
//     不再变。天然覆盖"首个 datagram 即含完整 ClientHello"的绝大多数情形。
//   - 首个 datagram 明文不足以剥头(极端的跨包分片 CH)时保持吸收后续包;距首个
//     QUIC 包超过 HoldMs 后冻结(frozen),不再为改判定吸收 —— 防 PTO 重传无限喂料。
//     冻结后 Ready()==false,上层按"有 QUIC 但没抠到 SNI"处理。
//   - 上层拿 QUIC()/SNI()/ECH();ECH 为真(real)时外层 SNI 是混淆占位,不得入规则。
//
// 只做识别与产出,不做路由决策。非并发:一条流一个实例,串行喂包。

import (
	"time"

	"smartproxy/internal/dpi"
)

type Sniff struct {
	hold time.Duration
	asm  *dpi.Assembler

	started time.Time // 首个 QUIC datagram 的时刻(hold 窗口起点)
	dcid    []byte    // 首个包的 DCID(供外层判死观察对齐)

	quic   bool // 见过客户端 Initial
	ready  bool // 判定已固化
	sni    string
	ech    *dpi.ECHInfo
}

// NewSniff 建一个 HoldMs 窗口、Assembler 预算 maxBuffered 字节的嗅探器。hold<=0 时
// 只有首包一次机会(首包拼不出就冻结)。
func NewSniff(hold time.Duration, maxBuffered int) *Sniff {
	return &Sniff{
		hold: hold,
		asm:  dpi.NewAssembler(maxBuffered),
	}
}

// Ingest 喂一个发往目标的客户端 datagram。判定固化或冻结后调用为 no-op。
// 返回 true 表示本条流的判定本轮可能已变化(上层值得重新取一次状态)。
func (s *Sniff) Ingest(dgram []byte) bool {
	if s.ready || s.quic && !s.started.IsZero() && s.hold > 0 && time.Since(s.started) > s.hold {
		return false // 已固化 / 窗口已冻结
	}

	dcid, segs, packets := dpi.DecryptInitialDatagram(dgram)
	if packets == 0 {
		if !s.quic && s.asm.Len() == 0 {
			// 头几个包就不是 QUIC Initial:普通 UDP,尽早收工
			s.ready = true
		}
		return false
	}
	if !s.quic {
		s.quic = true
		s.started = time.Now()
		s.dcid = append([]byte(nil), dcid...)
	}
	if len(segs) == 0 {
		return false
	}
	s.asm.Feed(segs)
	if s.asm.Len() < 4 { // handshake 头都没到齐,等下个包
		return false
	}
	ch := s.asm.ClientHello()
	sni, ech := dpi.ParseClientHello(ch)
	s.sni, s.ech, s.ready = sni, ech, true
	return true
}

// QUIC 报告该流是否被识别为 QUIC 客户端 Initial 流。
func (s *Sniff) QUIC() bool { return s.quic }

// Ready 报告判定是否已固化(可用 SNI/ECH;或已确认非 QUIC)。
func (s *Sniff) Ready() bool { return s.ready }

// SNI 返回抠出的外层 server_name(仅当判定固化;真 ECH 时该值是混淆占位)。
func (s *Sniff) SNI() string { return s.sni }

// ECH 返回解出的 ECH 结构,非 nil 且 Real 时上层应作废 SNI 的域名规则用途。
func (s *Sniff) ECH() *dpi.ECHInfo { return s.ech }

// DCID 返回首个 QUIC 包的 DCID(判死观察按它对重传)。
func (s *Sniff) DCID() []byte { return s.dcid }
