package quic

// 哑包(GFW 首包启发对抗,USENIX Security 2025 关于 QUIC 阻断的论文):
// GFW 会额外留意"一条 (源端口>目的端口 且) 流上首个 UDP 包即 QUIC Initial"的连接,
// 判定后整条流黑洞。在直连 QUIC 前先垫一个非 QUIC 的哑 datagram,让该流"首个包不是
// QUIC" —— 首包启发不再把它当 QUIC 流的起点,后续 Initial 正常放行。
//
// 哑包内容无协议意义、无需服务器配合(服务器收到不认识的数据通常按 UDP 正常丢弃,
// 个别服务可能回 ICMP,无妨)。dummy 配置开启时才由 seam 在直连首包前发送。

import cryptoRand "crypto/rand"

// NewDummyDatagram 生成一包随机长度的非 QUIC 哑数据(QUIC 长头首字节固定 0xc0~0xff
// 区间,哑包避开即可;纯随机即天然避开首字节高位模式的概率极低,这里再显式保证)。
func NewDummyDatagram() []byte {
	// 长度取 40~280 之间随机:太大浪费,太小不像普通 UDP 载荷
	var lb [1]byte
	if _, err := cryptoRand.Read(lb[:]); err != nil {
		lb[0] = 137
	}
	n := 40 + int(lb[0])%241

	buf := make([]byte, n)
	if _, err := cryptoRand.Read(buf); err != nil {
		// 兜底:随机源不可用时用确定性填充(仍非 QUIC)
		for i := range buf {
			buf[i] = byte((i*31 + 7) & 0xff)
		}
	}
	// 显式保证首字节不是 QUIC 长头(长头要求 0x80|0x40 置位且 type=00);普通 UDP
	// 载荷没有固定格式,其余字节纯随机即可
	if buf[0]&0xc0 == 0xc0 {
		buf[0] &^= 0x40
	}
	return buf
}
