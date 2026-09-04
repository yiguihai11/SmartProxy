package dpi

// 被动解密 QUIC Initial（RFC 9001 §5.2 / RFC 9369），在单个 UDP datagram 内遍历所有
// coalesced QUIC 包（RFC 9000 §12.2），抠出其中全部 CRYPTO 帧。纯函数，只依赖标准库，
// 不需要任何连接级密钥 —— Initial 密钥只由包头里明文的 DCID 现场推导。
//
// 用法分两步：把每个 datagram 的返回 segs 喂给 Assembler（quicflow.go）跨包按绝对
// offset 重组 TLS ClientHello 明文，再由 ExtractClientHelloSNI / ExtractClientHelloECH
// 抠出 server_name / 判断 ECH。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// RFC 9001 §5.2 的 Initial salt（v1 / RFC 9369 的 v2）
var quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
var quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

// CryptoSeg 是 CRYPTO 流的一个分片：明文里自 Offset 起 len(Data) 字节。
type CryptoSeg struct {
	Offset int
	Data   []byte
}

// quicHkdfExpandLabel 实现 RFC 8446 §7.1 的 HKDF-Expand-Label（QUIC 复用 TLS 1.3 标签）。
// 空 context 也要带 0 长度字节占位，缺了密钥全错。
func quicHkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

type quicKeySet struct {
	key []byte // 16B AES-128-GCM 密钥
	iv  []byte // 12B 随机数
	hp  []byte // 16B 头保护密钥
}

// quicInitialKeys 由 DCID 和版本现场推导 Initial 密钥，版本不认识返回 nil。
func quicInitialKeys(dcid []byte, version uint32) *quicKeySet {
	var salt, keyL, ivL, hpL []byte
	switch version {
	case 0x00000001: // QUIC v1
		salt, keyL, ivL, hpL = quicSaltV1, []byte("quic key"), []byte("quic iv"), []byte("quic hp")
	case 0x6b3343cf: // QUIC v2 (RFC 9369)
		salt, keyL, ivL, hpL = quicSaltV2, []byte("quicv2 key"), []byte("quicv2 iv"), []byte("quicv2 hp")
	default:
		return nil
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt) // Extract(secret=DCID, salt)
	if err != nil {
		panic(err)
	}
	cs := quicHkdfExpandLabel(secret, "client in", 32)
	return &quicKeySet{
		key: quicHkdfExpandLabel(cs, string(keyL), 16),
		iv:  quicHkdfExpandLabel(cs, string(ivL), 12),
		hp:  quicHkdfExpandLabel(cs, string(hpL), 16),
	}
}

// quicReadVarint 读 QUIC varint（RFC 9000 §16），返回 (值, 占用字节数)。
func quicReadVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	first := b[0]
	ln := 1 << (first >> 6) // 00->1, 01->2, 10->4, 11->8
	mask := byte(0x3f)
	if ln == 1 {
		return uint64(first & mask), 1
	}
	var v uint64
	for i := 0; i < ln; i++ {
		v <<= 8
		if i == 0 {
			v |= uint64(first & mask)
		} else {
			v |= uint64(b[i])
		}
	}
	return v, ln
}

// parseInitialFrame 解析 Initial 明文里的一帧，返回 [帧总字节数, CRYPTO 分段]。
// 非 CRYPTO 帧分段为 nil；未知帧/截断返回 -1，调用方应停止解析本包。
// Initial 只允许装 PADDING/PING/ACK/CRYPTO/CONNECTION_CLOSE（RFC 9000 §12.4），
// 任意顺序、CRYPTO 夹在 ACK/PADDING 中间都能正确跳过。
func parseInitialFrame(b []byte) (int, *CryptoSeg) {
	if len(b) == 0 {
		return -1, nil
	}
	// 越界安全 varint：成功时 *p 前进
	varintAt := func(p *int) (uint64, bool) {
		if *p >= len(b) {
			return 0, false
		}
		l := 1 << (b[*p] >> 6)
		if *p+l > len(b) {
			return 0, false
		}
		v, _ := quicReadVarint(b[*p:])
		*p += l
		return v, true
	}
	ft := b[0]
	switch {
	case ft == 0x00: // PADDING：吃光整串
		i := 0
		for i < len(b) && b[i] == 0x00 {
			i++
		}
		return i, nil
	case ft == 0x01: // PING：空帧
		return 1, nil
	case ft == 0x06: // CRYPTO
		p := 1
		off, ok := varintAt(&p)
		if !ok {
			return -1, nil
		}
		ln, ok := varintAt(&p)
		if !ok || int(ln) > len(b)-p {
			return -1, nil
		}
		return p + int(ln), &CryptoSeg{int(off), b[p : p+int(ln)]}
	case ft == 0x02 || ft == 0x03: // ACK(+ECN)
		p := 1
		if _, ok := varintAt(&p); !ok { // Largest Acknowledged
			return -1, nil
		}
		if _, ok := varintAt(&p); !ok { // ACK Delay
			return -1, nil
		}
		rc, ok := varintAt(&p) // ACK Range Count
		if !ok {
			return -1, nil
		}
		if _, ok := varintAt(&p); !ok { // First ACK Range
			return -1, nil
		}
		for i := uint64(0); i < rc; i++ { // 每组 Gap + ACK Range Length
			if _, ok := varintAt(&p); !ok {
				return -1, nil
			}
			if _, ok := varintAt(&p); !ok {
				return -1, nil
			}
		}
		if ft == 0x03 { // ECN 计数
			for i := 0; i < 3; i++ {
				if _, ok := varintAt(&p); !ok {
					return -1, nil
				}
			}
		}
		if p > len(b) {
			return -1, nil
		}
		return p, nil
	case ft == 0x1c || ft == 0x1d: // CONNECTION_CLOSE (transport / application)
		p := 1
		if _, ok := varintAt(&p); !ok { // Error Code
			return -1, nil
		}
		if ft == 0x1c { // transport 特有 Frame Type
			if _, ok := varintAt(&p); !ok {
				return -1, nil
			}
		}
		rl, ok := varintAt(&p) // Reason Phrase Length
		if !ok || int(rl) > len(b)-p {
			return -1, nil
		}
		return p + int(rl), nil
	}
	return -1, nil // 其余帧型在 Initial 里不合法/未知，停
}

// DecryptInitialDatagram 解密一个 UDP datagram 里的全部客户端 Initial（coalesced 多包），
// 收集所有 CRYPTO 帧。返回首个可解包的 DCID、全部分段、成功解密包数。
//
// packets>0 说明该 datagram 是合法的 QUIC 客户端 Initial，是进入短窗/黑洞自愈的候选；
// =0 时（非 QUIC、服务器包、握手后的 1-RTT 包等）segs 为空，调用方应按普通 UDP 处理。
func DecryptInitialDatagram(dgram []byte) (dcid []byte, segs []CryptoSeg, packets int) {
	pos := 0
	for {
		if pos+21 > len(dgram) {
			return
		}
		d := dgram[pos:]
		first := d[0]
		// 长头 + fixed bit + type==Initial(00)；不满足就不是客户端 Initial，coalesce 到此为止
		if first&0x80 == 0 || first&0x40 == 0 || first&0x30 != 0 {
			return
		}
		ver := binary.BigEndian.Uint32(d[1:5])
		if ver != 0x00000001 && ver != 0x6b3343cf {
			return
		}
		dcil := int(d[5])
		if 7+dcil > len(d) {
			return
		}
		if dcid == nil {
			dcid = d[6 : 6+dcil]
		}
		p := 6 + dcil
		if p >= len(d) {
			return
		}
		scil := int(d[p])
		p++
		if p+scil > len(d) {
			return
		}
		p += scil // SCID 用不到，跳过
		tl, n := quicReadVarint(d[p:])
		p += n
		if p+int(tl) > len(d) {
			return
		}
		p += int(tl)
		plen, n := quicReadVarint(d[p:])
		p += n
		if plen < 20 || p+int(plen) > len(d) {
			return
		}
		payload := d[p : p+int(plen)]
		packetEnd := pos + p + int(plen)

		k := quicInitialKeys(d[6:6+dcil], ver)
		if k == nil {
			return
		}
		block, err := aes.NewCipher(k.hp)
		if err != nil {
			return
		}
		var mask [16]byte
		block.Encrypt(mask[:], payload[4:20]) // sample = pn 字段后 4 字节起的 16B 密文
		firstByte := d[0] ^ (mask[0] & 0x0f)  // mask[0] 解包头首字节低 4 位
		pnLen := int(firstByte&0x03) + 1
		var pn uint64
		for i := 0; i < pnLen; i++ {
			pn = pn<<8 | uint64(payload[i]^mask[1+i])
		}
		ct := payload[pnLen:]
		if len(ct) < 16 {
			pos = packetEnd
			continue
		}
		// AAD = 包头(首字节用解保护后的 firstByte) + pn(解保护后) —— 与加密侧逐字节一致
		aad := make([]byte, 0, p+pnLen)
		aad = append(aad, d[:p]...)
		aad[0] = firstByte
		var pnb [8]byte
		binary.BigEndian.PutUint64(pnb[:], pn)
		aad = append(aad, pnb[8-pnLen:]...)
		nonce := make([]byte, 12) // nonce = iv XOR pn(末 8 字节)
		copy(nonce, k.iv)
		for i := 0; i < 8; i++ {
			nonce[4+i] ^= pnb[i]
		}
		blk2, _ := aes.NewCipher(k.key)
		gcm, _ := cipher.NewGCM(blk2)
		pt, err := gcm.Open(nil, nonce, ct, aad)
		if err != nil {
			pos = packetEnd
			continue
		}
		packets++
		// 抠出包内全部 CRYPTO 帧：任意帧序都不放过
		b := pt
		for len(b) > 0 {
			consumed, cseg := parseInitialFrame(b)
			if consumed < 0 {
				break
			}
			if cseg != nil {
				segs = append(segs, *cseg)
			}
			b = b[consumed:]
		}
		pos = packetEnd
	}
}
