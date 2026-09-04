package dpi

// 解密正路径端到端：按 RFC 9000/9001/9369 反向构造合法客户端 Initial（真实做 AES-128-GCM
// 加密 + header protection），喂 DecryptInitialDatagram 再重组 + ParseClientHello，验证
// 整条链能抠出 SNI。此前 packets>0 的正路径零覆盖，只有"非 QUIC 拒绝"的反向测试。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// varintBuf 写 QUIC varint（RFC 9000 §16），测试只用到 1/2 字节档。
func varintBuf(v int) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{byte(v>>8) | 0x40, byte(v)}
	default:
		panic("test varint out of range")
	}
}

// sealInitialPacketAt 密封一个承载单条 CRYPTO 帧（自 offset 起）的 QUIC Initial 包，
// 返回可拼进 datagram 的 wire 字节：[header(首字节已加头保护)] [pn(1B，已加头保护)] [ct]。
//
// 布局与 quic.go 解密侧逐字节镜像：header = firstByte | ver(4) | dcil | dcid |
// scil(0) | token_len(0) | length(varint)；AAD = header(首字节用去保护后的 0xc0) +
// pn 明文；nonce = iv XOR pn(末 8B)；payload 明文 = CRYPTO 帧(0x06, offset, len, data)。
func sealInitialPacketAt(ch []byte, offset int, dcid []byte, version uint32, pn byte) (wire []byte, ct []byte) {
	ks := quicInitialKeys(dcid, version)
	if ks == nil {
		panic("unknown quic version in test")
	}

	// payload 明文：单条 CRYPTO 帧（0x06, offset, len, data）
	plain := append([]byte{0x06}, varintBuf(offset)...)
	plain = append(plain, varintBuf(len(ch))...)
	plain = append(plain, ch...)

	ct = make([]byte, 0, len(plain)+16) // 加密后预留 tag

	// header（去保护态首字节 0xc0 = long | fixed | Initial）
	var hdr []byte
	hdr = append(hdr, 0xc0)
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], version)
	hdr = append(hdr, v[:]...)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00)                          // scid len 0
	hdr = append(hdr, 0x00)                          // token len varint 0
	hdr = append(hdr, varintBuf(1+len(plain)+16)...) // length = pn(1) + ct

	// pn 明文按 pnLen=1 编码：pn 高 7 字节恒 0，只动末字节
	var pnb [8]byte
	pnb[7] = pn
	aad := append(append([]byte{}, hdr...), pnb[7])

	// 加密（AAD 用去保护态）
	block, err := aes.NewCipher(ks.key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, 12)
	copy(nonce, ks.iv)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= pnb[i]
	}
	ct = gcm.Seal(ct, nonce, plain, aad)

	// header protection：mask = AES(hp, sample)，sample = wire payload[4:20] = ct[3:19]
	// （pn 占 payload[0]，sample 起点在 ct 内，与 pn 字节无关，可先算 mask 再拼 payload）
	hp, err := aes.NewCipher(ks.hp)
	if err != nil {
		panic(err)
	}
	if len(ct) < 19 {
		panic("test packet too short for sample")
	}
	var mask [16]byte
	hp.Encrypt(mask[:], ct[3:19])
	firstWire := byte(0xc0) ^ (mask[0] & 0x0f)
	pnWire := pn ^ mask[1]

	wire = make([]byte, 0, len(hdr)+1+len(ct))
	wire = append(wire, firstWire)
	wire = append(wire, hdr[1:]...)
	wire = append(wire, pnWire)
	wire = append(wire, ct...)
	return wire, ct
}

// sealInitialPacket 密封一条 offset 0 的 CRYPTO 帧（单包常规用法）。
func sealInitialPacket(ch []byte, dcid []byte, version uint32, pn byte) ([]byte, []byte) {
	return sealInitialPacketAt(ch, 0, dcid, version, pn)
}

// buildE2EDatagram 拼一个（可为 coalesced 多包的）客户端 Initial datagram。
func buildE2EDatagram(pkts [][]byte) []byte {
	var d []byte
	for _, p := range pkts {
		d = append(d, p...)
	}
	return d
}

const e2eDCID = "\x01\x02\x03\x04\x05\x06\x07\x08"

func TestDecryptInitialDatagramE2ESNI(t *testing.T) {
	for _, v := range []struct {
		name    string
		version uint32
	}{
		{"v1", 0x00000001},
		{"v2", 0x6b3343cf},
	} {
		t.Run(v.name, func(t *testing.T) {
			ch := buildClientHello("quic-e2e.example.com", 0x2a2a /*GREASE*/, false)
			dcid := []byte(e2eDCID)
			pkt, _ := sealInitialPacket(ch, dcid, v.version, 5)
			dgram := buildE2EDatagram([][]byte{pkt})

			gotDcid, segs, packets := DecryptInitialDatagram(dgram)
			if packets != 1 {
				t.Fatalf("packets=%d want 1", packets)
			}
			if !bytes.Equal(gotDcid, dcid) {
				t.Fatalf("dcid=%x want %x", gotDcid, dcid)
			}
			if len(segs) != 1 || segs[0].Offset != 0 || !bytes.Equal(segs[0].Data, ch) {
				t.Fatalf("segs wrong: %+v", segs)
			}

			a := NewAssembler(2048)
			a.Feed(segs)
			sni, ech := ParseClientHello(a.ClientHello())
			if sni != "quic-e2e.example.com" {
				t.Fatalf("sni=%q", sni)
			}
			if ech == nil || ech.Real {
				t.Fatalf("GREASE ECH expected non-real: %+v", ech)
			}
		})
	}
}

func TestDecryptInitialDatagramE2ERealECH(t *testing.T) {
	ch := buildClientHello("outer-decoy.example.com", 0x0001 /*真 ECH*/, true)
	dcid := []byte(e2eDCID)
	pkt, _ := sealInitialPacket(ch, dcid, 0x00000001, 9)
	dgram := buildE2EDatagram([][]byte{pkt})

	_, segs, packets := DecryptInitialDatagram(dgram)
	if packets != 1 {
		t.Fatalf("packets=%d want 1", packets)
	}
	a := NewAssembler(2048)
	a.Feed(segs)
	sni, ech := ParseClientHello(a.ClientHello())
	if sni != "outer-decoy.example.com" {
		t.Fatalf("outer SNI should be extractable even under real ECH, got %q", sni)
	}
	if ech == nil || !ech.Real {
		t.Fatalf("real ECH not flagged: %+v", ech)
	}
}

func TestDecryptInitialDatagramCoalescedSplit(t *testing.T) {
	// 一个 datagram 里 coalesced 两个包，CRYPTO 流被拆成 offset 0 和 offset k 两段
	// （模拟分片 + PTO 后补发），验证跨包帧遍历 + 重组成完整 ClientHello。
	ch := chWithoutECH("coalesced.example.com")
	dcid := []byte(e2eDCID)
	k := len(ch) / 2

	chunk0, chunk1 := ch[:k], ch[k:]

	// 每个包独立密封（不同 pn），明文各装一条 CRYPTO 帧
	pkt0, _ := sealInitialPacketAt(chunk0, 0, dcid, 0x00000001, 1)
	pkt1, _ := sealInitialPacketAt(chunk1, k, dcid, 0x00000001, 2)
	dgram := buildE2EDatagram([][]byte{pkt0, pkt1})

	_, segs, packets := DecryptInitialDatagram(dgram)
	if packets != 2 {
		t.Fatalf("packets=%d want 2 (coalesced)", packets)
	}
	if len(segs) != 2 || segs[0].Offset != 0 || segs[1].Offset != k {
		t.Fatalf("segs offsets wrong: %+v", segs)
	}
	a := NewAssembler(2048)
	a.Feed(segs)
	got := a.ClientHello()
	if !bytes.Equal(got, ch) {
		t.Fatalf("coalesced reassembly len=%d want %d", len(got), len(ch))
	}
	sni, _ := ParseClientHello(got)
	if sni != "coalesced.example.com" {
		t.Fatalf("sni=%q", sni)
	}
}

func TestDecryptInitialDatagramTamperFails(t *testing.T) {
	// 合法 datagram 弄坏 tag → 必须判为不可解（packets=0、无 segs），不能panic不能误收
	ch := chWithoutECH("tamper.example.com")
	dcid := []byte(e2eDCID)
	pkt, _ := sealInitialPacket(ch, dcid, 0x00000001, 3)
	dgram := buildE2EDatagram([][]byte{pkt})
	dgram[len(dgram)-1] ^= 0xff // tag 末字节翻转

	_, segs, packets := DecryptInitialDatagram(dgram)
	if packets != 0 || len(segs) != 0 {
		t.Fatalf("tampered datagram: packets=%d segs=%d, want 0/0", packets, len(segs))
	}
}

func TestDecryptInitialDatagramRejectsJunk(t *testing.T) {
	// 非 QUIC 垃圾：首字节连 long-header 都算不上 → 直接 0
	_, segs, packets := DecryptInitialDatagram(bytes.Repeat([]byte{0x41}, 200))
	if packets != 0 || len(segs) != 0 {
		t.Fatalf("junk: packets=%d segs=%d, want 0/0", packets, len(segs))
	}
}
