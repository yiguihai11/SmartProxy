package engine

// QUIC 判死自愈的端到端测试:国外 QUIC 目标先直连 trial,timeout_ms 内零服务器回包
// → 判 GFW 黑洞 → 写动态黑名单 → 会话出向热切为 UDP-capable 上游(代理)。之后:
//   - 同一会话(已热切)后续客户端包改走代理转发,回包仍能回到客户端;
//   - 全新会话(IP 已在动态黑名单)不再重试直连判死,直接走代理。
//
// 结构:引擎 A(quic 开启、chnroute 空 → 127.0.0.1 是"国外"、默认策略走上游 up)
// 叠在引擎 B(纯直连 SOCKS5 上游)之上,客户端经 A 的 SOCKS5 UDP ASSOCIATE 接入。
// 目标是一个只回 "ping" 前缀、其余静默丢弃的 UDP 假服务器 —— 模拟"服务器在,但直连
// 路径上的 QUIC Initial 被黑洞"：trial 发的 Initial 必无回包 → 判死;之后 ping 经
// 代理(B 直连可达目标)才能拿到回包。
//
// 判死判定链依赖 dpi.DecryptInitialDatagram 返回 packets>0,而造这样一个合法加密
// 客户端 Initial 需要 dpi 私有的密钥派生(quicInitialKeys 等),engine 包无法 import;
// 本文件把整条 seal 链按 internal/dpi/quic.go 逐字节镜像拷成 qtest* 测试副本。
// 副本密封的 Initial 喂 sniff.Ingest 时必须被判定为 QUIC()==true、且抠不出 SNI
// (CRYPTO 明文不足 4B 不进 ParseClientHello)→ 走最简单 B 直连判死路径。

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// ── QUIC Initial seal 链(dpi/quic.go 的逐字节镜像测试副本)──────────────────

var qtestSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
var qtestSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

const qtestDCID = "\x01\x02\x03\x04\x05\x06\x07\x08"

func qtestHkdfExpandLabel(secret []byte, label string, length int) []byte {
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

type qtestKeySet struct {
	key []byte
	iv  []byte
	hp  []byte
}

func qtestInitialKeys(dcid []byte, version uint32) *qtestKeySet {
	var salt, keyL, ivL, hpL []byte
	switch version {
	case 0x00000001:
		salt, keyL, ivL, hpL = qtestSaltV1, []byte("quic key"), []byte("quic iv"), []byte("quic hp")
	case 0x6b3343cf:
		salt, keyL, ivL, hpL = qtestSaltV2, []byte("quicv2 key"), []byte("quicv2 iv"), []byte("quicv2 hp")
	default:
		return nil
	}
	secret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		panic(err)
	}
	cs := qtestHkdfExpandLabel(secret, "client in", 32)
	return &qtestKeySet{
		key: qtestHkdfExpandLabel(cs, string(keyL), 16),
		iv:  qtestHkdfExpandLabel(cs, string(ivL), 12),
		hp:  qtestHkdfExpandLabel(cs, string(hpL), 16),
	}
}

// qtestVarintBuf 写 QUIC varint(RFC 9000 §16),测试只用到 1/2 字节档。
func qtestVarintBuf(v int) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		return []byte{byte(v>>8) | 0x40, byte(v)}
	default:
		panic("qtest varint out of range")
	}
}

// qtestSealInitial 密封一个承装 cryptoData(offset 0 的 CRYPTO 帧)的 QUIC Initial
// 单包 datagram(已加 header protection)。布局与 dpi 解密侧逐字节镜像。
func qtestSealInitial(cryptoData, dcid []byte, version uint32, pn byte) []byte {
	ks := qtestInitialKeys(dcid, version)
	if ks == nil {
		panic("unknown quic version")
	}
	// payload 明文:单条 CRYPTO 帧(0x06, offset=0, len, data)
	plain := append([]byte{0x06}, qtestVarintBuf(0)...)
	plain = append(plain, qtestVarintBuf(len(cryptoData))...)
	plain = append(plain, cryptoData...)

	// header(去保护态首字节 0xc0 = long | fixed | Initial)
	hdr := []byte{0xc0}
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], version)
	hdr = append(hdr, v[:]...)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // scid len 0
	hdr = append(hdr, 0x00) // token len varint 0
	hdr = append(hdr, qtestVarintBuf(1+len(plain)+16)...)

	// pn 明文按 pnLen=1 编码
	var pnb [8]byte
	pnb[7] = pn
	aad := append(append([]byte{}, hdr...), pnb[7])

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
	ct := gcm.Seal(nil, nonce, plain, aad)

	// header protection:mask = AES(hp, sample=ct[3:19])
	if len(ct) < 19 {
		panic("packet too short for sample")
	}
	hp, err := aes.NewCipher(ks.hp)
	if err != nil {
		panic(err)
	}
	var mask [16]byte
	hp.Encrypt(mask[:], ct[3:19])
	firstWire := byte(0xc0) ^ (mask[0] & 0x0f)
	pnWire := pn ^ mask[1]

	wire := make([]byte, 0, len(hdr)+1+len(ct))
	wire = append(wire, firstWire)
	wire = append(wire, hdr[1:]...)
	wire = append(wire, pnWire)
	wire = append(wire, ct...)
	return wire
}

// ── 端到端测试 ─────────────────────────────────────────

func TestEngineQUICBlackhole_JudgedDeadThenProxyUDP(t *testing.T) {
	// 只回 "ping" 前缀、其余静默丢的假服务器:直连 trial 的 Initial 必无回包 → 判死;
	// ping 经代理才能让回包回来。
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind target: %v", err)
	}
	defer ln.Close()
	targetPort := ln.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.HasPrefix(buf[:n], []byte("ping")) {
				ln.WriteTo(buf[:n], src) // 回显
			}
		}
	}()

	// 上游 B:纯直连引擎(SOCKS5 + UDP ASSOCIATE),代表"能直连到目标"的境外代理。
	up := newTestEngine(t)
	// 引擎 A:quic 开启,判死窗口 500ms;chnroute 空 → 127.0.0.1 是"国外"目标。
	q := config.SmartProxyQuicConf{
		Enabled:     true,
		Ports:       []int{targetPort}, // 判死候选只看这些端口;用回环 echo 端口避开特权端口
		MaxBuffered: 64,
		HoldMs:      100,
		TimeoutMs:   500,
	}
	eng := startEngine(t, engineSpec{
		chnroute: "",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
		strategy: "up",
		quic:     &q,
	})

	// 相位 1:发一个合法客户端 QUIC Initial(2B CRYPTO 垃圾 → sniff 判 QUIC、抠不出 SNI)
	// 触发 B 直连判死观察;目标不回 → timeout 后判死 → 黑名单 + 出向热切代理。
	tcpConn, u := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcpConn.Close()
	defer u.Close()

	initial := qtestSealInitial([]byte{0x01, 0x02}, []byte(qtestDCID), 0x00000001, 5)
	frame := append([]byte{0, 0, 0}, socks5Addr("127.0.0.1", targetPort)...)
	frame = append(frame, initial...)
	if _, err := u.Write(frame); err != nil {
		t.Fatalf("phase1 write initial: %v", err)
	}

	// 判死窗口 500ms;轮询动态黑名单(判死回调先写黑名单、再做代理 ASSOCIATE)。
	deadline := time.Now().Add(4 * time.Second)
	for !eng.Router.IsIPBlacklisted("127.0.0.1", targetPort) {
		if time.Now().After(deadline) {
			t.Fatalf("target not blacklisted within 4s: QUIC not judged dead (trial got a reply?)")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// 等热切 ASSOCIATE 落定(本地回环 ms 级),给 200ms 余量。
	time.Sleep(200 * time.Millisecond)

	// 相位 2a:同一 ASSOCIATE(命中已热切的同一会话)发 ping → 必须经代理往返成功。
	beforeA := sampleCounters()
	payloadA := []byte("pingA-hot-switched")
	if err := writeUDPFrame(u, "127.0.0.1", targetPort, payloadA); err != nil {
		t.Fatalf("phase2a write: %v", err)
	}
	gotA := readUDPReply(t, u)
	if !bytes.Equal(gotA, payloadA) {
		t.Fatalf("phase2a echo mismatch: got %q want %q", gotA, payloadA)
	}
	assertProxiedTraffic(t, beforeA, true) // 热切后走代理:A 侧 UDP proxy 计数增长
	assertUpstreamDirect(t, beforeA, true) // 上游 B 真收到并直连目标:B 侧 UDP direct 计数增长

	// 相位 2b:全新 ASSOCIATE(全新会话)发 ping → IP 已在动态黑名单,不再重试直连判死,
	// 直接走代理往返成功。
	beforeB := sampleCounters()
	tcp2, u2 := socks5UDPAssociate(t, eng.listener.Addr().String())
	defer tcp2.Close()
	defer u2.Close()
	payloadB := []byte("pingB-fresh-blacklisted")
	if err := writeUDPFrame(u2, "127.0.0.1", targetPort, payloadB); err != nil {
		t.Fatalf("phase2b write: %v", err)
	}
	gotB := readUDPReply(t, u2)
	if !bytes.Equal(gotB, payloadB) {
		t.Fatalf("phase2b echo mismatch: got %q want %q", gotB, payloadB)
	}
	assertProxiedTraffic(t, beforeB, true) // 黑名单让新会话直接走代理
	assertUpstreamDirect(t, beforeB, true)
}

// writeUDPFrame 把 payload 包成 SOCKS5 UDP 帧(RSV+ATYP+addr+port)发到会话 socket。
func writeUDPFrame(u *net.UDPConn, host string, port int, payload []byte) error {
	frame := append([]byte{0, 0, 0}, socks5Addr(host, port)...)
	frame = append(frame, payload...)
	_, err := u.Write(frame)
	return err
}

// readUDPReply 读一包 SOCKS5 UDP 回复并剥掉帧头,返回纯 payload。
func readUDPReply(t *testing.T, u *net.UDPConn) []byte {
	t.Helper()
	u.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 65535)
	n, err := u.Read(buf)
	if err != nil {
		t.Fatalf("read udp reply: %v", err)
	}
	got, err := stripUDPHeader(buf[:n])
	if err != nil {
		t.Fatalf("strip udp header: %v", err)
	}
	return got
}
