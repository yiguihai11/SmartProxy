package dpi

// 解析解密后的 CRYPTO 流里的 TLS ClientHello 明文，抠出 server_name / 判断 ECH。
// 区别于 ExtractSNI（喂 TLS record），这里喂的是 QUIC CRYPTO 流剥掉 handshake 头后
// 的 ClientHello 正文 —— 与现有 dpi.go 的 record 层解析互补。
//
// 容忍分片截断：handshake 头声明长度大于实收时按实收走，扩展出现即分析，宁可少拿
// 不panic（外层照样包 recover）。

import (
	"encoding/binary"
	"strings"
)

// ECHInfo 是从 encrypted_client_hello(0xfe0d) 扩展解出的信息。
// Real=false 表示 GREASE 占位 —— Chrome/Firefox 几乎每个 ClientHello 都带一个，
// 套件号是 RFC 8701 GREASE 值（形如 0x?a?a 的重复字节），此时外层 server_name
// 仍是真实域名、可作路由依据。
// Real=true 才是真正协商 ECH：外层 SNI 只是对服务器的混淆占位，不能当域名规则用。
type ECHInfo struct {
	CipherSuite uint16 // ECH cipher_suite 的 kdf_id 半段（判定用）
	ConfigID    byte
	Real        bool
}

// isGreaseCipherSuite 判断 2 字节套件号是否为 RFC 8701 GREASE 值：两字节相等且低位
// 半字节为 0xa（0x0a0a、0x1a1a、…、0xfafa）。
func isGreaseCipherSuite(v uint16) bool {
	hi, lo := byte(v>>8), byte(v)
	return hi == lo && hi&0x0f == 0x0a
}

// ParseClientHello 从一段（可能截断的）ClientHello 明文里尽量抠出 server_name 和 ECH。
// 返回的 sni 已小写；ech 非 nil 表示见到了 0xfe0d 且结构可读。两者都拿不到时返回零值，
// 调用方用 Len()（见 Assembler）区分"明文不足"与"确实没有"。
func ParseClientHello(stream []byte) (sni string, ech *ECHInfo) {
	defer func() {
		if r := recover(); r != nil {
			sni, ech = "", nil
		}
	}()
	if len(stream) < 4 || stream[0] != 0x01 { // 1 = ClientHello
		return "", nil
	}
	declared := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	body := stream[4:]
	if declared < len(body) {
		body = body[:declared]
	}
	// legacy_version(2) + random(32)
	if len(body) < 34 {
		return "", nil
	}
	pos := 34

	// session_id
	if pos >= len(body) {
		return "", nil
	}
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos > len(body) {
		return "", nil
	}

	// cipher_suites(2B len)
	if pos+2 > len(body) {
		return "", nil
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos > len(body) {
		return "", nil
	}

	// compression_methods(1B len)
	if pos >= len(body) {
		return "", nil
	}
	cmLen := int(body[pos])
	pos += 1 + cmLen
	if pos > len(body) {
		return "", nil
	}

	// extensions(2B len)，数据不足时截到实收，逐条分析
	if pos+2 > len(body) {
		return "", nil
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if extTotal > len(body)-pos {
		extTotal = len(body) - pos
	}
	exts := body[pos : pos+extTotal]

	for i := 0; i+4 <= len(exts); {
		extType := binary.BigEndian.Uint16(exts[i : i+2])
		extLen := int(binary.BigEndian.Uint16(exts[i+2 : i+4]))
		start := i + 4
		if extLen > len(exts)-start { // 截断的扩展：剩下的没法分析，放弃
			return sni, ech
		}
		data := exts[start : start+extLen]
		switch {
		case extType == 0x0000 && sni == "": // server_name：取第一个即可
			sni = sniFromExtData(data)
		case extType == 0xfe0d && ech == nil: // encrypted_client_hello
			ech = echFromExtData(data)
		}
		i = start + extLen
	}
	return sni, ech
}

// sniFromExtData 解析 server_name 扩展正文，返回小写 host 或 ""。
func sniFromExtData(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen > len(data)-2 {
		return ""
	}
	item := data[2 : 2+listLen]
	if len(item) < 3 || item[0] != 0x00 { // 只要 host_name 类型
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(item[1:3]))
	if 3+nameLen > len(item) {
		return ""
	}
	return strings.ToLower(string(item[3 : 3+nameLen]))
}

// echFromExtData 解析 ECHClientHello 正文。现网结构（draft-ietf-tls-esni）：
//
//	cipher_suite(4B: kdf_id+aead_id) | config_id(1B) | enc<2B前缀> | payload<2B前缀>
//
// Real 依 cipher_suite 的 kdf_id（前 2B）是否 GREASE 判定：GREASE 占位整段都是
// GREASE 值，而真 ECH 的 kdf_id 恒为 HKDF-SHA256(0x0001) 等标准值。结构不完整只
// 回退返回 nil。
func echFromExtData(data []byte) *ECHInfo {
	if len(data) < 7 { // 至少读全 cipher_suite(4)+config_id(1)+enc 长度(2)
		return nil
	}
	info := &ECHInfo{
		CipherSuite: binary.BigEndian.Uint16(data[0:2]), // kdf_id
		ConfigID:    data[4],
	}
	if !isGreaseCipherSuite(info.CipherSuite) {
		info.Real = true
	}
	return info
}
