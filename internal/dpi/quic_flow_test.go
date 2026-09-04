package dpi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---------- 合成 ClientHello 构造（结构合法，内容任意） ----------

func buildClientHello(sni string, echSuite uint16, echReal bool) []byte {
	var ext []byte
	addExt := func(t uint16, data []byte) {
		var h [4]byte
		binary.BigEndian.PutUint16(h[0:2], t)
		binary.BigEndian.PutUint16(h[2:4], uint16(len(data)))
		ext = append(ext, h[:]...)
		ext = append(ext, data...)
	}
	// server_name
	var sd []byte
	{
		name := []byte(sni)
		sd = append(sd, 0, 1) // list_len 占位
		sd = append(sd, 0)    // name_type host_name
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(name)))
		sd = append(sd, l[:]...)
		sd = append(sd, name...)
		binary.BigEndian.PutUint16(sd[0:2], uint16(len(sd)-2))
		addExt(0x0000, sd)
	}
	// ECH（GREASE 或真结构都长一样，只差套件号）
	{
		ed := make([]byte, 7)
		binary.BigEndian.PutUint16(ed[0:2], echSuite) // kdf_id
		binary.BigEndian.PutUint16(ed[2:4], echSuite) // aead_id
		ed[4] = 0x2a                                  // config_id
		// enc_len=0 / payload 略：检测只看 kdf_id，不带多余字节
		addExt(0xfe0d, ed)
	}
	// 组装 body
	var ch []byte
	ch = append(ch, 0x03, 0x03) // legacy_version
	ch = append(ch, bytes.Repeat([]byte{0xaa}, 32)...)
	ch = append(ch, 0) // session_id len
	ch = append(ch, 0, 2, 0x13, 0x01)
	ch = append(ch, 1, 0) // compression: [len=1]{null}
	var el [2]byte
	binary.BigEndian.PutUint16(el[:], uint16(len(ext)))
	ch = append(ch, el[:]...)
	ch = append(ch, ext...)
	// handshake 头
	out := []byte{0x01, 0, 0, 0}
	binary.BigEndian.PutUint32(out[0:4], uint32(1)<<24|uint32(len(ch)))
	return append(out, ch...)
}

func TestParseClientHelloSNI(t *testing.T) {
	ch := buildClientHello("example.com", 0x2a2a /*GREASE*/, false)
	sni, ech := ParseClientHello(ch)
	if sni != "example.com" {
		t.Fatalf("sni = %q, want example.com", sni)
	}
	if ech == nil {
		t.Fatal("expected ECH extension present")
	}
	if ech.Real {
		t.Fatalf("GREASE ECH misjudged as real: %+v", ech)
	}
}

func TestParseClientHelloRealECH(t *testing.T) {
	ch := buildClientHello("inner.example.com", 0x0001 /*真 ECH kdf*/, true)
	sni, ech := ParseClientHello(ch)
	if sni == "" {
		t.Fatal("outer SNI should still be extractable")
	}
	if ech == nil || !ech.Real {
		t.Fatalf("real ECH not detected: %+v", ech)
	}
}

func TestParseClientHelloNoECH(t *testing.T) {
	sni, ech := ParseClientHello(chWithoutECH("plain.example.com"))
	if sni != "plain.example.com" || ech != nil {
		t.Fatalf("sni=%q ech=%+v", sni, ech)
	}
}

func chWithoutECH(sni string) []byte {
	var sd []byte
	name := []byte(sni)
	sd = append(sd, 0, 0)
	sd = append(sd, 0)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(name)))
	sd = append(sd, l[:]...)
	sd = append(sd, name...)
	binary.BigEndian.PutUint16(sd[0:2], uint16(len(sd)-2))

	var ext []byte
	{
		var h [4]byte
		binary.BigEndian.PutUint16(h[0:2], 0x0000)
		binary.BigEndian.PutUint16(h[2:4], uint16(len(sd)))
		ext = append(ext, h[:]...)
		ext = append(ext, sd...)
	}
	var ch []byte
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, bytes.Repeat([]byte{0xaa}, 32)...)
	ch = append(ch, 0)
	ch = append(ch, 0, 2, 0x13, 0x01)
	ch = append(ch, 1, 0)
	var el [2]byte
	binary.BigEndian.PutUint16(el[:], uint16(len(ext)))
	ch = append(ch, el[:]...)
	ch = append(ch, ext...)
	out := []byte{0x01, 0, 0, 0}
	binary.BigEndian.PutUint32(out[0:4], uint32(1)<<24|uint32(len(ch)))
	return append(out, ch...)
}

// ---------- Assembler 跨分片 / 重传重叠 ----------

func feedAssembler(a *Assembler, off int, data []byte) {
	a.Feed([]CryptoSeg{{Offset: off, Data: data}})
}

func TestAssemblerSplitReassembly(t *testing.T) {
	ch := chWithoutECH("split.example.com")
	a := NewAssembler(2048)
	c1, c2 := len(ch)/3, 2*len(ch)/3
	parts := []struct{ off, end int }{{0, c1}, {c1, c2}, {c2, len(ch)}}
	for _, p := range parts {
		feedAssembler(a, p.off, ch[p.off:p.end])
	}
	got := a.ClientHello()
	if !bytes.Equal(got, ch) {
		t.Fatalf("reassembled len=%d want %d", len(got), len(ch))
	}
	sni, _ := ParseClientHello(got)
	if sni != "split.example.com" {
		t.Fatalf("sni=%q", sni)
	}
}

func TestAssemblerOverlapRetransmit(t *testing.T) {
	ch := chWithoutECH("retransmit.example.com")
	a := NewAssembler(2048)
	// 第一包 full，然后一个只含前半段的"重传"，不得造成重复输出
	feedAssembler(a, 0, ch)
	feedAssembler(a, 0, ch[:len(ch)/2])
	got := a.ClientHello()
	if !bytes.Equal(got, ch) {
		t.Fatalf("overlap produced len=%d want %d", len(got), len(ch))
	}
}

func TestAssemblerGap(t *testing.T) {
	ch := chWithoutECH("gap.example.com")
	a := NewAssembler(2048)
	c1, c2 := len(ch)/2, len(ch)/2+40
	if c2 > len(ch) {
		c2 = len(ch)
	}
	feedAssembler(a, 0, ch[:c1])
	feedAssembler(a, c2, ch[c2:]) // 缺口之后的先不收
	got := a.ClientHello()
	if !bytes.Equal(got, ch[:c1]) {
		t.Fatalf("gap handling wrong: len=%d", len(got))
	}
	// 补上缺口即可拼全
	feedAssembler(a, c1, ch[c1:c2])
	got = a.ClientHello()
	if !bytes.Equal(got, ch) {
		t.Fatalf("after backfill len=%d want %d", len(got), len(ch))
	}
}

func TestAssemblerLen(t *testing.T) {
	a := NewAssembler(2048)
	if a.Len() != 0 {
		t.Fatal("empty assembler Len must be 0")
	}
	ch := chWithoutECH("x.example.com")
	feedAssembler(a, 0, ch[:50])
	if a.Len() != 50 {
		t.Fatalf("Len=%d want 50", a.Len())
	}
}
