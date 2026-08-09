package upstream

// Tests for the deferred SS address handshake (ssConnect):
//
// The reference clients (shadowsocks-rust sslocal, ss-android) send the SS address header
// together with the first payload chunk in a single write, so the obfs-http body covers
// addr+data (Content-Length is the combined length). SmartProxy previously emitted the bare
// address header as the entire obfs body (Content-Length == addr length, payload in a
// separate segment) — the shadowsocks-in-obfs signature GFW's DPI flags and resets. These
// tests pin the combined-first-write wire and the read-first flush (rust issue #232).

import (
	"bytes"
	"context"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// wantAddrExampleCom443 is the plaintext SS address header for "example.com:443"
// (ATYP domain 0x03, len 11, port 0x01bb).
var wantAddrExampleCom443 = append([]byte{0x03, 0x0b}, append([]byte("example.com"), 0x01, 0xbb)...)

// testTimeoutError is a net.Error that reports Timeout, so deferredSSConn's grace logic fires.
type testTimeoutError struct{}

func (testTimeoutError) Error() string   { return "i/o timeout" }
func (testTimeoutError) Timeout() bool   { return true }
func (testTimeoutError) Temporary() bool { return true }

// testGraceConn is a controllable net.Conn: reads return testTimeoutError `timeouts` times
// before serving readData; all writes are recorded.
type testGraceConn struct {
	writeMu  sync.Mutex
	writes   [][]byte
	readData []byte
	timeouts int
	deadline bool
}

func (c *testGraceConn) Read(p []byte) (int, error) {
	if c.timeouts > 0 {
		c.timeouts--
		return 0, testTimeoutError{}
	}
	if len(c.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readData)
	c.readData = c.readData[n:]
	return n, nil
}

func (c *testGraceConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *testGraceConn) SetReadDeadline(t time.Time) error { c.deadline = !t.IsZero(); return nil }
func (c *testGraceConn) Close() error                      { return nil }
func (c *testGraceConn) LocalAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *testGraceConn) RemoteAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2} }
func (c *testGraceConn) SetDeadline(t time.Time) error     { return nil }
func (c *testGraceConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// noneDeferred builds a deferredSSConn configured as ssConnect does for the none/plain
// method: the first write merges [addr][payload], the flush emits the addr alone.
func noneDeferred(rec *testGraceConn) *deferredSSConn {
	addr := wantAddrExampleCom443
	return &deferredSSConn{
		Conn: rec,
		firstWrite: func(b []byte) (int, error) {
			merged := make([]byte, 0, len(addr)+len(b))
			merged = append(merged, addr...)
			merged = append(merged, b...)
			if err := writeAll(rec, merged); err != nil {
				return 0, err
			}
			return len(b), nil
		},
		flush: func() error { return writeAll(rec, addr) },
	}
}

// TestDeferredSSConn_WriteFirstCombines pins the core fix: the first Write sends the SS
// address header + payload as a SINGLE underlying write; later writes pass through. The
// merged buffer is longer than the input, so the count must be len(b) or io.CopyBuffer
// reports io.ErrShortWrite.
func TestDeferredSSConn_WriteFirstCombines(t *testing.T) {
	rec := &testGraceConn{}
	c := noneDeferred(rec)

	first := []byte("hello world")
	n, err := c.Write(first)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(first) {
		t.Errorf("first Write returned %d, want %d (input len)", n, len(first))
	}
	if len(rec.writes) != 1 {
		t.Fatalf("first Write caused %d underlying writes, want exactly 1 (addr must travel with the first payload)", len(rec.writes))
	}
	merged := append(append([]byte(nil), wantAddrExampleCom443...), first...)
	if !bytes.Equal(rec.writes[0], merged) {
		t.Errorf("first underlying write = %v, want addr+payload %v", rec.writes[0], merged)
	}

	second := []byte("more")
	if _, err := c.Write(second); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 2 || !bytes.Equal(rec.writes[1], second) {
		t.Errorf("second Write = %v, want only the payload %v (no repeated addr header)", rec.writes, second)
	}
}

// TestDeferredSSConn_ReadFirstFlushesAfterGrace covers read-first protocols (FTP/SMTP): a
// read with no server data within the grace must flush the bare address header, then
// proceed with the read.
func TestDeferredSSConn_ReadFirstFlushesAfterGrace(t *testing.T) {
	rec := &testGraceConn{readData: []byte("220 smtp ready"), timeouts: 1}
	c := noneDeferred(rec)

	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len("220 smtp ready") || string(buf[:n]) != "220 smtp ready" {
		t.Errorf("Read = %q, want %q", buf[:n], "220 smtp ready")
	}
	// After the grace timeout the address header must have gone out alone.
	if len(rec.writes) != 1 || !bytes.Equal(rec.writes[0], wantAddrExampleCom443) {
		t.Errorf("expected bare addr flush after grace, got writes: %v", rec.writes)
	}
}

// TestDeferredSSConn_ReadFirstDataNoFlush: if server data arrives within the grace (the
// write direction fired the combined handshake), no bare addr is flushed.
func TestDeferredSSConn_ReadFirstDataNoFlush(t *testing.T) {
	rec := &testGraceConn{readData: []byte("HTTP/1.1 204")}
	c := noneDeferred(rec)

	if _, err := c.Read(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 0 {
		t.Errorf("server data within grace must not flush the bare addr, got writes: %v", rec.writes)
	}
}

// TestDeferredSSConn_WriteThenReadPassthrough: after a first Write the read side never
// sets a deadline or flushes.
func TestDeferredSSConn_WriteThenReadPassthrough(t *testing.T) {
	rec := &testGraceConn{readData: []byte("server reply")}
	c := noneDeferred(rec)

	if _, err := c.Write([]byte("GET /")); err != nil {
		t.Fatal(err)
	}
	if rec.deadline {
		t.Error("Read after a Write must not set a read deadline")
	}
	if _, err := c.Read(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Errorf("expected only the combined first write, got: %v", rec.writes)
	}
}

// TestSSConnectNoneObfs_ContentLengthCoversAddrAndData is the end-to-end regression test
// for the GFW reset: through the full ssConnect path (none + obfs-http), the first data
// write must produce an obfs body whose Content-Length covers the SS address header AND the
// payload contiguously — never a bare addr-only body.
func TestSSConnectNoneObfs_ContentLengthCoversAddrAndData(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())

	captured := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()
		all, _ := io.ReadAll(conn) // client closes after writing -> EOF
		captured <- all
	}()

	// Same shape as the real node: ss://none + obfs-local;obfs=http;obfs-host=upay.10010.com
	u := "ss://bm9uZTpwYXNz@127.0.0.1:" + portStr + "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dupay.10010.com"
	p, err := NewProxy(u)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := p.Connect(ctx, "example.com", 443)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	payload := []byte("GET / HTTP/1.1\r\nHost: v2ex.com\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	raw := <-captured
	if raw == nil {
		t.Fatal("listener never accepted a connection")
	}

	// The obfs GET header must claim a body covering addr+payload.
	clMatch := regexp.MustCompile(`(?m)^Content-Length:\s*(\d+)`).FindSubmatch(raw)
	if clMatch == nil {
		t.Fatalf("no Content-Length in captured wire:\n%s", dumpPrintable(raw))
	}
	contentLength, err := strconv.Atoi(string(clMatch[1]))
	if err != nil {
		t.Fatalf("bad Content-Length %q: %v", clMatch[1], err)
	}
	wantCL := len(wantAddrExampleCom443) + len(payload)
	if contentLength != wantCL {
		t.Errorf("Content-Length = %d, want %d (addr %d + payload %d in one body; a bare %d-byte addr body is the GFW DPI signature)",
			contentLength, wantCL, len(wantAddrExampleCom443), len(payload), len(wantAddrExampleCom443))
	}

	// The body must be addr+payload contiguously and nothing else (single write).
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("no header terminator in captured wire")
	}
	body := raw[idx+4:]
	if !bytes.Equal(body[:contentLength], append(append([]byte(nil), wantAddrExampleCom443...), payload...)) {
		t.Errorf("obfs body != addr+payload:\n%s", dumpPrintable(body[:minInt(contentLength, len(body))]))
	}
	if len(body) != contentLength {
		t.Errorf("obfs body is %d bytes, want exactly Content-Length %d (no separate addr-only segment)", len(body), contentLength)
	}
}
