package upstream

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestObfsHTTPReadKeepAlive is a regression test for httpObfsConn.Read blocking on the
// obfs response boundary. A server sends its 101 obfs response plus a relayed HTTP reply
// (or the reply shortly after) and then KEEPS the connection open (HTTP keep-alive), as a
// healthy remote target does. Read must hand the relayed reply to the caller as soon as it
// is buffered — never block trying to fill the caller's buffer — or net/http hangs waiting
// for headers. (Found with an ss://none obfs-http node whose health probe timed out.)
func TestObfsHTTPReadKeepAlive(t *testing.T) {
	for _, tc := range []struct {
		name   string // how the mock server delivers 101 + 204
		single bool   // true: send both in one Write; false: send 101, pause, then 204
	}{
		{name: "combined", single: true},
		{name: "split", single: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				// consume the obfs GET header up to \r\n\r\n
				buf := make([]byte, 8192)
				got := 0
				for {
					n, err := conn.Read(buf[got:])
					got += n
					if err != nil {
						return
					}
					if bytes.Contains(buf[:got], []byte("\r\n\r\n")) {
						break
					}
				}
				const (
					obfs101 = "HTTP/1.1 101 Switching Protocols\r\n\r\n"
					repl204 = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
				)
				if tc.single {
					conn.Write([]byte(obfs101 + repl204))
				} else {
					conn.Write([]byte(obfs101))
					time.Sleep(50 * time.Millisecond)
					conn.Write([]byte(repl204))
				}
				// keep the connection open until the client hangs up
				conn.Read(buf)
			}()

			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			obfs, err := wrapObfs(raw, &obfsConfig{id: "obfs-local", obfs: "http", host: "upay.10010.com", method: "GET", uri: "/"})
			if err != nil {
				t.Fatal(err)
			}
			defer obfs.Close()

			transport := &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return obfs, nil
				},
			}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			req, _ := http.NewRequest("GET", "http://x/", nil)
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do failed after %v: %v", time.Since(start), err)
			}
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("status = %s, want 204", resp.Status)
			}
			t.Logf("client.Do OK after %v status=%s", time.Since(start), resp.Status)
			resp.Body.Close()
			obfs.Close() // release the keep-alive conn so the mock server's read unblocks
			<-serverDone
		})
	}
}

// TestObfsHTTPWireFormat proves the obfs plugin is actually applied to outgoing packets.
// A local TCP listener captures the RAW bytes SmartProxy sends for an ss://none obfs-http
// node. The first bytes MUST be the obfs HTTP GET request — the plaintext SS stream must
// NOT hit the wire first — the Host header must carry the configured obfs-host, and the
// unencrypted none-method SS address header must follow the \r\n\r\n boundary. If these
// prefix checks fail, packets are leaving without obfuscation, which is the exact symptom
// reported for this node.
func TestObfsHTTPWireFormat(t *testing.T) {
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
	t.Logf("captured %d bytes:\n%s", len(raw), dumpPrintable(raw))

	// 1. the wire MUST open with the obfs HTTP request, not the SS stream
	if !bytes.HasPrefix(raw, []byte("GET / HTTP/1.1\r\n")) {
		t.Fatalf("first bytes are not the obfs GET header: %q", raw[:minInt(len(raw), 60)])
	}
	// 2. Host carries the configured obfs-host (with the SS port appended when !=80, per
	//    simple-obfs: the real node's port 80 Host omits it)
	if !bytes.Contains(raw, []byte("Host: upay.10010.com")) {
		t.Errorf("obfs Host header missing: %q", raw[:minInt(len(raw), 200)])
	}
	// 3. the none-method SS address header (ATYP domain "example.com":443) follows \r\n\r\n
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("no header terminator found in captured bytes: %q", raw[:minInt(len(raw), 200)])
	}
	rest := raw[idx+4:]
	wantAddr := []byte{0x03, 0x0b} // ATYP=domain, len=11
	wantAddr = append(wantAddr, []byte("example.com")...)
	wantAddr = append(wantAddr, 0x01, 0xbb) // port 443
	if !bytes.HasPrefix(rest, wantAddr) {
		t.Fatalf("SS address header missing after \\r\\n\\r\\n: got %q, want prefix %q", rest[:minInt(len(rest), 40)], wantAddr)
	}
	// 4. the payload follows the address header in the same plaintext stream
	if !bytes.Contains(rest, payload) {
		t.Errorf("payload not found after obfs header: %q", rest[:minInt(len(rest), 200)])
	}
	t.Logf("wire format OK: obfs GET header precedes the plaintext SS stream")
}

// dumpPrintable renders captured bytes, replacing control characters so the header is readable.
func dumpPrintable(b []byte) string {
	var out []byte
	for _, c := range b {
		if c == '\r' {
			out = append(out, '\\', 'r')
		} else if c == '\n' {
			out = append(out, '\\', 'n')
		} else if c < 0x20 || c > 0x7e {
			out = append(out, '.')
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}
