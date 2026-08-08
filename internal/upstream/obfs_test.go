package upstream

import (
	"bytes"
	"context"
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
