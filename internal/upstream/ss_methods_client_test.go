package upstream

// Self-contained validation for the two ciphers that shadowsocks-rust (the reference
// ssserver) does not implement — aes-192-gcm and xchacha20-ietf-poly1305 — so they cannot
// be exercised against it (see ss_methods_e2e_test.go for the ciphers ssserver does have).
// Here sing-shadowsocks' own in-process server Service stands in for the far end: SmartProxy's
// built-in client must complete a full encrypted round-trip through it. This runs in the
// normal unit suite (no external binary, no build tag).

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestSSMethods_NoReferenceServer round-trips a payload through an in-process sing SS
// server for each cipher shadowsocks-rust lacks.
func TestSSMethods_NoReferenceServer(t *testing.T) {
	for _, method := range []string{"aes-192-gcm", "xchacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			// local echo target
			echoLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echoLn.Close()
			go acceptLoop(echoLn, func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo back
			})

			const password = "smartproxy-methods-client"
			svc, err := shadowaead.NewService(method, nil, password, 0, &echoForwardHandler{})
			if err != nil {
				t.Fatalf("NewService(%s): %v", method, err)
			}
			srv, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			go acceptLoop(srv, func(c net.Conn) {
				defer c.Close()
				_ = svc.NewConnection(context.Background(), c, M.Metadata{})
			})

			_, srvPortStr, _ := net.SplitHostPort(srv.Addr().String())
			_, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
			echoPort, _ := strconv.Atoi(echoPortStr)

			u := "ss://" + b64url(method+":"+password) + "@127.0.0.1:" + srvPortStr
			p, err := NewProxy(u)
			if err != nil {
				t.Fatalf("NewProxy: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			conn, err := p.Connect(ctx, "127.0.0.1", echoPort)
			cancel()
			if err != nil {
				t.Fatalf("Connect via %s: %v", method, err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(15 * time.Second))

			payload := []byte("hello over " + method)
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			echo := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, echo); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(echo, payload) {
				t.Fatalf("echo mismatch: got %q want %q", echo, payload)
			}
			t.Logf("%s: encrypted round-trip OK", method)
		})
	}
}

// acceptLoop accepts connections on ln and hands each to fn (blocking, run in a goroutine).
func acceptLoop(ln net.Listener, fn func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go fn(c)
	}
}

// echoForwardHandler forwards each accepted SS connection to metadata.Destination
// (our local echo server), bridging both directions.
type echoForwardHandler struct{}

func (h *echoForwardHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var d net.Dialer
	target, err := d.DialContext(ctx, "tcp", metadata.Destination.String())
	if err != nil {
		return err
	}
	defer target.Close()
	go func() {
		_, _ = io.Copy(target, conn)
		// half-close write side once the client's side ends, so the echo's EOF propagates
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, err = io.Copy(conn, target)
	return err
}

func (h *echoForwardHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return nil // UDP not exercised here
}

func (h *echoForwardHandler) NewError(ctx context.Context, err error) {}
