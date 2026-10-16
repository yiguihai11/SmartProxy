package singbox

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestEngine_LifecycleAndDirectDial(t *testing.T) {
	// Start a local test TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("hello from local server"))
			_ = conn.Close()
		}
	}()

	engine := NewEngine()
	defer engine.Close()

	// Register a parsed outbound (e.g. shadowsocks or direct)
	raw := []byte(`{
		"type": "direct",
		"tag": "my-direct"
	}`)
	if err := engine.RegisterOutbound("my-direct", raw); err != nil {
		t.Fatalf("RegisterOutbound failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := engine.DialContext(ctx, "my-direct", "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:len("hello from local server")])
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf[:n]) != "hello from local server" {
		t.Errorf("unexpected response: %s", string(buf[:n]))
	}

	// Test unregister
	if err := engine.UnregisterOutbound("my-direct"); err != nil {
		t.Fatalf("UnregisterOutbound failed: %v", err)
	}

	_, err = engine.GetOutbound("my-direct")
	if err == nil {
		t.Error("expected error getting unregistered outbound, got nil")
	}
}

func TestEngine_SetDNSAndResolve(t *testing.T) {
	engine := NewEngine()
	defer engine.Close()

	if err := engine.SetDNS("223.5.5.5:53"); err != nil {
		t.Fatalf("SetDNS failed: %v", err)
	}

	raw := []byte(`{
		"type": "direct",
		"tag": "my-direct"
	}`)
	if err := engine.RegisterOutbound("my-direct", raw); err != nil {
		t.Fatalf("RegisterOutbound failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := engine.DialContext(ctx, "my-direct", "tcp", "www.baidu.com:80")
	if err != nil {
		t.Logf("dial domain warning (may be offline during test): %v", err)
		return
	}
	defer conn.Close()
	t.Logf("successfully resolved and dialed www.baidu.com:80 through sing-box direct outbound")
}

