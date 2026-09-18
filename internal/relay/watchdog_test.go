package relay

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchdog_Stall_TriggersRSTAndBlacklist(t *testing.T) {
	clientR, clientW := net.Pipe()
	remoteR, remoteW := net.Pipe()
	defer clientR.Close()
	defer remoteW.Close()

	var stalled atomic.Bool
	var stallReason string
	var stallMu sync.Mutex

	cfg := WatchdogConfig{
		Timeout: 50 * time.Millisecond,
		Host:    "140.82.116.4",
		Port:    443,
		Domain:  "github.com",
		OnStall: func(h string, p int, d, reason string) {
			stallMu.Lock()
			stalled.Store(true)
			stallReason = reason
			stallMu.Unlock()
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run relay in background
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		TCPRelay(ctx, clientR, remoteR, false, nil, WithWatchdog(cfg))
	}()

	// Simulate client writing HTTP request
	go func() {
		clientW.Write([]byte("GET / HTTP/2\r\n\r\n"))
	}()

	// Remote does NOT reply (simulating GFW blackhole silent drop)
	// We read client's request on remoteW to simulate request leaving client
	buf := make([]byte, 1024)
	n, err := remoteW.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("failed to read client request on remote end: %v", err)
	}

	// Wait for watchdog to trigger (timeout is 50ms)
	select {
	case <-relayDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TCPRelay did not terminate after watchdog timeout")
	}

	if !stalled.Load() {
		t.Fatal("expected OnStall callback to be invoked, but was not")
	}

	stallMu.Lock()
	defer stallMu.Unlock()
	if stallReason != "gfw_silent_drop_watchdog" {
		t.Fatalf("expected reason 'gfw_silent_drop_watchdog', got '%s'", stallReason)
	}

	// Verify clientW got closed/reset
	_, writeErr := clientW.Write([]byte("test"))
	if writeErr == nil {
		t.Error("expected client connection to be closed by watchdog, but write succeeded")
	}
}

func TestWatchdog_NormalResponse_Disarms(t *testing.T) {
	clientR, clientW := net.Pipe()
	remoteR, remoteW := net.Pipe()
	defer clientR.Close()
	defer clientW.Close()
	defer remoteR.Close()
	defer remoteW.Close()

	var stalled atomic.Bool
	cfg := WatchdogConfig{
		Timeout: 500 * time.Millisecond,
		Host:    "1.1.1.1",
		Port:    443,
		Domain:  "cloudflare.com",
		OnStall: func(h string, p int, d, reason string) {
			stalled.Store(true)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		TCPRelay(ctx, clientR, remoteR, false, nil, WithWatchdog(cfg))
	}()

	// 1. Client writes request
	go func() {
		clientW.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	}()

	// 2. Remote reads request
	buf := make([]byte, 1024)
	n, err := remoteW.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("remote read failed: %v", err)
	}

	// 3. Remote immediately replies with response
	_, err = remoteW.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	if err != nil {
		t.Fatalf("remote write failed: %v", err)
	}

	// 4. Client reads response
	respBuf := make([]byte, 1024)
	rn, err := clientW.Read(respBuf)
	if err != nil || rn == 0 {
		t.Fatalf("client read response failed: %v", err)
	}

	// Wait beyond the watchdog timeout (500ms)
	time.Sleep(600 * time.Millisecond)

	if stalled.Load() {
		t.Fatal("watchdog should have been disarmed by normal response, but OnStall was called!")
	}
}

func TestWatchdog_EarlyReset_Triggers(t *testing.T) {
	clientR, clientW := net.Pipe()
	defer clientR.Close()
	defer clientW.Close()

	var stalled atomic.Bool
	var stallReason string
	var stallMu sync.Mutex

	cfg := WatchdogConfig{
		Timeout: 1 * time.Second,
		Host:    "140.82.116.4",
		Port:    443,
		Domain:  "github.com",
		OnStall: func(h string, p int, d, reason string) {
			stallMu.Lock()
			stalled.Store(true)
			stallReason = reason
			stallMu.Unlock()
		},
	}

	// Mock remote connection that returns ECONNRESET on Read
	mockRemote := &errorConn{err: syscall.ECONNRESET}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		TCPRelay(ctx, clientR, mockRemote, false, nil, WithWatchdog(cfg))
	}()

	select {
	case <-relayDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TCPRelay did not terminate after early reset")
	}

	if !stalled.Load() {
		t.Fatal("expected early reset to trigger OnStall, but it did not")
	}

	stallMu.Lock()
	defer stallMu.Unlock()
	if stallReason != "gfw_rst_injected" {
		t.Fatalf("expected reason 'gfw_rst_injected', got '%s'", stallReason)
	}
}

func TestWatchdog_ProxyBypassed(t *testing.T) {
	clientR, clientW := net.Pipe()
	remoteR, remoteW := net.Pipe()
	defer clientR.Close()
	defer clientW.Close()
	defer remoteR.Close()
	defer remoteW.Close()

	var stalled atomic.Bool
	cfg := WatchdogConfig{
		Timeout: 30 * time.Millisecond,
		Host:    "1.2.3.4",
		Port:    443,
		OnStall: func(h string, p int, d, reason string) {
			stalled.Store(true)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// proxy = true: watchdog should NOT attach!
	go TCPRelay(ctx, clientR, remoteR, true, nil, WithWatchdog(cfg))

	// Client writes, remote is silent
	go func() { clientW.Write([]byte("data")) }()

	time.Sleep(60 * time.Millisecond)

	if stalled.Load() {
		t.Fatal("watchdog should not trigger for proxy connections")
	}
}

type errorConn struct {
	err error
}

func (e *errorConn) Read(b []byte) (n int, err error)   { return 0, e.err }
func (e *errorConn) Write(b []byte) (n int, err error)  { return 0, e.err }
func (e *errorConn) Close() error                       { return nil }
func (e *errorConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (e *errorConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (e *errorConn) SetDeadline(t time.Time) error      { return nil }
func (e *errorConn) SetReadDeadline(t time.Time) error  { return nil }
func (e *errorConn) SetWriteDeadline(t time.Time) error { return nil }
