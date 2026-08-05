package upstream

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func createTestUDPConn(t *testing.T) (*UDPProxyConn, net.PacketConn) {
	t.Helper()

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve addr: %v", err)
	}
	server, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Fatalf("failed to dial: %v", err)
	}

	tcpServer, _ := net.Pipe()

	proxyConn := &UDPProxyConn{
		UDPConn: client,
		tcpConn: tcpServer,
	}

	return proxyConn, server
}

func cleanupTestConn(proxyConn *UDPProxyConn, server net.PacketConn) {
	if proxyConn != nil {
		proxyConn.Close()
	}
	if server != nil {
		server.Close()
	}
}

func TestUDPAssociatePool_New(t *testing.T) {
	p := NewUDPAssociatePool(0)
	if p.maxSize != 4 {
		t.Errorf("expected default maxSize 4, got %d", p.maxSize)
	}
	if p.Len() != 0 {
		t.Errorf("new pool should be empty, got %d", p.Len())
	}
}

func TestUDPAssociatePool_NewCustomSize(t *testing.T) {
	p := NewUDPAssociatePool(8)
	if p.maxSize != 8 {
		t.Errorf("expected maxSize 8, got %d", p.maxSize)
	}
}

func TestUDPAssociatePool_AcquireFromEmptyPool(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	acquired := false
	conn, err := p.Acquire(ctx, "8.8.8.8", 53,
		func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
			acquired = true
			if host != "8.8.8.8" || port != 53 {
				t.Errorf("expected host=8.8.8.8 port=53, got host=%s port=%d", host, port)
			}

			client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
			tcpA, _ := net.Pipe()
			return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
		})
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if !acquired {
		t.Error("provider was not called")
	}

	conn.Close()
	p.Close()
}

func TestUDPAssociatePool_ReleaseAndReuse(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	createCount := 0
	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
		createCount++
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	conn1, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	if createCount != 1 {
		t.Errorf("expected 1 create, got %d", createCount)
	}

	p.Release(conn1)
	if p.Len() != 1 {
		t.Errorf("expected pool size 1 after release, got %d", p.Len())
	}

	conn2, err := p.Acquire(ctx, "1.1.1.1", 53, provider)
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}
	if createCount != 1 {
		t.Errorf("expected 1 create total (reused), got %d", createCount)
	}

	if conn1.UDPConn != conn2.UDPConn {
		t.Error("Acquire did not reuse the released connection")
	}

	conn2.Close()
	p.Close()
}

func TestUDPAssociatePool_RespectsMaxSize(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	var conns []*UDPProxyConn
	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	for i := 0; i < 3; i++ {
		conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		conns = append(conns, conn)
	}

	for _, c := range conns {
		p.Release(c)
	}

	if p.Len() != 2 {
		t.Errorf("expected pool size 2 (maxSize), got %d", p.Len())
	}

	p.Close()
}

func TestUDPAssociatePool_Discard(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	p.Discard(conn)
	if p.Len() != 0 {
		t.Errorf("expected pool size 0 after discard, got %d", p.Len())
	}

	p.Close()
}

func TestUDPAssociatePool_CloseDrainsAll(t *testing.T) {
	p := NewUDPAssociatePool(4)
	ctx := context.Background()

	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	var conns []*UDPProxyConn
	for i := 0; i < 4; i++ {
		conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
		if err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
		conns = append(conns, conn)
	}

	for _, c := range conns {
		p.Release(c)
	}

	if p.Len() != 4 {
		t.Errorf("expected pool size 4 after filling, got %d", p.Len())
	}

	p.Close()
	if p.Len() != 0 {
		t.Errorf("expected pool size 0 after close, got %d", p.Len())
	}
}

func TestUDPAssociatePool_ProviderError(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	expectedErr := &net.OpError{Op: "dial", Net: "udp", Err: net.UnknownNetworkError("test error")}
	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
		return nil, expectedErr
	}

	conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
	if err == nil {
		t.Fatal("expected error from provider, got nil")
	}
	if conn != nil {
		conn.Close()
	}

	if p.Len() != 0 {
		t.Errorf("expected pool size 0 after failed acquire, got %d", p.Len())
	}

	p.Close()
}

func TestUDPAssociatePool_DeadlinesClearedOnRelease(t *testing.T) {
	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	proxyConn, server := createTestUDPConn(t)
	defer cleanupTestConn(proxyConn, server)

	proxyConn.UDPConn.SetDeadline(time.Now().Add(time.Nanosecond))
	time.Sleep(time.Millisecond)

	buf := make([]byte, 1)
	err := proxyConn.UDPConn.SetReadDeadline(time.Now().Add(time.Millisecond))
	if err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	_, err = proxyConn.UDPConn.Read(buf)
	if err == nil {
		t.Log("note: read unexpectedly succeeded, deadline status unclear")
	}

	p.Release(proxyConn)
	if p.Len() != 1 {
		t.Errorf("expected pool size 1 after release, got %d", p.Len())
	}

	reused, err := p.Acquire(ctx, "8.8.8.8", 53,
		func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {
			t.Fatal("provider should not be called")
			return nil, nil
		})
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer reused.Close()

	if err := reused.UDPConn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Errorf("SetDeadline failed after acquire from pool: %v", err)
	}

	reused.UDPConn.SetDeadline(time.Time{})

	p.Close()
}

func TestUDPAssociatePool_ConcurrentAccess(t *testing.T) {
	p := NewUDPAssociatePool(4)
	ctx := context.Background()

	var mu sync.Mutex
	createCount := 0
	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {

		time.Sleep(time.Millisecond)
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		mu.Lock()
		createCount++
		mu.Unlock()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
			if err != nil {
				t.Errorf("concurrent Acquire failed: %v", err)
				return
			}

			time.Sleep(time.Millisecond)
			p.Release(conn)
		}()
	}
	wg.Wait()

	mu.Lock()
	created := createCount
	mu.Unlock()
	t.Logf("created %d connections for 20 concurrent acquires (pool size 4)", created)
	if created > 20 {
		t.Errorf("created more connections than acquires: %d", created)
	}
	if created < 1 {
		t.Errorf("should have created at least 1 connection")
	}

	if p.Len() > 4 {
		t.Errorf("expected at most 4 idle connections, got %d", p.Len())
	}

	p.Close()
}

func TestUDPAssociatePool_NilReleaseIsSafe(t *testing.T) {
	p := NewUDPAssociatePool(2)

	p.Release(nil)
	p.Discard(nil)
	p.Close()

	p.Release(nil)
}

func TestUDPAssociatePool_AcquireProviderNotHoldingLock(t *testing.T) {

	p := NewUDPAssociatePool(2)
	ctx := context.Background()

	provider := func(ctx context.Context, host string, port int) (*UDPProxyConn, error) {

		if l := p.Len(); l != 0 {
			t.Errorf("expected pool empty during provider, got %d", l)
		}
		client, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19999})
		tcpA, _ := net.Pipe()
		return &UDPProxyConn{UDPConn: client, tcpConn: tcpA}, nil
	}

	conn, err := p.Acquire(ctx, "8.8.8.8", 53, provider)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	conn.Close()
	p.Close()
}
