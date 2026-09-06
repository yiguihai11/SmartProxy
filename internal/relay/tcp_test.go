package relay

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"smartproxy/internal/trace"
)

func makeConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var accepted net.Conn
	var acceptErr error
	ready := make(chan struct{})

	go func() {
		accepted, acceptErr = l.Accept()
		close(ready)
	}()

	dialed, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatalf("dial: %v", err)
	}

	<-ready
	l.Close()

	if acceptErr != nil {
		dialed.Close()
		t.Fatalf("accept: %v", acceptErr)
	}

	return accepted, dialed
}

func TestTCPRelay_SingleDirection(t *testing.T) {

	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	var received string
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		n, _ := dstR.Read(buf)
		received = string(buf[:n])
	}()

	srcW.Write([]byte("hello from client"))
	srcW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	TCPRelay(ctx, srcR, dstW, false, nil)
	dstW.Close()
	wg.Wait()

	if received != "hello from client" {
		t.Errorf("expected 'hello from client', got %q", received)
	}
}

func TestTCPRelay_Bidirectional(t *testing.T) {
	clientR, clientW := makeConnPair(t)
	remoteR, remoteW := makeConnPair(t)

	var c2r, r2c string
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		n, _ := remoteW.Read(buf)
		c2r = string(buf[:n])
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		n, _ := clientW.Read(buf)
		r2c = string(buf[:n])
	}()

	go TCPRelay(context.Background(), clientR, remoteR, false, nil)

	var wgWrite sync.WaitGroup
	wgWrite.Add(2)
	go func() {
		defer wgWrite.Done()
		clientW.Write([]byte("c2r-data"))
	}()
	go func() {
		defer wgWrite.Done()
		remoteW.Write([]byte("r2c-data"))
	}()
	wgWrite.Wait()

	time.Sleep(100 * time.Millisecond)

	clientR.Close()
	remoteR.Close()

	wg.Wait()

	if c2r != "c2r-data" {
		t.Errorf("c2r: expected 'c2r-data', got %q", c2r)
	}
	if r2c != "r2c-data" {
		t.Errorf("r2c: expected 'r2c-data', got %q", r2c)
	}
}

func TestTCPRelay_DataThenEOF(t *testing.T) {

	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	var wg sync.WaitGroup
	wg.Add(1)

	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := dstR.Read(buf)
			if n > 0 {
				received = append(received, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	srcW.Write([]byte("quick-close-data"))
	srcW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	TCPRelay(ctx, srcR, dstW, false, nil)
	dstW.Close()
	wg.Wait()

	if string(received) != "quick-close-data" {
		t.Errorf("expected 'quick-close-data', got %q", string(received))
	}
}

func TestTCPRelay_EOFReturnsPromptly(t *testing.T) {
	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	srcW.Close()
	dstR.Close()

	TCPRelay(context.Background(), srcR, dstW, false, nil)
}

func TestTCPRelay_LargeData(t *testing.T) {
	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	payload := make([]byte, 100000)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := dstR.Read(buf)
			if n > 0 {
				received = append(received, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		srcW.Write(payload)
		srcW.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	TCPRelay(ctx, srcR, dstW, false, nil)
	dstW.Close()
	wg.Wait()

	if len(received) != len(payload) {
		t.Errorf("expected %d bytes, got %d", len(payload), len(received))
		return
	}
	for i := range received {
		if received[i] != payload[i] {
			t.Errorf("mismatch at byte %d: expected %d, got %d", i, payload[i], received[i])
			break
		}
	}
}

// TestTCPRelay_FinishedLogCarriesFlow 钉住转发结束锚点契约:ctx 带 flow id 时,
// "TCP relay finished" 必须落在带同一 flow=N 的 logger 上,且 up/down 字节正确结算。
// 这是 grep "flow=N" 从入口日志一路追到转发结束的最后一段;回归时若 ctx 链断掉
// (比如某入口不再 WithFlow),此测试即失败。
func TestTCPRelay_FinishedLogCarriesFlow(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	var received []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := make([]byte, 65536)
		for {
			n, err := dstR.Read(b)
			if n > 0 {
				received = append(received, b[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	const payload = "quick-close-data"
	srcW.Write([]byte(payload))
	srcW.Close()

	// r2c 方向无远端回包会一直阻塞读,靠超时 ctx 走 cancel 分支收尾(同 DataThenEOF);
	// cancel 分支同样会打 "TCP relay finished"。
	base, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := trace.WithFlow(base, 4242)
	TCPRelay(ctx, srcR, dstW, false, nil)
	dstW.Close()
	wg.Wait()

	if string(received) != payload {
		t.Fatalf("expected %q, got %q", payload, received)
	}
	out := buf.String()
	if !strings.Contains(out, "TCP relay finished") {
		t.Fatalf("relay finished anchor log missing:\n%s", out)
	}
	if !strings.Contains(out, "flow=4242") {
		t.Fatalf("finished log must carry the ctx flow id:\n%s", out)
	}
	// up = c2r 转发的 payload 字节;down = 0(远端无回包即关闭)
	if !strings.Contains(out, "up="+strconv.Itoa(len(payload))) || !strings.Contains(out, "down=0") {
		t.Fatalf("finished log byte counters wrong (want up=%d down=0):\n%s", len(payload), out)
	}
}

func TestTCPRelay_ConcurrentWrites(t *testing.T) {

	srcR, srcW := makeConnPair(t)
	dstR, dstW := makeConnPair(t)

	var wg sync.WaitGroup
	wg.Add(1)

	var received []byte
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := dstR.Read(buf)
			if n > 0 {
				received = append(received, buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	var wgWrite sync.WaitGroup
	for i := 0; i < 10; i++ {
		wgWrite.Add(1)
		go func(i int) {
			defer wgWrite.Done()
			msg := []byte{byte(i), byte(i), byte(i), byte(i)}
			srcW.Write(msg)
		}(i)
	}
	wgWrite.Wait()
	srcW.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	TCPRelay(ctx, srcR, dstW, false, nil)
	dstW.Close()
	wg.Wait()

	if len(received) != 40 {
		t.Errorf("expected 40 bytes, got %d", len(received))
	}
}

// TestTCPRelay_PrefixReplayed regression test: the first byte (the prefix) read during smart-direct
// direct-connection validation must be replayed to the client in the r2c direction before any
// subsequent data from remote, and the c2r direction is unaffected by the prefix.
func TestTCPRelay_PrefixReplayed(t *testing.T) {
	clientR, clientW := makeConnPair(t)
	remoteR, remoteW := makeConnPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go TCPRelay(ctx, clientR, remoteR, false, []byte("P"))

	clientW.SetReadDeadline(time.Now().Add(2 * time.Second))
	remoteW.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Server direction: write "hello", the client should receive "P"+"hello" (prefix replayed first)
	if _, err := remoteW.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	var got string
	for len(got) < len("Phello") {
		n, err := clientW.Read(buf)
		if err != nil {
			t.Fatalf("read from client: %v (got %q)", err, got)
		}
		got += string(buf[:n])
	}
	if got != "Phello" {
		t.Fatalf("expected 'Phello', got %q", got)
	}

	// Client direction is unaffected by the prefix: app data → server
	if _, err := clientW.Write([]byte("req")); err != nil {
		t.Fatal(err)
	}
	got = ""
	for len(got) < len("req") {
		n, err := remoteW.Read(buf)
		if err != nil {
			t.Fatalf("read from remote: %v (got %q)", err, got)
		}
		got += string(buf[:n])
	}
	if got != "req" {
		t.Fatalf("expected 'req', got %q", got)
	}

	// Cleanup: let the relay goroutines in both directions exit normally
	clientW.Close()
	remoteW.Close()
	cancel()
}
