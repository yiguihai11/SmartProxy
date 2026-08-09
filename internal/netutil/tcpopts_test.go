package netutil

import (
	"net"
	"testing"
	"time"
)

// TestSetKeepAliveIntervalSmoke verifies the helper runs without error on a real TCP conn
// pair (on linux it sets TCP_KEEPINTVL; elsewhere it is a no-op). Keepalive tuning is
// best-effort, so the contract is "no error on a valid *net.TCPConn".
func TestSetKeepAliveIntervalSmoke(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCh := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		serverCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := <-serverCh
	defer server.Close()

	clientTCP, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatalf("client is %T, want *net.TCPConn", client)
	}
	if err := clientTCP.SetKeepAlive(true); err != nil {
		t.Fatal(err)
	}
	clientTCP.SetKeepAlivePeriod(15 * time.Second)
	if err := SetKeepAliveInterval(clientTCP, 15*time.Second); err != nil {
		t.Fatalf("SetKeepAliveInterval: %v", err)
	}
}

// TestEnableTCPFastOpenSmoke verifies the helper runs without error on an active listener.
func TestEnableTCPFastOpenSmoke(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tcpl, ok := ln.(*net.TCPListener)
	if !ok {
		t.Skipf("listener is %T, want *net.TCPListener", ln)
	}
	if err := EnableTCPFastOpen(tcpl); err != nil {
		t.Fatalf("EnableTCPFastOpen: %v", err)
	}
}
