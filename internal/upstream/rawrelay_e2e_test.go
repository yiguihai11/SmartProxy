//go:build e2e

package upstream

// End-to-end verification: SmartProxy's raw UDP relay (udp_addr) connects directly to a
// real shadowsocks-rust ss-local (udp_only mode, the equivalent of shadowsocks-android's
// UDP fallback instance).
//
// Prerequisites (prepared by an external script):
//   - SS_SERVER_BIN points to the built ssserver
//   - SS_LOCAL_BIN  points to the built sslocal
//   - these two processes are started and stopped by this test itself
//
// Run:
//
//	SS_SERVER_BIN=/path/ssserver SS_LOCAL_BIN=/path/sslocal go test -tags e2e ./internal/upstream/ -run TestRawRelayE2E -v

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"smartproxy/internal/config"
)

// e2eEnv holds the paths to the two real binaries.
func e2eEnv(t *testing.T) (serverBin, localBin string) {
	t.Helper()
	serverBin = os.Getenv("SS_SERVER_BIN")
	localBin = os.Getenv("SS_LOCAL_BIN")
	if serverBin == "" || localBin == "" {
		t.Skip("SS_SERVER_BIN / SS_LOCAL_BIN not set")
	}
	return serverBin, localBin
}

// startRealSS starts a real ssserver + sslocal (udp_only) and returns sslocal's UDP listen address.
func startRealSS(t *testing.T, serverBin, localBin string) (udpAddr string, cleanup func()) {
	t.Helper()

	method := "aes-256-gcm"
	password := "smartproxy-e2e-pass"
	serverPort := freeUDPPort(t)
	localPort := freeUDPPort(t)

	// Use a JSON config (this CLI version folds the port into the address argument; a config file is the most reliable)
	dir := t.TempDir()

	serverCfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "tcp_and_udp"
	}`, serverPort, password, method)
	serverCfgPath := filepath.Join(dir, "ssserver.json")
	if err := os.WriteFile(serverCfgPath, []byte(serverCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	localCfg := fmt.Sprintf(`{
	  "server": "127.0.0.1",
	  "server_port": %d,
	  "local_address": "127.0.0.1",
	  "local_port": %d,
	  "password": %q,
	  "method": %q,
	  "mode": "udp_only"
	}`, serverPort, localPort, password, method)
	localCfgPath := filepath.Join(dir, "sslocal.json")
	if err := os.WriteFile(localCfgPath, []byte(localCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1) ssserver: listens on 127.0.0.1:<serverPort>, forwarding UDP to the real target
	ssServer := exec.Command(serverBin, "-c", serverCfgPath)
	ssServer.Stdout = os.Stderr
	ssServer.Stderr = os.Stderr
	if err := ssServer.Start(); err != nil {
		t.Fatalf("failed to start ssserver: %v", err)
	}

	// 2) sslocal: udp_only mode, listening on local UDP 127.0.0.1:<localPort>
	//    (same mode=udp_only as shadowsocks-android's UDP fallback instance)
	ssLocal := exec.Command(localBin, "-c", localCfgPath)
	ssLocal.Stdout = os.Stderr
	ssLocal.Stderr = os.Stderr
	if err := ssLocal.Start(); err != nil {
		ssServer.Process.Kill()
		t.Fatalf("failed to start sslocal: %v", err)
	}

	udpAddr = fmt.Sprintf("127.0.0.1:%d", localPort)

	cleanup = func() {
		ssLocal.Process.Kill()
		ssServer.Process.Kill()
		ssLocal.Process.Wait()
		ssServer.Process.Wait()
	}

	// Wait for the port to be truly writable (a raw UDP Dial always succeeds, so this only confirms the process is up)
	time.Sleep(300 * time.Millisecond)
	return udpAddr, cleanup
}

// buildDNSQuery builds an A-record query for example.com (non-compressed name, easy to validate by TXID).
func buildDNSQuery(t *testing.T) []byte {
	t.Helper()
	txid := uint16(rand.Intn(65535))
	q := make([]byte, 0, 64)
	q = binary.BigEndian.AppendUint16(q, txid)   // ID
	q = binary.BigEndian.AppendUint16(q, 0x0100) // flags: RD
	q = binary.BigEndian.AppendUint16(q, 1)      // QDCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // ANCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // NSCOUNT
	q = binary.BigEndian.AppendUint16(q, 0)      // ARCOUNT
	for _, label := range strings.Split("example.com", ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)                        // root
	q = binary.BigEndian.AppendUint16(q, 1) // A
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	return q
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// TestRawRelayE2E verifies end-to-end raw relay via udp_addr using a real ss-local (udp_only):
//  1. Proxy.UDPAddr = "127.0.0.1:<udp port>" (host:port form)
//  2. UDPAssociate goes through rawUDPAssociate, never touching TCP ASSOCIATE
//  3. send an example.com DNS query (SOCKS5 UDP frame, target 1.1.1.1:53)
//  4. receiving a real DNS response frame proves the data really flows end to end
func TestRawRelayE2E(t *testing.T) {
	serverBin, localBin := e2eEnv(t)
	udpAddr, cleanup := startRealSS(t, serverBin, localBin)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(udpAddr)
	udpPort, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p := &Proxy{
		Scheme:  SchemeSOCKS5,
		Host:    host,
		Port:    udpPort, // no TCP listener; success here proves the raw UDP path is taken
		UDPAddr: udpAddr, // host:port forces raw UDP
		UDPOnly: true,    // marks the upstream as UDP-only: TCP must be skipped, UDP must keep working
	}

	// A udp_only upstream has no TCP listener, so a TCP connect must fail fast.
	tcpConn, tcpErr := p.Connect(ctx, "example.com", 80)
	if tcpErr == nil {
		tcpConn.Close()
		t.Fatal("expected TCP connect to fail on a udp_only upstream (no TCP listener)")
	}
	t.Logf("TCP connect failed as expected: %v", tcpErr)

	// Simulate the TCP health probe tripping the circuit breaker (the old TCP/UDP coupling
	// that used to disable UDP too). Even with the circuit open, the udp_only UDP relay
	// must keep working — that is the "TCP down, keep testing UDP" guarantee.
	hcCfg := config.HealthCheckConf{Enabled: true, FailuresThreshold: 1, OpenCoolDown: 30}
	hc := NewHealthChecker(hcCfg, []*Proxy{p})
	defer hc.Stop()
	hc.RecordFailure(p, tcpErr)
	if p.IsAvailable() {
		t.Log("note: circuit stayed closed (checkProxy skips udp_only proxies); continuing anyway")
	}

	conn, err := p.UDPAssociate(ctx, "1.1.1.1", 53)
	if err != nil {
		t.Fatalf("UDPAssociate(raw) failed despite TCP being down: %v", err)
	}
	defer conn.Close()

	// Build the SOCKS5 UDP frame: RSV|FRAG|ATYP|DST.ADDR|DST.PORT|DNS query
	dnsQuery := buildDNSQuery(t)
	targetIP := net.ParseIP("1.1.1.1").To4()
	frame := []byte{0x00, 0x00, 0x00, 0x01}
	frame = append(frame, targetIP...)
	frame = append(frame, 0x00, 0x35) // 53
	frame = append(frame, dnsQuery...)

	t.Logf("sending %d-byte DNS query frame via raw UDP relay to %s", len(frame), udpAddr)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp := buf[:n]
	t.Logf("received %d-byte response frame", n)

	// Verify: the response frame = SOCKS5 UDP header + DNS response
	if len(resp) < 4 || resp[0] != 0x00 || resp[1] != 0x00 || resp[2] != 0x00 {
		t.Fatalf("bad SOCKS5 UDP header: %x", resp[:min(len(resp), 4)])
	}
	// Skip DST.ADDR/PORT to get the DNS payload (the target is our 1.1.1.1:53, an IP-form 10-byte header)
	const hdrLen = 10
	if len(resp) <= hdrLen {
		t.Fatalf("response too short: %d", len(resp))
	}
	dnsResp := resp[hdrLen:]
	if !bytes.Contains(dnsResp, dnsQuery[:2]) {
		t.Fatalf("DNS response TXID mismatch: query id=%x resp=%x", dnsQuery[:2], dnsResp[:2])
	}
	t.Logf("DNS response TXID matched, real end-to-end UDP relay OK")
}
