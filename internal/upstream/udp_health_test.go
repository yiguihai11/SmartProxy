package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"smartproxy/internal/config"
)

// deadUDPPort returns a loopback UDP port that is currently unbound, for probe-failure tests.
func deadUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

// startFrameDNSServer listens on IPv4 loopback and answers SOCKS5-UDP-frame-wrapped DNS
// queries with a valid DNS response (same TXID, QR=1) wrapped back in a frame.
func startFrameDNSServer(t *testing.T) (*net.UDPConn, int) {
	return startFrameDNSServerOn(t, net.IPv4(127, 0, 0, 1))
}

// startFrameDNSServerOn listens on the given IP (IPv4 or IPv6 loopback) and answers
// SOCKS5-UDP-frame-wrapped DNS queries with a valid DNS response (same TXID, QR=1) wrapped
// back in a frame. It doubles as the raw-relay target and the DNS server for udp_only probes:
// the probe's raw UDP relay dials this address, and the header inside the frame is ignored.
func startFrameDNSServerOn(t *testing.T, ip net.IP) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			payload, err := parseUDPFrame(buf[:n])
			if err != nil {
				continue
			}
			var q dns.Msg
			if err := q.Unpack(payload); err != nil || len(q.Question) == 0 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(&q) // same ID, QR=1
			packed, err := resp.Pack()
			if err != nil {
				continue
			}
			pc.WriteToUDP(buildUDPFrame("1.1.1.1", 53, packed), addr)
		}
	}()
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// startGarbageUDPServer replies to every datagram with non-frame garbage.
func startGarbageUDPServer(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_ = n
			pc.WriteToUDP([]byte("garbage-response"), addr)
		}
	}()
	return pc, pc.LocalAddr().(*net.UDPAddr).Port
}

// startTunnelSOCKS5Mock is a real SOCKS5 proxy for loopback: CONNECT is tunneled to the
// target (so an HTTP health probe succeeds end to end), while UDP ASSOCIATE is rejected
// with rep=0x07 so the client falls back to raw UDP (which nothing answers here).
func startTunnelSOCKS5Mock(t *testing.T) (addr string, done func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = tunnelSOCKS5Conn(conn) }()
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); wg.Wait() }
}

func tunnelSOCKS5Conn(c net.Conn) error {
	defer c.Close()

	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 0x05 {
		return fmt.Errorf("bad handshake: %v", err)
	}
	if _, err := io.ReadFull(c, make([]byte, int(head[1]))); err != nil {
		return err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	cmd, atyp := req[1], req[3]
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		return fmt.Errorf("unsupported atyp %d", atyp)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return err
	}
	port := int(binary.BigEndian.Uint16(pb))

	if cmd == 0x03 { // UDP ASSOCIATE: reject, forcing the raw-UDP fallback
		_, err := c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}

	upstream, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer upstream.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	go func() {
		io.Copy(upstream, c)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(c, upstream)
	return nil
}

// TestCheckProxy_AutoUDPOnly verifies a node with a working UDP relay but no TCP listener:
// the TCP probe fails, the UDP probe succeeds, and the effective mode auto-derives to
// udp_only. The successful end-to-end UDP probe (via the raw fast path, since TCP is down)
// also records the raw capability.
func TestCheckProxy_AutoUDPOnly(t *testing.T) {
	dn, dnsPort := startFrameDNSServer(t)
	defer dn.Close()
	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: dnsPort}
	cfg := config.HealthCheckConf{
		Enabled:            true,
		URL:                "http://127.0.0.1:1/", // unreachable: no TCP listener at dnsPort
		Interval:           1,
		Timeout:            2,
		FailuresThreshold:  1,
		SuccessesThreshold: 1,
	}
	hc := NewHealthChecker(cfg, []*Proxy{p})
	defer hc.Stop()
	hc.checkProxy(p)

	if !p.IsUDPAvailable() {
		t.Fatal("expected UDP circuit closed: the DNS probe succeeded")
	}
	if lat := p.udpHealth.Snapshot().Latency; lat <= 0 {
		t.Errorf("expected UDP probe latency, got %v", lat)
	}
	if p.IsAvailable() {
		t.Error("expected TCP circuit open: the HTTP probe failed (no TCP listener)")
	}
	if got := p.EffectiveMode(); got != ModeUDPOnly {
		t.Errorf("expected auto-derived udp_only, got %q", got)
	}
	if got := p.UDPCapability(); got != UDPCapRaw {
		t.Errorf("expected UDPCapability=raw (raw relay proven by the probe), got %q", got)
	}
}

// TestCheckProxy_DeadUDPMarksNone verifies a fresh node whose UDP fails end to end (no
// ASSOCIATE, no answering raw relay) is marked UDPCapNone — the "否则不支持udp" case. Its TCP
// circuit also opens (no TCP listener), so the effective mode stays tcp_and_udp with both
// circuit snapshots reporting the outage.
func TestCheckProxy_DeadUDPMarksNone(t *testing.T) {
	p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: deadUDPPort(t)}
	cfg := config.HealthCheckConf{
		Enabled:            true,
		URL:                "http://127.0.0.1:1/",
		Interval:           1,
		Timeout:            1,
		FailuresThreshold:  1,
		SuccessesThreshold: 1,
	}
	hc := NewHealthChecker(cfg, []*Proxy{p})
	defer hc.Stop()
	hc.checkProxy(p)

	if p.IsUDPAvailable() {
		t.Error("expected UDP circuit open: no relay answers at the dead port")
	}
	if got := p.UDPCapability(); got != UDPCapNone {
		t.Errorf("expected UDPCapability=none for a fresh node whose UDP failed end to end, got %q", got)
	}
	if got := p.EffectiveMode(); got != ModeTCPAndUDP {
		t.Errorf("both circuits down -> expected tcp_and_udp (snapshots report the outage), got %q", got)
	}
}

// TestCheckProxy_ProbesTCPAndUDP proves the two circuits are independent on one node: the
// TCP HTTP probe succeeds (real tunnel to a local server) while the UDP probe fails (no
// UDP relay), so TCP stays healthy while UDP is marked down.
func TestCheckProxy_ProbesTCPAndUDP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	defer ts.Close()

	proxyAddr, done := startTunnelSOCKS5Mock(t)
	defer done()
	host, portStr, _ := net.SplitHostPort(proxyAddr)

	cfg := config.HealthCheckConf{
		Enabled:            true,
		URL:                ts.URL,
		Interval:           1,
		Timeout:            2,
		FailuresThreshold:  1,
		SuccessesThreshold: 1,
		OpenCoolDown:       60,
		UDPProbeDNS:        "127.0.0.1:1", // the frame target; nothing answers the raw relay
		UDPProbeDomain:     "dns.google",
	}
	p := &Proxy{Scheme: SchemeSOCKS5, Host: host, Port: parsePort(portStr)}
	hc := NewHealthChecker(cfg, []*Proxy{p})
	defer hc.Stop()

	hc.checkProxy(p)

	if !p.IsAvailable() {
		t.Fatal("TCP circuit must be closed: the HTTP probe succeeded")
	}
	if p.IsUDPAvailable() {
		t.Fatal("UDP circuit must be open: no UDP relay listens at the proxy address")
	}
}

// TestUDPHealth_IndependentCircuit verifies at the record level that opening one circuit
// never affects the other.
func TestUDPHealth_IndependentCircuit(t *testing.T) {
	cfg := config.HealthCheckConf{
		Enabled:            true,
		FailuresThreshold:  1,
		SuccessesThreshold: 1,
		OpenCoolDown:       60,
	}

	pu := &Proxy{URL: "socks5://127.0.0.1:1"}
	hcu := NewHealthChecker(cfg, []*Proxy{pu})
	defer hcu.Stop()
	hcu.RecordUDPFailure(pu, errors.New("udp relay down"))
	if pu.IsUDPAvailable() {
		t.Error("expected UDP circuit open after UDP failure")
	}
	if !pu.IsAvailable() {
		t.Error("TCP circuit must stay closed when only UDP fails")
	}

	pt := &Proxy{URL: "socks5://127.0.0.1:1"}
	hct := NewHealthChecker(cfg, []*Proxy{pt})
	defer hct.Stop()
	hct.RecordFailure(pt, errors.New("tcp connect failed"))
	if pt.IsAvailable() {
		t.Error("expected TCP circuit open after TCP failure")
	}
	if !pt.IsUDPAvailable() {
		t.Error("UDP circuit must stay closed when only TCP fails")
	}
}

// TestProbeUDP_ValidatesResponse checks the probe rejects anything that is not a valid
// DNS response: an echo of the query (QR=0) and a non-frame reply.
func TestProbeUDP_ValidatesResponse(t *testing.T) {
	hc := NewHealthChecker(config.HealthCheckConf{Enabled: true, Timeout: 2}, nil)
	defer hc.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	t.Run("echoed query is not a response", func(t *testing.T) {
		echo, echoPort := startUDPEcho(t)
		defer echo.Close()
		p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: echoPort}
		_, _, err := hc.probeUDP(p, ctx)
		if err == nil {
			t.Fatal("expected error when the relay echoes the query (QR=0)")
		}
		if !strings.Contains(err.Error(), "invalid DNS response") {
			t.Errorf("expected 'invalid DNS response', got: %v", err)
		}
	})

	t.Run("garbage reply", func(t *testing.T) {
		garbage, garbagePort := startGarbageUDPServer(t)
		defer garbage.Close()
		p := &Proxy{Scheme: SchemeSOCKS5, Host: "127.0.0.1", Port: garbagePort}
		if _, _, err := hc.probeUDP(p, ctx); err == nil {
			t.Fatal("expected error on garbage relay reply")
		}
	})
}

// TestUDPFrameRoundTrip guards the build/parse framing against off-by-one drift.
func TestUDPFrameRoundTrip(t *testing.T) {
	payload := []byte("hello-dns")
	for _, target := range []struct {
		host string
		port int
	}{
		{"1.1.1.1", 53},
		{"dns.example.com", 5353},
		{"2001:db8::1", 53},
	} {
		got, err := parseUDPFrame(buildUDPFrame(target.host, target.port, payload))
		if err != nil {
			t.Fatalf("parse(%s): %v", target.host, err)
		}
		if string(got) != string(payload) {
			t.Errorf("parse(%s) payload mismatch: got %q want %q", target.host, got, payload)
		}
	}
}
