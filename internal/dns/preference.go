package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"smartproxy/internal/fwmark"
	"smartproxy/internal/safego"
)

type PreferMode string

const (
	PreferNone PreferMode = ""
	PreferPing PreferMode = "ping"
	PreferTCP  PreferMode = "tcp"
)

type Preference struct {
	enabled   bool
	mode      PreferMode
	tcpPorts  []int
	hasPing   bool
	hasPing6  bool
	pingPath  string
	ping6Path string
}

func ParseSpeedCheckMode(modeStr string) (PreferMode, []int) {
	modeStr = strings.TrimSpace(strings.ToLower(modeStr))
	if modeStr == "" {
		return PreferNone, nil
	}
	if modeStr == "ping" {
		return PreferPing, nil
	}
	if strings.HasPrefix(modeStr, "tcp:") {
		portsStr := modeStr[4:]
		var ports []int
		for _, part := range strings.Split(portsStr, ",") {
			part = strings.TrimSpace(part)

			part = strings.TrimPrefix(part, "tcp:")

			var port int
			if n := fmtSscanf(part, &port); n > 0 && port >= 1 && port <= 65535 {
				ports = append(ports, port)
			}
		}
		if len(ports) > 0 {
			return PreferTCP, ports
		}
	}
	slog.Warn("unsupported speed-check-mode, disabling IP preference", "mode", modeStr)
	return PreferNone, nil
}

func fmtSscanf(s string, p *int) int {
	n, _ := fmt.Sscanf(strings.TrimSpace(s), "%d", p)
	return n
}

func NewPreference(enabled bool, mode PreferMode, tcpPorts []int) *Preference {
	p := &Preference{
		enabled:  enabled,
		mode:     mode,
		tcpPorts: tcpPorts,
	}

	if mode == PreferPing {
		p.checkPingCommands()
	}

	if enabled {
		slog.Info("DNS IP preference enabled", "mode", mode, "tcpPorts", tcpPorts)
	}
	return p
}

func (p *Preference) checkPingCommands() {

	pingPath, err := exec.LookPath("ping")
	if err != nil {
		slog.Warn("ping command not available, fallback to TCP for IPv4", "error", err)
	} else if err := exec.Command(pingPath, "-c1", "-W1", "127.0.0.1").Run(); err != nil {
		slog.Warn("ping command not available, fallback to TCP for IPv4", "error", err)
	} else {
		p.hasPing = true
		p.pingPath = pingPath
	}

	ping6Path, err := exec.LookPath("ping6")
	if err != nil {
		slog.Warn("ping6 command not available, fallback to TCP for IPv6", "error", err)
	} else if err := exec.Command(ping6Path, "-c1", "-W1", "::1").Run(); err != nil {
		slog.Warn("ping6 command not available, fallback to TCP for IPv6", "error", err)
	} else {
		p.hasPing6 = true
		p.ping6Path = ping6Path
	}
}

func (p *Preference) PreferIPs(ctx context.Context, ips []string) string {
	if !p.enabled || len(ips) <= 1 {
		if len(ips) == 1 {
			return ips[0]
		}
		return ""
	}

	type result struct {
		ip  string
		lat time.Duration
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []result
	)

	for _, ip := range ips {
		wg.Add(1)
		safego.Go("dns.prefetch", func() {
			ip := ip
			defer wg.Done()
			var lat time.Duration
			var ok bool
			switch p.mode {
			case PreferPing:
				lat, ok = p.pingLatency(ctx, ip)
			case PreferTCP:
				lat, ok = p.tcpLatency(ctx, ip)
			default:
				return
			}
			if ok {
				mu.Lock()
				results = append(results, result{ip: ip, lat: lat})
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	var bestIP string
	var bestLatency time.Duration = 1<<63 - 1
	for _, r := range results {
		if r.lat < bestLatency {
			bestLatency = r.lat
			bestIP = r.ip
		}
	}

	if bestIP != "" {
		slog.Info("DNS preference selected", "ip", bestIP, "latency", bestLatency)
	}
	return bestIP
}

var pingTimeRe = regexp.MustCompile(`time=([0-9.]+) ms`)

func (p *Preference) pingLatency(ctx context.Context, ip string) (time.Duration, bool) {
	isV6 := strings.Contains(ip, ":")
	if isV6 && !p.hasPing6 {
		return 0, false
	}
	if !isV6 && !p.hasPing {
		return 0, false
	}

	cmd := p.pingPath
	if isV6 {
		cmd = p.ping6Path
	}

	c, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(c, cmd, "-c1", "-W0.5", ip).Output()
	if err != nil {
		return 0, false
	}

	match := pingTimeRe.FindSubmatch(out)
	if match == nil {
		return 50 * time.Millisecond, true
	}

	var ms float64
	fmt.Sscanf(string(match[1]), "%f", &ms)
	return time.Duration(ms * float64(time.Millisecond)), true
}

func (p *Preference) tcpLatency(ctx context.Context, ip string) (time.Duration, bool) {
	for _, port := range p.tcpPorts {
		d := net.Dialer{Timeout: 2 * time.Second, Control: fwmark.Control}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
		if err != nil {
			continue
		}
		lat := time.Since(start)
		conn.Close()
		return lat, true
	}
	return 0, false
}
