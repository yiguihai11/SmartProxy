package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// FindSingBoxExecutable attempts to find a valid sing-box binary on the system dynamically.
func FindSingBoxExecutable(preferredPath string) string {
	if preferredPath != "" {
		if fi, err := os.Stat(preferredPath); err == nil && !fi.IsDir() {
			return preferredPath
		}
	}

	// 1. Check system PATH first
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}

	// 2. Check user's home directory dynamically
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		userPaths := []string{
			filepath.Join(home, "lantern_re", "bin", "sing-box"),
			filepath.Join(home, "bin", "sing-box"),
			filepath.Join(home, ".local", "bin", "sing-box"),
		}
		for _, p := range userPaths {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}

	// 3. Check environment prefixes if available (e.g. Termux $PREFIX/bin/sing-box)
	if prefix := os.Getenv("PREFIX"); prefix != "" {
		p := filepath.Join(prefix, "bin", "sing-box")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}

	// 4. Standard unix paths
	stdPaths := []string{
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	}
	for _, p := range stdPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}

	return ""
}

func getFreePorts(count int) ([]int, error) {
	var ports []int
	var listeners []net.Listener
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return nil, err
		}
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
		listeners = append(listeners, ln)
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	return ports, nil
}

type testInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type testRouteRule struct {
	Inbound  []string `json:"inbound"`
	Outbound string   `json:"outbound"`
}

type testSingBoxConfig struct {
	Log struct {
		Level string `json:"level"`
	} `json:"log"`
	Inbounds  []testInbound     `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     struct {
		Rules []testRouteRule `json:"rules"`
	} `json:"route"`
}

// TestAndFilterNodes verifies internet connectivity for each node using sing-box and returns only working nodes.
func TestAndFilterNodes(ctx context.Context, nodes []json.RawMessage, singboxBin string, testURL string, timeout time.Duration) ([]json.RawMessage, error) {
	if len(nodes) == 0 {
		return nodes, nil
	}

	if singboxBin == "" {
		singboxBin = FindSingBoxExecutable("")
	}
	if singboxBin == "" {
		return nodes, fmt.Errorf("sing-box binary not found, skipping node connectivity testing")
	}

	if testURL == "" {
		testURL = "http://cp.cloudflare.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	ports, err := getFreePorts(len(nodes))
	if err != nil {
		return nil, fmt.Errorf("failed to allocate test ports: %w", err)
	}

	// Prepare sing-box probe config
	var sbCfg testSingBoxConfig
	sbCfg.Log.Level = "warn"
	sbCfg.Outbounds = nodes

	nodeTags := make([]string, len(nodes))
	for i, raw := range nodes {
		var meta struct {
			Tag string `json:"tag"`
		}
		_ = json.Unmarshal(raw, &meta)
		tag := meta.Tag
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		nodeTags[i] = tag

		inTag := fmt.Sprintf("in-%s", tag)
		sbCfg.Inbounds = append(sbCfg.Inbounds, testInbound{
			Type:       "socks",
			Tag:        inTag,
			Listen:     "127.0.0.1",
			ListenPort: ports[i],
		})

		sbCfg.Route.Rules = append(sbCfg.Route.Rules, testRouteRule{
			Inbound:  []string{inTag},
			Outbound: tag,
		})
	}

	cfgBytes, err := json.MarshalIndent(sbCfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize test config: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "lantern_test_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpCfgPath := filepath.Join(tmpDir, "test_config.json")
	if err := os.WriteFile(tmpCfgPath, cfgBytes, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp test config: %w", err)
	}

	// Start sing-box runner
	procCtx, cancelProc := context.WithCancel(ctx)
	defer cancelProc()

	cmd := exec.CommandContext(procCtx, singboxBin, "run", "-c", tmpCfgPath)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sing-box for testing: %w", err)
	}
	defer func() {
		cancelProc()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	// Wait up to 1.5s for the first port to be ready
	ready := false
	firstPort := ports[0]
	for i := 0; i < 15; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", firstPort), 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return nil, fmt.Errorf("sing-box failed to start listening within timeout")
	}

	// Concurrently test each node
	type testResult struct {
		index int
		alive bool
	}

	resChan := make(chan testResult, len(nodes))
	var wg sync.WaitGroup

	for i, port := range ports {
		wg.Add(1)
		go func(idx, p int) {
			defer wg.Done()
			alive := probeNode(ctx, p, testURL, timeout)
			resChan <- testResult{index: idx, alive: alive}
		}(i, port)
	}

	wg.Wait()
	close(resChan)

	aliveMap := make(map[int]bool)
	for res := range resChan {
		if res.alive {
			aliveMap[res.index] = true
		}
	}

	var workingNodes []json.RawMessage
	for i, node := range nodes {
		if aliveMap[i] {
			workingNodes = append(workingNodes, node)
		}
	}

	return workingNodes, nil
}

func probeNode(ctx context.Context, socksPort int, testURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent
}
