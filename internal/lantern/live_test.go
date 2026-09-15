package lantern

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestLiveNodesConnectivity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := New(Config{
		DataDir:         "/data/data/com.termux/files/home",
		AccountsFile:    "accounts.json",
		NodesFile:       "lantern_nodes.json",
		MaxAccounts:     5,
		EnableSSE:       false,
		SingBoxPath:     "/data/data/com.termux/files/home/lantern_re/bin/sing-box",
		TestURL:         "http://cp.cloudflare.com/generate_204",
		TestTimeout:     5 * time.Second,
		FilterDeadNodes: true,
	})
	if err != nil {
		t.Fatalf("client init failed: %v", err)
	}

	accs := client.GetAccountManager().List()
	t.Logf("Local accounts: %d (Max: 5)", len(accs))
	for i, a := range accs {
		t.Logf("  [%d] Device: %s, UserID: %d, Allot: %d, Used: %d, QuotaOK: %v",
			i+1, a.DeviceID, a.UserID, a.Allot, a.Used, a.QuotaOK)
	}

	nodes, err := client.EnsureNodes(ctx)
	if err != nil {
		t.Fatalf("EnsureNodes failed: %v", err)
	}

	t.Logf("Tested and verified working nodes count: %d", len(nodes))
	for i, n := range nodes {
		var meta struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
		}
		_ = json.Unmarshal(n, &meta)
		t.Logf("  [%d] type: %-12s target: %-22s tag: %s",
			i+1, meta.Type, fmt.Sprintf("%s:%d", meta.Server, meta.ServerPort), meta.Tag)
	}

	sbBytes, err := BuildCompleteSingBoxConfig(nodes, 2080)
	if err != nil {
		t.Fatalf("BuildCompleteSingBoxConfig failed: %v", err)
	}
	t.Logf("Complete sing-box config generated: %d bytes", len(sbBytes))
}
