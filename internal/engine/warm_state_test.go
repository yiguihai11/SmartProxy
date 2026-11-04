package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"smartproxy/internal/config"
)

func TestEngine_WarmStateExportAndImport(t *testing.T) {
	dir := t.TempDir()
	aclPath := filepath.Join(dir, "acl.txt")
	require.NoError(t, os.WriteFile(aclPath, []byte("# empty acl\n"), 0o600))
	chnroutePath := filepath.Join(dir, "chnroute.txt")
	require.NoError(t, os.WriteFile(chnroutePath, []byte("1.0.1.0/24\n"), 0o600))

	cfg := config.DefaultConfig()
	cfg.Routing.ACLFile = aclPath
	cfg.Routing.ChnrouteFile = chnroutePath
	cfg.Listen.Port = 0
	cfg.Listen.AdminPort = 0
	cfg.Upstream.Proxies = []config.ProxyEntry{
		{Alias: "hk-node", URL: "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#HK"},
		{Alias: "us-node", URL: "ss://YWVzLTEyOC1nY206cGFzcw@5.6.7.8:8388#US"},
	}

	e1, err := New(cfg, dir)
	require.NoError(t, err)
	defer e1.Stop()

	// 1. Populate dynamic blacklist
	e1.Router.AddToBlacklist("bad.com", 443, "bad.com", "blocked")
	e1.Router.AddToBlacklist("9.9.9.9", 80, "", "timeout")

	// 2. Populate DNS cache
	e1.DNSHandler.CacheSet("example.com.", dns.TypeA, []byte("dnsWireA"), 60*time.Second)

	// 3. Populate node health & latencies
	hk := e1.UpstreamMgr.FindProxy("hk-node")
	require.NotNil(t, hk)
	hk.SetGeoInfo("HK", "1.2.3.4")
	hk.SetPingLatency(45 * time.Millisecond)

	us := e1.UpstreamMgr.FindProxy("us-node")
	require.NotNil(t, us)
	// Manually disable US node
	require.NoError(t, e1.UpstreamMgr.SetCircuitHealth("us-node", "tcp", "disable"))

	// Export warm state
	data, err := e1.ExportWarmStateJSON()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Save warm_state.json into a new engine directory
	dir2 := t.TempDir()
	aclPath2 := filepath.Join(dir2, "acl.txt")
	require.NoError(t, os.WriteFile(aclPath2, []byte("# empty acl\n"), 0o600))
	chnroutePath2 := filepath.Join(dir2, "chnroute.txt")
	require.NoError(t, os.WriteFile(chnroutePath2, []byte("1.0.1.0/24\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir2, WarmStateFileName), data, 0o600))

	cfg2 := config.DefaultConfig()
	cfg2.Routing.ACLFile = aclPath2
	cfg2.Routing.ChnrouteFile = chnroutePath2
	cfg2.Listen.Port = 0
	cfg2.Listen.AdminPort = 0
	cfg2.Upstream.Proxies = []config.ProxyEntry{
		{Alias: "hk-node", URL: "ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#HK"},
		{Alias: "us-node", URL: "ss://YWVzLTEyOC1nY206cGFzcw@5.6.7.8:8388#US"},
	}

	// New engine e2 should automatically load warm_state.json from dir2
	e2, err := New(cfg2, dir2)
	require.NoError(t, err)
	defer e2.Stop()

	// Verify Blacklist restored
	ipBL, domainBL := e2.Router.BlacklistSnapshot()
	assert.NotEmpty(t, ipBL)
	assert.NotEmpty(t, domainBL)

	// Verify DNS Cache restored
	cached := e2.DNSHandler.CacheGet("example.com.", dns.TypeA)
	assert.Equal(t, []byte("dnsWireA"), cached)

	// Verify Node States restored
	hk2 := e2.UpstreamMgr.FindProxy("hk-node")
	require.NotNil(t, hk2)
	assert.Equal(t, "HK", hk2.CountryCode())
	assert.Equal(t, 45*time.Millisecond, hk2.PingLatency())

	us2 := e2.UpstreamMgr.FindProxy("us-node")
	require.NotNil(t, us2)
	assert.True(t, us2.V4TCPAvailable() == false)
}
