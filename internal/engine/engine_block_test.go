package engine

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"smartproxy/internal/config"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBlockEngine 搭最小 Engine:只配 Routing.ACLFile,其余字段零值即可
// (BlockConnection 只读 Config)。
func newBlockEngine(t *testing.T, aclPath string) *Engine {
	t.Helper()
	e := &Engine{}
	e.Config.Store(&config.Config{Routing: config.RoutingConf{ACLFile: aclPath}})
	return e
}

func readACL(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return string(b)
}

func TestBlockConnection_NoACLConfigured(t *testing.T) {
	e := newBlockEngine(t, "")
	err := e.BlockConnection("example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acl_file not configured")
}

func TestBlockConnection_DomainNormalized_CreatesFile(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	e := newBlockEngine(t, acl)
	require.NoError(t, e.BlockConnection("Example.COM."))

	// 文件不存在时建文件,域名小写化、去尾点。
	content := readACL(t, acl)
	assert.Contains(t, content, "block domain example.com")
	assert.NotContains(t, content, "Example.COM.")
}

func TestBlockConnection_IP(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	e := newBlockEngine(t, acl)
	require.NoError(t, e.BlockConnection("1.2.3.4"))
	assert.Contains(t, readACL(t, acl), "block ip 1.2.3.4")
}

func TestBlockConnection_IPv6BracketsStripped(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	e := newBlockEngine(t, acl)
	require.NoError(t, e.BlockConnection("[2001:db8::1]"))
	content := readACL(t, acl)
	assert.Contains(t, content, "block ip 2001:db8::1")
	assert.NotContains(t, content, "[")
}

func TestBlockConnection_Dedup(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	require.NoError(t, os.WriteFile(acl, []byte("block domain example.com\n"), 0o644))
	e := newBlockEngine(t, acl)
	require.NoError(t, e.BlockConnection("EXAMPLE.com"))
	// 已存在的行直接返回,不重复追加。
	assert.Equal(t, 1, strings.Count(readACL(t, acl), "block domain example.com"))
}

func TestBlockConnection_PreservesExisting(t *testing.T) {
	acl := filepath.Join(t.TempDir(), "acl.txt")
	require.NoError(t, os.WriteFile(acl, []byte("# comment\nallow domain safe.example\n"), 0o644))
	e := newBlockEngine(t, acl)
	require.NoError(t, e.BlockConnection("evil.example"))
	content := readACL(t, acl)
	assert.Contains(t, content, "block domain evil.example")
	assert.Contains(t, content, "allow domain safe.example")
}

func TestEngine_ReloadConfig_ValidationFailure_PreservesOriginalConfig(t *testing.T) {
	origCfg := config.DefaultConfig()
	origCfg.Routing.ACLFile = "/valid/acl.txt"
	origCfg.Routing.ChnrouteFile = "/valid/chnroute.txt"

	e := &Engine{}
	e.Config.Store(origCfg)

	// 新配置具有非法验证参数 (如 query_timeout <= 0)
	badCfg := config.DefaultConfig()
	badCfg.DNS.QueryTimeout = 0

	err := e.ReloadConfig(badCfg, t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config validation failed")

	// 验证 Config 指针未被污染
	curCfg := e.Config.Load()
	assert.Same(t, origCfg, curCfg)
	assert.Equal(t, "/valid/acl.txt", curCfg.Routing.ACLFile)
}

func TestEngine_ReloadConfig_InvalidACLFile_FailsFastWithoutStore(t *testing.T) {
	dir := t.TempDir()
	validACL := filepath.Join(dir, "valid_acl.txt")
	require.NoError(t, os.WriteFile(validACL, []byte("allow port 80\n"), 0o644))

	origCfg := config.DefaultConfig()
	origCfg.Routing.ACLFile = validACL
	origCfg.Routing.ChnrouteFile = filepath.Join(dir, "chnroute.txt")
	require.NoError(t, os.WriteFile(origCfg.Routing.ChnrouteFile, []byte("1.0.1.0/24\n"), 0o644))

	e, err := New(origCfg, dir)
	require.NoError(t, err)

	// 新配置指向不存在的 ACL 路径
	newCfg := config.DefaultConfig()
	newCfg.Routing.ACLFile = filepath.Join(dir, "non_existent_acl.txt")
	newCfg.Routing.ChnrouteFile = origCfg.Routing.ChnrouteFile

	err = e.ReloadConfig(newCfg, dir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to pre-load ACL rules")

	// 核心断言：e.Config 依然是旧配置，未被更新
	assert.Equal(t, validACL, e.Config.Load().Routing.ACLFile)
}

func TestEngine_ReloadConfig_ACLParseFailure_DoesNotMutateChnrouteOrConfig(t *testing.T) {
	dir := t.TempDir()
	validACL := filepath.Join(dir, "valid_acl.txt")
	require.NoError(t, os.WriteFile(validACL, []byte("allow port 80\n"), 0o644))

	chn1 := filepath.Join(dir, "chn1.txt")
	require.NoError(t, os.WriteFile(chn1, []byte("10.0.0.0/8\n"), 0o644))

	chn2 := filepath.Join(dir, "chn2.txt")
	require.NoError(t, os.WriteFile(chn2, []byte("20.0.0.0/8\n"), 0o644))

	origCfg := config.DefaultConfig()
	origCfg.Routing.ACLFile = validACL
	origCfg.Routing.ChnrouteFile = chn1

	e, err := New(origCfg, dir)
	require.NoError(t, err)

	// 新配置欲更新 chnroute 为 chn2，但 ACL 路径非法
	newCfg := config.DefaultConfig()
	newCfg.Routing.ChnrouteFile = chn2
	newCfg.Routing.ACLFile = filepath.Join(dir, "corrupted_or_missing_acl.txt")

	err = e.ReloadConfig(newCfg, dir)
	assert.Error(t, err)

	// 核心断言 1: Config 维持旧配置
	assert.Equal(t, chn1, e.Config.Load().Routing.ChnrouteFile)

	// 核心断言 2: Chnroute 运行时未被部分更新，仍属于 chn1（不含 20.0.0.1）
	assert.False(t, e.Chnroute.Contains(net.ParseIP("20.0.0.1")), "chnroute must NOT be partially updated if ACL fails")
	assert.True(t, e.Chnroute.Contains(net.ParseIP("10.0.0.1")), "original chnroute must stay intact")
}

func TestShouldFilterAAAA(t *testing.T) {
	// 1. Nil config
	assert.False(t, shouldFilterAAAA(nil))

	// 2. Explicit filter_aaaa
	cfg1 := config.DefaultConfig()
	cfg1.DNS.FilterAAAA = true
	assert.True(t, shouldFilterAAAA(cfg1))

	// 3. TUN enabled with IPv4 only (e.g. user turned off IPv6 interception on Android)
	cfg2 := config.DefaultConfig()
	cfg2.TUN.Enabled = true
	cfg2.TUN.Address = []string{"172.19.0.1/30"}
	cfg2.DNS.FilterAAAA = false
	assert.True(t, shouldFilterAAAA(cfg2), "TUN with IPv4 only must filter AAAA")

	// 4. TUN enabled with dual-stack (IPv4 + IPv6)
	cfg3 := config.DefaultConfig()
	cfg3.TUN.Enabled = true
	cfg3.TUN.Address = []string{"172.19.0.1/30", "fc00::1/64"}
	cfg3.DNS.FilterAAAA = false
	assert.False(t, shouldFilterAAAA(cfg3), "TUN with dual-stack must NOT filter AAAA")

	// 5. TUN disabled and filter_aaaa false (pure SOCKS proxy mode)
	cfg4 := config.DefaultConfig()
	cfg4.TUN.Enabled = false
	cfg4.DNS.FilterAAAA = false
	assert.False(t, shouldFilterAAAA(cfg4))
}

func TestEngine_HandleNetworkChange(t *testing.T) {
	// Verify zero-value or initialized Engine handles network change safely without panic
	e := &Engine{}
	e.HandleNetworkChange()
}

func TestEngine_Adblock_Stop_Lifecycle(t *testing.T) {
	dir := t.TempDir()
	aclPath := filepath.Join(dir, "acl.txt")
	require.NoError(t, os.WriteFile(aclPath, []byte("allow port 80\n"), 0o644))
	chnPath := filepath.Join(dir, "chnroute.txt")
	require.NoError(t, os.WriteFile(chnPath, []byte("1.0.1.0/24\n"), 0o644))

	cfg := config.DefaultConfig()
	cfg.Routing.ACLFile = aclPath
	cfg.Routing.ChnrouteFile = chnPath
	cfg.DNS.Adblock.Enabled = true
	cfg.DNS.Adblock.CacheFile = "adblock_cache.txt"

	e, err := New(cfg, dir)
	require.NoError(t, err)
	require.NotNil(t, e.adblockMgr)

	// Engine.Stop() must cleanly stop adblockMgr without deadlock or goroutine leak
	e.Stop()
}

func TestEngine_ACL_Adblock_Interaction(t *testing.T) {
	dir := t.TempDir()
	aclContent := "block domain acl-blocked.com\nallow domain acl-allowed-but-ad-blocked.com\n"
	aclPath := filepath.Join(dir, "acl.txt")
	require.NoError(t, os.WriteFile(aclPath, []byte(aclContent), 0o644))

	chnPath := filepath.Join(dir, "chnroute.txt")
	require.NoError(t, os.WriteFile(chnPath, []byte("1.0.1.0/24\n"), 0o644))

	cacheContent := "||acl-allowed-but-ad-blocked.com^\n||ad-only-blocked.com^\n"
	cachePath := filepath.Join(dir, "adblock_cache.txt")
	require.NoError(t, os.WriteFile(cachePath, []byte(cacheContent), 0o644))

	cfg := config.DefaultConfig()
	cfg.Routing.ACLFile = aclPath
	cfg.Routing.ChnrouteFile = chnPath
	cfg.DNS.Enabled = true
	cfg.DNS.StaticRecords = []config.StaticRecord{
		{Host: "ad-override.com", IP: []string{"192.168.1.100"}},
	}
	cfg.DNS.Adblock.Enabled = true
	cfg.DNS.Adblock.CacheFile = cachePath

	e, err := New(cfg, dir)
	require.NoError(t, err)
	defer e.Stop()

	// Wait for adblock manager startup to load disk cache
	for i := 0; i < 20; i++ {
		st := e.adblockMgr.Status()
		if st.CacheCount >= 2 {
			break
		}
		// give startup goroutine time to parse cache
		time.Sleep(20 * time.Millisecond)
	}

	query := func(domain string) (isBlocked bool, ips []string) {
		m := new(mdns.Msg)
		m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
		wire, err := m.Pack()
		require.NoError(t, err)

		respWire := e.DNSHandler.HandleDNS(context.Background(), wire, "1.1.1.1", 53, e.RuleEng)
		if respWire == nil {
			return false, nil
		}
		resp := new(mdns.Msg)
		require.NoError(t, resp.Unpack(respWire))
		for _, ans := range resp.Answer {
			if a, ok := ans.(*mdns.A); ok {
				ip := a.A.String()
				ips = append(ips, ip)
				if ip == "0.0.0.0" {
					isBlocked = true
				}
			}
		}
		return isBlocked, ips
	}

	// 1. static_records takes highest precedence over both ACL and AdBlock
	blocked, ips := query("ad-override.com")
	assert.False(t, blocked)
	assert.Contains(t, ips, "192.168.1.100")

	// 2. ACL block takes precedence before AdBlock
	blocked, ips = query("acl-blocked.com")
	assert.True(t, blocked)
	assert.Contains(t, ips, "0.0.0.0")

	// 3. ACL allow domain does NOT exempt AdBlock (DevPlan §0.2 constraint 3)
	blocked, ips = query("acl-allowed-but-ad-blocked.com")
	assert.True(t, blocked, "ACL allow domain must NOT exempt adblock filtering")
	assert.Contains(t, ips, "0.0.0.0")

	// 4. Adblock-only rule blocks as expected
	blocked, ips = query("ad-only-blocked.com")
	assert.True(t, blocked)
	assert.Contains(t, ips, "0.0.0.0")
}

