package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"smartproxy/internal/config"

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


