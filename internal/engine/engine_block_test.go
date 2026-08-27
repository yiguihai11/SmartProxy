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
