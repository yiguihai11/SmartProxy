package admin

import (
	"os"
	"path/filepath"
	"testing"
)

// Dumps the en/zh dashboard variants for the node i18n smoke test
// (scripts/dashboard-i18n.test.js, wired into .github/workflows/go-test.yml).
// Normally skipped: it only acts when DASHBOARD_DUMP_DIR is set, so plain
// `go test ./...` has no side effects. The node script executes the real head
// JS (boot + zhBoot) against these files, which the string-level Go tests
// cannot do.
func TestDashboardDumpForNodeSmoke(t *testing.T) {
	dir := os.Getenv("DASHBOARD_DUMP_DIR")
	if dir == "" {
		t.Skip("DASHBOARD_DUMP_DIR not set; only CI's node smoke needs this")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"dashboard-en.html": dashboardHTML,
		"dashboard-zh.html": zhDashboardHTML,
	}
	for name, doc := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}
