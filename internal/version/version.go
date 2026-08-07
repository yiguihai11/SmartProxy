package version

import (
	"fmt"
	"runtime"
)

// Build metadata. Each field is overridden at build time via ldflags, e.g.:
//
//	go build -ldflags "-X smartproxy/internal/version.Version=1.1.0 \
//	                  -X smartproxy/internal/version.GitCommit=abc1234 \
//	                  -X smartproxy/internal/version.BuildTime=2026-08-05T12:00:00Z"
//
// Fields must be vars, not consts: `-X` can only rewrite mutable package
// variables. The "unknown" defaults let binaries compiled without ldflags
// degrade gracefully instead of printing empty strings.
var (
	// Version is the release version, normally derived from a git tag
	// (e.g. "1.1.0"). make build injects it automatically.
	Version = "1.0.0"
	// GitCommit is the short commit hash the binary was built from.
	GitCommit = "unknown"
	// BuildTime is the UTC build timestamp (RFC3339).
	BuildTime = "unknown"
)

// GoVersion is the Go toolchain version the binary was built with.
func GoVersion() string { return runtime.Version() }

// String returns a compact one-line banner, e.g.:
//
//	smartproxy 1.1.0 (commit abc1234, built 2026-08-05T12:00:00Z, go1.25.0)
func String() string {
	return fmt.Sprintf("smartproxy %s (commit %s, built %s, %s)",
		Version, GitCommit, BuildTime, GoVersion())
}

// Info returns the full set of version fields, exposed by the admin
// /version endpoint.
func Info() map[string]string {
	return map[string]string{
		"version":    Version,
		"commit":     GitCommit,
		"build_time": BuildTime,
		"go_version": GoVersion(),
	}
}
