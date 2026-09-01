package chnroute

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
)

// maxChnrouteSize caps how much of a chnroute file Load will read. Real delegated
// prefix lists are a few MiB; 64 MiB leaves huge headroom. The cap exists because
// /files/validate takes an arbitrary path — an unbounded ReadAll on /dev/zero (or a
// giant sparse file) would be a one-request OOM that takes the proxy down.
const maxChnrouteSize = 64 << 20 // 64 MiB

func Load(path string) (*Trie, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read cap+1 so a file at/over the limit is reported rather than parsed truncated.
	data, err := io.ReadAll(io.LimitReader(f, maxChnrouteSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxChnrouteSize {
		return nil, fmt.Errorf("chnroute file too large (>%d MiB)", maxChnrouteSize>>20)
	}

	prefixes, err := parsePrefixes(data)
	if err != nil {
		return nil, err
	}

	count := len(prefixes)
	if count > 0 {
		slog.Info("loaded domestic CIDR prefixes", "count", count)
	} else {
		slog.Warn("no valid CIDR loaded, DNS pollution detection will be disabled", "path", path)
	}

	t := New()
	t.InsertBatch(prefixes)
	return t, nil
}

// Parse parses CIDR/address lines from raw bytes into a new Trie.
// Blank lines and # comments are ignored, invalid lines are skipped; when there are no valid
// prefixes an empty Trie is returned (IsEmpty() is true).
func Parse(data []byte) (*Trie, error) {
	prefixes, err := parsePrefixes(data)
	if err != nil {
		return nil, err
	}
	t := New()
	t.InsertBatch(prefixes)
	return t, nil
}

func parsePrefixes(data []byte) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			addr, err2 := netip.ParseAddr(line)
			if err2 != nil {
				slog.Debug("skipping invalid CIDR line", "line", line, "error", err)
				continue
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		prefixes = append(prefixes, prefix)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return prefixes, nil
}
