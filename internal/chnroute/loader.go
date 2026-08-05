package chnroute

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
)

func Load(path string) (*Trie, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
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
