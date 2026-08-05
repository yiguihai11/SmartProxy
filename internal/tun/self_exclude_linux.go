//go:build linux

package tun

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// selfExcludeRulePriority is the priority of the self-exclude rule: it must match before
// sing-tun auto_route's hijack rule (default IPRoute2RuleIndex=9000), so marked packets hit the main table first.
const selfExcludeRulePriority = 8999

// nftTable is the name of a dedicated nftables table; the whole table is deleted on Close without affecting other rules.
const nftTable = "smartproxy"

// installSelfExclude installs the "exclude self" rules when auto_route=true (full hijack):
//  1. ip rule (v4+v6): `fwmark <mark> lookup main` — packets marked by the router itself bypass the TUN hijack;
//  2. nftables output chain (type route, only changes mark without dropping packets): packets for the excluded
//     ports (default 22 SSH) are also marked, likewise bypassing the hijack.
//
// It returns a cleanup function. Any step that fails returns an error: the caller must abort TUN startup,
// otherwise it is an auto_route full hijack with no exclusion (server SSH hangs).
func installSelfExclude(mark int, excludePorts []int) (func(), error) {
	// First clean up leftovers from the previous crash/exit (idempotent): if a stale 8999 rule remains,
	// RuleAdd with NLM_F_EXCL will fail and prevent startup.
	cleanupStaleSelfExclude()

	var cleanups []func()

	// 1. ip rule: fwmark <mark> lookup main (v4 + v6)
	families := []int{netlink.FAMILY_V4, netlink.FAMILY_V6}
	var rules []*netlink.Rule
	for _, family := range families {
		rule := netlink.NewRule()
		rule.Priority = selfExcludeRulePriority
		rule.Family = family
		rule.Mark = uint32(mark)
		rule.MarkSet = true
		rule.Table = unix.RT_TABLE_MAIN
		if err := netlink.RuleAdd(rule); err != nil {
			for _, added := range rules {
				_ = netlink.RuleDel(added)
			}
			return nil, fmt.Errorf("add self-exclude ip rule (family %d): %w", family, err)
		}
		rules = append(rules, rule)
	}
	cleanups = append(cleanups, func() {
		for _, rule := range rules {
			if err := netlink.RuleDel(rule); err != nil {
				slog.Warn("TUN failed to delete self-exclude ip rule", "family", rule.Family, "error", err)
			}
		}
	})

	// 2. nftables output chain marks packets for the excluded ports
	if len(excludePorts) > 0 {
		if err := setupNFTOutputMark(mark, excludePorts); err != nil {
			for _, fn := range cleanups {
				fn()
			}
			return nil, err
		}
		cleanups = append(cleanups, func() {
			if err := cleanupNFTOutputMark(); err != nil {
				slog.Warn("TUN failed to delete nftables output mark table", "error", err)
			}
		})
	}

	return func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}, nil
}

// cleanupStaleSelfExclude removes self-exclude rules left over from the previous crash/exit (idempotent):
// the priority-8999 mark rules (v4+v6) plus the smartproxy nft table.
// If a stale 8999 rule remains, the next RuleAdd with NLM_F_EXCL will fail and prevent startup.
func cleanupStaleSelfExclude() {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: selfExcludeRulePriority}, netlink.RT_FILTER_PRIORITY)
		if err != nil {
			slog.Warn("TUN failed to list self-exclude rules for stale cleanup", "family", family, "error", err)
			continue
		}
		for i := range rules {
			if rules[i].MarkSet {
				if err := netlink.RuleDel(&rules[i]); err != nil {
					slog.Warn("TUN failed to delete stale self-exclude rule", "family", family, "error", err)
				}
			}
		}
	}
	// nft table (returns an error if absent; ignore it)
	_ = cleanupNFTOutputMark()
}

// setupNFTOutputMark creates a dedicated table plus an output chain (type route, only changes mark without dropping packets),
// and marks outbound packets for the excluded ports.
func setupNFTOutputMark(mark int, excludePorts []int) error {
	if err := runNft("add", "table", "inet", nftTable); err != nil {
		return err
	}
	chain := fmt.Sprintf("{ type route hook output priority mangle; policy accept; }")
	if err := runNft("add", "chain", "inet", nftTable, "output", chain); err != nil {
		return err
	}
	// Mark both server-side responses (sport) and the router's outbound connections (dport)
	for _, port := range excludePorts {
		for _, dir := range []string{"sport", "dport"} {
			rule := fmt.Sprintf("tcp %s %d meta mark set 0x%x", dir, port, mark)
			if err := runNft("add", "rule", "inet", nftTable, "output", rule); err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanupNFTOutputMark deletes the whole table (including all chains/rules), without affecting other nftables rules.
func cleanupNFTOutputMark() error {
	return runNft("delete", "table", "inet", nftTable)
}

// runNft invokes the nft binary with a 10s timeout to prevent hanging.
func runNft(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
