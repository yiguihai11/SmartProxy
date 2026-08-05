//go:build linux

package tun

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// installSelectiveRoutes installs, when auto_route=false, policy routing for each address family so that
// only traffic whose source address is in the TUN subnet goes through tun0 (equivalent to the source-rule part
// of sing-tun auto_route, but without installing the from 0.0.0.0 full hijack), which is safe for server/SSH scenarios.
// Implemented only on Linux (netlink); see selective_route_other.go for other platforms.
func (h *TUNHandler) installSelectiveRoutes(iface string, inet4, inet6 []netip.Prefix) {
	var cleanups []func()
	if len(inet4) > 0 {
		if cleanup, err := installSelectiveSourceRoute(iface, inet4[0], netlink.FAMILY_V4); err != nil {
			slog.Warn("TUN failed to install IPv4 selective source route", "error", err)
		} else {
			cleanups = append(cleanups, cleanup)
		}
	}
	if len(inet6) > 0 {
		if cleanup, err := installSelectiveSourceRoute(iface, inet6[0], netlink.FAMILY_V6); err != nil {
			slog.Warn("TUN failed to install IPv6 selective source route", "error", err)
		} else {
			cleanups = append(cleanups, cleanup)
		}
	}
	if len(cleanups) > 0 {
		h.setSelectiveCleanup(cleanups)
	}
}

// installSelectiveSourceRoute installs policy routing so that only traffic whose source address is in the TUN subnet
// goes through tun0: it creates a dedicated routing table holding the default route (default dev tun0) and adds a policy
// rule `from <subnet> lookup <table>`. This is equivalent to the "source rule" part of sing-tun auto_route, but without
// installing the from 0.0.0.0 full hijack, so the server itself (including SSH) is unaffected.
// It returns a cleanup function that deletes the policy rule and the routing table.
func installSelectiveSourceRoute(iface string, prefix netip.Prefix, family int) (func(), error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("lookup link %s: %w", iface, err)
	}
	ifIndex := link.Attrs().Index

	table, err := findFreeRouteTable(family)
	if err != nil {
		return nil, err
	}

	// Default route: default dev tun0 table <table> (dev-only, no gateway, scope link).
	// The kernel rejects dev-only routes with onlink/all-zero gateways ("ONLINK can not be set");
	// the correct form is Dst=default prefix + no Gw + no Flags, with scope inferred as link from dev-only.
	var dst *net.IPNet
	if family == netlink.FAMILY_V4 {
		dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	} else {
		dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	route := &netlink.Route{
		LinkIndex: ifIndex,
		Dst:       dst,
		Table:     table,
		Scope:     netlink.SCOPE_LINK,
		Type:      int(unix.RTN_UNICAST),
	}
	if err := netlink.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("add default route dev %s table %d: %w", iface, table, err)
	}

	// Policy rule: from <prefix> lookup <table> pref 100
	rule := netlink.NewRule()
	rule.Priority = 100
	rule.Family = family
	rule.Table = table
	rule.Src = prefix
	if err := netlink.RuleAdd(rule); err != nil {
		_ = netlink.RouteDel(route)
		return nil, fmt.Errorf("add source rule from %s to table %d: %w", prefix, table, err)
	}

	return func() {
		if err := netlink.RuleDel(rule); err != nil {
			slog.Warn("TUN failed to delete selective source rule", "prefix", prefix.String(), "table", table, "error", err)
		}
		if err := netlink.RouteDel(route); err != nil {
			slog.Warn("TUN failed to delete selective source route", "prefix", prefix.String(), "table", table, "error", err)
		}
	}, nil
}

// findFreeRouteTable randomly picks an unused routing table number (avoiding the kernel's built-in tables 0-255).
// Multiple concurrently running instances will not conflict with each other.
func findFreeRouteTable(family int) (int, error) {
	for i := 0; i < 32; i++ {
		table := int(rand.Uint32())
		if table <= 255 {
			continue
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			return 0, fmt.Errorf("list routes in candidate table %d: %w", table, err)
		}
		if len(routes) == 0 {
			return table, nil
		}
	}
	return 0, fmt.Errorf("no free route table found after 32 attempts")
}
