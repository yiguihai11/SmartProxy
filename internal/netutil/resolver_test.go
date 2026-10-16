package netutil

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSetSystemDNS(t *testing.T) {
	origV4, origV6 := GetSystemDNS()
	defer SetSystemDNS(origV4, origV6)

	SetSystemDNS("119.29.29.29", "2402:4e00::")
	v4, v6 := GetSystemDNS()
	if v4 != "119.29.29.29:53" {
		t.Errorf("expected 119.29.29.29:53, got %s", v4)
	}
	if v6 != "[2402:4e00::]:53" {
		t.Errorf("expected [2402:4e00::]:53, got %s", v6)
	}
}

func TestIsLoopbackOrEmpty(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"127.0.0.1:53", true},
		{"127.0.0.1", true},
		{"[::1]:53", true},
		{"::1", true},
		{"0.0.0.0:53", true},
		{"223.5.5.5:53", false},
		{"114.114.114.114:53", false},
		{"[2400:3200::1]:53", false},
	}
	for _, tc := range cases {
		got := isLoopbackOrEmpty(tc.addr)
		if got != tc.want {
			t.Errorf("isLoopbackOrEmpty(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestDefaultResolverLookup(t *testing.T) {
	origV4, origV6 := GetSystemDNS()
	SetSystemDNS("223.5.5.5", "")
	defer SetSystemDNS(origV4, origV6)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupHost(ctx, "www.baidu.com")
	if err != nil {
		t.Logf("lookup warning (may be offline during test): %v", err)
		return
	}
	if len(addrs) == 0 {
		t.Errorf("expected at least one address for www.baidu.com")
	}
}
