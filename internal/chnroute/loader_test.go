package chnroute

import (
	"net"
	"os"
	"testing"
)

func TestParse_ValidCIDRs(t *testing.T) {
	data := []byte("# comment\n\n10.0.0.0/8\n192.168.1.1\n2001:db8::/32\n")
	tr, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if tr.IsEmpty() {
		t.Fatal("expected non-empty trie")
	}
	if !tr.Contains(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 should be contained")
	}
	if !tr.Contains(net.ParseIP("192.168.1.1")) {
		t.Error("192.168.1.1 should be contained (bare address)")
	}
	if !tr.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 should be contained")
	}
}

func TestParse_EmptyAndInvalid(t *testing.T) {
	// only comments / blank lines → empty trie
	tr, err := Parse([]byte("# comment\n\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !tr.IsEmpty() {
		t.Error("expected empty trie for comment-only input")
	}

	// invalid lines are skipped, valid ones kept
	tr2, err := Parse([]byte("not-a-cidr\n10.0.0.0/8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if tr2.IsEmpty() {
		t.Error("expected non-empty trie despite invalid line")
	}
}

func TestLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/chnroute.txt"
	data := "8.8.8.0/24\n1.1.1.0/24\n# trailing\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	tr, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if tr.IsEmpty() {
		t.Fatal("expected loaded trie to be non-empty")
	}
}
