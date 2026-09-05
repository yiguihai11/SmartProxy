package chnroute

import (
	"net"
	"net/netip"
	"sync/atomic"
)

type Trie struct {
	root atomic.Pointer[trieData]
}

type trieData struct {
	root    *node
	isEmpty bool
}

type node struct {
	key    netip.Addr
	plen   int
	bitPos int
	left   *node
	right  *node
}

const (
	leafPos = -1
	rootPos = -2
)

func New() *Trie {
	t := &Trie{}
	t.root.Store(&trieData{root: &node{bitPos: rootPos}, isEmpty: true})
	return t
}

func (t *Trie) Insert(prefix netip.Prefix) {
	data := t.root.Load()
	newRoot := cloneNode(data.root)
	addr, plen := prefix.Addr(), prefix.Bits()
	if plen == 0 {
		newRoot.plen = 1
	} else {
		maxBits := 128
		if addr.Is4() {
			maxBits = 32
		}
		newRoot.left = insert(newRoot.left, addr, plen, maxBits)
	}
	t.root.Store(&trieData{root: newRoot, isEmpty: false})
}

func (t *Trie) InsertBatch(prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}
	data := t.root.Load()
	root := cloneNode(data.root)
	for _, p := range prefixes {
		addr, plen := p.Addr(), p.Bits()
		if plen == 0 {
			root.plen = 1
		} else {
			maxBits := 128
			if addr.Is4() {
				maxBits = 32
			}
			root.left = insert(root.left, addr, plen, maxBits)
		}
	}
	t.root.Store(&trieData{root: root, isEmpty: false})
}

func insert(n *node, addr netip.Addr, plen, maxBits int) *node {
	if n == nil {
		return &node{key: addr, plen: plen, bitPos: leafPos}
	}
	if n.bitPos == leafPos {
		if n.key == addr && n.plen == plen {
			return n
		}
		diffBit := firstDiffBit(n.key, addr, n.plen, plen, maxBits)
		return split(n, addr, plen, diffBit, maxBits)
	}
	if !commonPrefix(n.key, addr, n.bitPos) {
		diffBit := firstDiffBit(n.key, addr, n.plen, plen, maxBits)
		return split(n, addr, plen, diffBit, maxBits)
	}
	bit := getBit(addr, n.bitPos, maxBits)
	if bit == 0 {
		n.left = insert(n.left, addr, plen, maxBits)
	} else {
		n.right = insert(n.right, addr, plen, maxBits)
	}
	return n
}

func split(old *node, newAddr netip.Addr, newPlen, diffBit, maxBits int) *node {
	if diffBit == old.plen && old.plen < newPlen {
		internal := &node{key: old.key, plen: old.plen, bitPos: diffBit}
		newLeaf := &node{key: newAddr, plen: newPlen, bitPos: leafPos}
		newBit := getBit(newAddr, diffBit, maxBits)
		if old.bitPos != leafPos {
			old.plen = 0
			if newBit == 0 {
				internal.left, internal.right = newLeaf, old
			} else {
				internal.left, internal.right = old, newLeaf
			}
		} else {
			if newBit == 0 {
				internal.left = newLeaf
			} else {
				internal.right = newLeaf
			}
		}
		return internal
	}
	if diffBit == newPlen && newPlen < old.plen {
		internal := &node{key: newAddr, plen: newPlen, bitPos: diffBit}
		oldBit := getBit(old.key, diffBit, maxBits)
		if oldBit == 0 {
			internal.left = old
		} else {
			internal.right = old
		}
		return internal
	}
	newLeaf := &node{key: newAddr, plen: newPlen, bitPos: leafPos}
	internal := &node{key: newAddr, plen: 0, bitPos: diffBit}
	newBit := getBit(newAddr, diffBit, maxBits)
	if newBit == 0 {
		internal.left, internal.right = newLeaf, old
	} else {
		internal.left, internal.right = old, newLeaf
	}
	return internal
}

func firstDiffBit(a1, a2 netip.Addr, plen1, plen2, maxBits int) int {
	b1, b2 := addrBytes(a1), addrBytes(a2)
	minLen := plen1
	if plen2 < minLen {
		minLen = plen2
	}
	if minLen == 0 {
		minLen = maxBits
	}
	for i := 0; i < minLen && i < maxBits; i++ {
		if getBitRaw(b1, i) != getBitRaw(b2, i) {
			return i
		}
	}
	if plen1 < plen2 {
		return plen1
	}
	return plen2
}

func commonPrefix(a1, a2 netip.Addr, bits int) bool {
	b1, b2 := addrBytes(a1), addrBytes(a2)
	for i := 0; i < bits; i++ {
		if getBitRaw(b1, i) != getBitRaw(b2, i) {
			return false
		}
	}
	return true
}

func getBit(addr netip.Addr, pos, maxBits int) byte {
	if pos < 0 || pos >= maxBits {
		return 0
	}
	return getBitRaw(addrBytes(addr), pos)
}

func getBitRaw(b []byte, pos int) byte {
	if pos/8 >= len(b) {
		return 0
	}
	return (b[pos/8] >> (7 - (pos % 8))) & 1
}

func addrBytes(addr netip.Addr) []byte {
	if addr.Is4() {
		a := addr.As4()
		return a[:]
	}
	a := addr.As16()
	return a[:]
}

func (t *Trie) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	data := t.root.Load()
	switch {
	case data.isEmpty:
		return false
	case data.root.plen > 0:
		return true
	case data.root.left == nil:
		return false
	}
	return trieSearch(data.root.left, ip)
}

func trieSearch(n *node, ip net.IP) bool {
	for {
		if n.bitPos == leafPos {
			return matchKey(ip, n.key, n.plen)
		}
		if n.plen > 0 && matchKey(ip, n.key, n.plen) {
			return true
		}
		bit := getBitRaw(ip, n.bitPos)
		switch {
		case bit == 0 && n.left != nil:
			n = n.left
		case bit == 1 && n.right != nil:
			n = n.right
		default:
			return false
		}
	}
}

func matchKey(ip net.IP, key netip.Addr, plen int) bool {
	if plen == 0 {
		return true
	}
	kb := addrBytes(key)
	for i := 0; i < plen && i/8 < len(ip) && i/8 < len(kb); i++ {
		if getBitRaw(ip, i) != getBitRaw(kb, i) {
			return false
		}
	}
	return true
}

func (t *Trie) IsEmpty() bool { return t.root.Load().isEmpty }

func (t *Trie) Count() int { return countNodes(t.root.Load().root) }

func countNodes(n *node) int {
	if n == nil {
		return 0
	}
	c := 0
	if n.plen > 0 {
		c = 1
	}
	return c + countNodes(n.left) + countNodes(n.right)
}

// CountV4 and CountV6 report the stored prefixes of each family: every trie node
// carrying a prefix (n.plen > 0) whose key is an IPv4 / IPv6 address — terminal
// leaves AND aggregate ancestors alike — so CountV4()+CountV6() always equals
// Count() and each badge matches how many v4/v6 prefixes were actually loaded.
//
// (Counting only terminal leaves would silently drop aggregate prefixes that sit
// above a longer, nested prefix of either family in the shared trie — e.g. a v4
// 10.0.0.0/8 above 10.1.0.0/16, or a v4 36.0.16.0/20 above an IPv6 entry whose
// bit path it shares — leaving the family split not adding up to the total.)
func (t *Trie) CountV4() int { return countPrefixNodesByFamily(t.root.Load().root, true) }

func (t *Trie) CountV6() int { return countPrefixNodesByFamily(t.root.Load().root, false) }

func countPrefixNodesByFamily(n *node, v4 bool) int {
	if n == nil {
		return 0
	}
	c := 0
	if n.plen > 0 && n.key.Is4() == v4 {
		c = 1
	}
	return c + countPrefixNodesByFamily(n.left, v4) + countPrefixNodesByFamily(n.right, v4)
}

func (t *Trie) Pull(other *Trie) {
	t.root.Store(other.root.Load())
}

func cloneNode(n *node) *node {
	if n == nil {
		return nil
	}
	return &node{
		key:    n.key,
		plen:   n.plen,
		bitPos: n.bitPos,
		left:   cloneNode(n.left),
		right:  cloneNode(n.right),
	}
}
