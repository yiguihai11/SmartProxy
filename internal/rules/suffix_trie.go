package rules

import "strings"

type suffixTrie struct {
	root map[string]*suffixNode
}

type suffixNode struct {
	terminal bool
	children map[string]*suffixNode
}

func newSuffixTrie() *suffixTrie {
	return &suffixTrie{root: make(map[string]*suffixNode)}
}

func (t *suffixTrie) insert(suffix string) {
	labels := strings.Split(strings.TrimPrefix(suffix, "."), ".")
	if len(labels) == 0 {
		return
	}

	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}

	current := t.root
	for i, label := range labels {
		node, ok := current[label]
		if !ok {
			node = &suffixNode{children: make(map[string]*suffixNode)}
			current[label] = node
		}
		if i == len(labels)-1 {
			node.terminal = true
		}
		current = node.children
	}
}

func (t *suffixTrie) match(domain string) bool {
	// Walk labels from right to left without strings.Split or a temporary
	// reversed slice. Keep the existing rule that a suffix matches subdomains
	// only, not the apex domain itself.
	current := t.root
	remaining := domain
	for {
		i := strings.LastIndexByte(remaining, '.')
		if i < 0 {
			break
		}
		label := remaining[i+1:]
		if label == "" {
			return false
		}
		node, ok := current[label]
		if !ok {
			return false
		}
		if node.terminal {
			return true
		}
		current = node.children
		remaining = remaining[:i]
	}
	if remaining == "" {
		return false
	}
	// The final label completes the apex itself, which must not match.
	return false
}

func (t *suffixTrie) isEmpty() bool {
	return len(t.root) == 0
}
