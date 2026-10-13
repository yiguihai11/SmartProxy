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
	// reversed slice. A "*.a.com" rule covers a.com itself as well as every
	// subdomain below it, so the walk also tests the final (leftmost) label.
	current := t.root
	remaining := domain
	for remaining != "" {
		label := remaining
		if i := strings.LastIndexByte(remaining, '.'); i >= 0 {
			label, remaining = remaining[i+1:], remaining[:i]
		} else {
			remaining = ""
		}
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
	}
	return false
}

func (t *suffixTrie) isEmpty() bool {
	return len(t.root) == 0
}
