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
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return false
	}
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}

	current := t.root
	for i, label := range labels {
		node, ok := current[label]
		if !ok {
			return false
		}

		if node.terminal && i < len(labels)-1 {
			return true
		}
		current = node.children
	}
	return false
}

func (t *suffixTrie) isEmpty() bool {
	return len(t.root) == 0
}
