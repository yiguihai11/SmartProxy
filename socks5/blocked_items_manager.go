package socks5

import (
	"crypto/sha256"
	"fmt"
	"net"
	"smartproxy/logger"
	"sort"
	"strings"
	"sync"
	"time"
)

// FailureReason represents the reason why a connection was blocked
type FailureReason int

const (
	FailureReasonUnknown           FailureReason = iota
	FailureReasonRST                             // Connection reset (typical GFW behavior)
	FailureReasonTimeout                         // Connection timeout
	FailureReasonHandshakeFailure                // TLS handshake failed
	FailureReasonDNSFailure                      // DNS resolution failed
	FailureReasonConnectionRefused               // Connection refused
	FailureReasonHostUnreachable                 // Host unreachable
)

// String returns the string representation of FailureReason
func (fr FailureReason) String() string {
	switch fr {
	case FailureReasonRST:
		return "RST"
	case FailureReasonTimeout:
		return "Timeout"
	case FailureReasonHandshakeFailure:
		return "HandshakeFailure"
	case FailureReasonDNSFailure:
		return "DNSFailure"
	case FailureReasonConnectionRefused:
		return "ConnectionRefused"
	case FailureReasonHostUnreachable:
		return "HostUnreachable"
	default:
		return "Unknown"
	}
}

// BlockedItemType represents the type of blocked item
type BlockedItemType int

const (
	ItemTypeUnknown BlockedItemType = iota
	ItemTypeDomain                  // Domain name
	ItemTypeIPv4                    // IPv4 address
	ItemTypeIPv6                    // IPv6 address
)

// String returns the string representation of BlockedItemType
func (bit BlockedItemType) String() string {
	switch bit {
	case ItemTypeDomain:
		return "Domain"
	case ItemTypeIPv4:
		return "IPv4"
	case ItemTypeIPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

// PortInfo tracks connection attempts and failures for a specific port
type PortInfo struct {
	Port              int           `json:"port"`
	AttemptCount      int           `json:"attempt_count"`
	LastAttempt       time.Time     `json:"last_attempt"`
	LastFailureReason FailureReason `json:"last_failure_reason"`
	FirstFailureTime  time.Time     `json:"first_failure_time"`
}

// BlockedItem represents a blocked domain or IP with detailed information
type BlockedItem struct {
	Key            string                 `json:"key"` // Domain or IP
	Type           BlockedItemType        `json:"type"`
	FirstBlocked   time.Time              `json:"first_blocked"`
	LastUpdated    time.Time              `json:"last_updated"`
	TotalAttempts  int                    `json:"total_attempts"`
	Ports          map[int]*PortInfo      `json:"ports"`           // Port-specific information
	IPList         []string               `json:"ip_list"`         // List of IPs tried (for domains)
	FailureReasons map[FailureReason]int  `json:"failure_reasons"` // Count of each failure type
	AdditionalInfo map[string]interface{} `json:"additional_info"` // Extra information
	mutex          sync.RWMutex           `json:"-"`
}

// NewBlockedItem creates a new BlockedItem
func NewBlockedItem(key string, itemType BlockedItemType) *BlockedItem {
	now := time.Now()
	return &BlockedItem{
		Key:            key,
		Type:           itemType,
		FirstBlocked:   now,
		LastUpdated:    now,
		Ports:          make(map[int]*PortInfo),
		IPList:         make([]string, 0),
		FailureReasons: make(map[FailureReason]int),
		AdditionalInfo: make(map[string]interface{}),
	}
}

// AddAttempt records a connection attempt
func (bi *BlockedItem) AddAttempt(port int, reason FailureReason, ip string) {
	bi.mutex.Lock()
	defer bi.mutex.Unlock()

	now := time.Now()
	bi.LastUpdated = now
	bi.TotalAttempts++

	// Update failure reason count
	bi.FailureReasons[reason]++

	// Update or create port info
	portInfo, exists := bi.Ports[port]
	if !exists {
		portInfo = &PortInfo{
			Port:             port,
			FirstFailureTime: now,
		}
		bi.Ports[port] = portInfo
	}
	portInfo.AttemptCount++
	portInfo.LastAttempt = now
	portInfo.LastFailureReason = reason

	// Add IP to list if not already present (for domains)
	if bi.Type == ItemTypeDomain && ip != "" {
		found := false
		for _, existingIP := range bi.IPList {
			if existingIP == ip {
				found = true
				break
			}
		}
		if !found {
			bi.IPList = append(bi.IPList, ip)
		}
	}
}

// GetSortedPorts returns ports sorted by attempt count (descending)
func (bi *BlockedItem) GetSortedPorts() []PortInfo {
	bi.mutex.RLock()
	defer bi.mutex.RUnlock()

	ports := make([]PortInfo, 0, len(bi.Ports))
	for _, portInfo := range bi.Ports {
		ports = append(ports, *portInfo)
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i].AttemptCount > ports[j].AttemptCount
	})

	return ports
}

// GetPrimaryFailureReason returns the most common failure reason
func (bi *BlockedItem) GetPrimaryFailureReason() FailureReason {
	bi.mutex.RLock()
	defer bi.mutex.RUnlock()

	maxCount := 0
	primaryReason := FailureReasonUnknown

	for reason, count := range bi.FailureReasons {
		if count > maxCount {
			maxCount = count
			primaryReason = reason
		}
	}

	return primaryReason
}

// ShardedBlockedItemsMap implements a sharded hash table for high performance
type ShardedBlockedItemsMap struct {
	shards    []*blockedItemsShard
	shardMask uint32
}

// blockedItemsShard represents a single shard of the hash table
type blockedItemsShard struct {
	items map[string]*BlockedItem
	mutex sync.RWMutex
}

// NewShardedBlockedItemsMap creates a new sharded hash table with 251 shards
func NewShardedBlockedItemsMap() *ShardedBlockedItemsMap {
	const numShards = 251
	shards := make([]*blockedItemsShard, numShards)

	for i := 0; i < numShards; i++ {
		shards[i] = &blockedItemsShard{
			items: make(map[string]*BlockedItem),
		}
	}

	return &ShardedBlockedItemsMap{
		shards:    shards,
		shardMask: numShards - 1,
	}
}

// getShard returns the appropriate shard for the given key
func (s *ShardedBlockedItemsMap) getShard(key string) *blockedItemsShard {
	hash := sha256.Sum256([]byte(key))
	hashBytes := hash[:]

	// Use first 4 bytes for shard selection
	shardIndex := (uint32(hashBytes[0])<<24 | uint32(hashBytes[1])<<16 |
		uint32(hashBytes[2])<<8 | uint32(hashBytes[3])) & s.shardMask

	return s.shards[shardIndex]
}

// Add adds or updates a blocked item
func (s *ShardedBlockedItemsMap) Add(key string, itemType BlockedItemType, port int, reason FailureReason, ip string) {
	shard := s.getShard(key)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if item, exists := shard.items[key]; exists {
		item.AddAttempt(port, reason, ip)
	} else {
		item := NewBlockedItem(key, itemType)
		item.AddAttempt(port, reason, ip)
		shard.items[key] = item
	}
}

// Get retrieves a blocked item
func (s *ShardedBlockedItemsMap) Get(key string) (*BlockedItem, bool) {
	shard := s.getShard(key)
	shard.mutex.RLock()
	defer shard.mutex.RUnlock()

	item, exists := shard.items[key]
	if !exists {
		return nil, false
	}

	// Return a copy to avoid concurrent access issues
	return item.Copy(), true
}

// Delete removes a blocked item
func (s *ShardedBlockedItemsMap) Delete(key string) bool {
	shard := s.getShard(key)
	shard.mutex.Lock()
	defer shard.mutex.Unlock()

	if _, exists := shard.items[key]; exists {
		delete(shard.items, key)
		return true
	}
	return false
}

// Contains checks if a key exists
func (s *ShardedBlockedItemsMap) Contains(key string) bool {
	shard := s.getShard(key)
	shard.mutex.RLock()
	defer shard.mutex.RUnlock()

	_, exists := shard.items[key]
	return exists
}

// Count returns the total number of blocked items
func (s *ShardedBlockedItemsMap) Count() int {
	total := 0
	for _, shard := range s.shards {
		shard.mutex.RLock()
		total += len(shard.items)
		shard.mutex.RUnlock()
	}
	return total
}

// GetAll returns all blocked items (expensive operation, use sparingly)
func (s *ShardedBlockedItemsMap) GetAll() []*BlockedItem {
	var all []*BlockedItem
	for _, shard := range s.shards {
		shard.mutex.RLock()
		for _, item := range shard.items {
			all = append(all, item.Copy())
		}
		shard.mutex.RUnlock()
	}
	return all
}

// GetByType returns all blocked items of a specific type
func (s *ShardedBlockedItemsMap) GetByType(itemType BlockedItemType) []*BlockedItem {
	var items []*BlockedItem
	for _, shard := range s.shards {
		shard.mutex.RLock()
		for _, item := range shard.items {
			if item.Type == itemType {
				items = append(items, item.Copy())
			}
		}
		shard.mutex.RUnlock()
	}
	return items
}

// CleanupExpired removes expired items
func (s *ShardedBlockedItemsMap) CleanupExpired(ttl time.Duration) int {
	expiredCount := 0
	now := time.Now()

	for _, shard := range s.shards {
		shard.mutex.Lock()
		for key, item := range shard.items {
			if now.Sub(item.LastUpdated) > ttl {
				delete(shard.items, key)
				expiredCount++
			}
		}
		shard.mutex.Unlock()
	}

	return expiredCount
}

// BlockedItemsManager manages blocked items with TTL and cleanup
type BlockedItemsManager struct {
	items         *ShardedBlockedItemsMap
	ttl           time.Duration
	cleanupTicker *time.Ticker
	stopCleanup   chan bool
	logger        *logger.SlogLogger
}

// NewBlockedItemsManager creates a new BlockedItemsManager
func NewBlockedItemsManager(ttlMinutes int, logger *logger.SlogLogger) *BlockedItemsManager {
	ttl := time.Duration(ttlMinutes) * time.Minute
	manager := &BlockedItemsManager{
		items:       NewShardedBlockedItemsMap(),
		ttl:         ttl,
		stopCleanup: make(chan bool),
		logger:      logger,
	}

	// Start cleanup routine
	manager.startCleanup()

	return manager
}

// AddBlockedDomain adds a blocked domain with failure information
func (bm *BlockedItemsManager) AddBlockedDomain(domain, portStr, ip string, reason FailureReason) {
	port := 80 // default port
	if p, err := parsePort(portStr); err == nil {
		port = p
	}

	key := strings.ToLower(strings.TrimSpace(domain))
	bm.items.Add(key, ItemTypeDomain, port, reason, ip)

	bm.logger.Info("🚫 Added blocked domain: %s (port: %d, reason: %s, ip: %s)",
		key, port, reason, ip)
}

// AddBlockedIP adds a blocked IP with failure information
func (bm *BlockedItemsManager) AddBlockedIP(ip, portStr string, reason FailureReason) {
	port := 80 // default port
	if p, err := parsePort(portStr); err == nil {
		port = p
	}

	// Determine if IPv4 or IPv6
	var itemType BlockedItemType
	if net.ParseIP(ip).To4() != nil {
		itemType = ItemTypeIPv4
	} else {
		itemType = ItemTypeIPv6
	}

	bm.items.Add(ip, itemType, port, reason, "")

	bm.logger.Info("🚫 Added blocked IP: %s (port: %d, reason: %s, type: %s)",
		ip, port, reason, itemType)
}

// GetBlockedInfo retrieves blocked information for a domain or IP
func (bm *BlockedItemsManager) GetBlockedInfo(key string) (*BlockedItem, bool) {
	return bm.items.Get(key)
}

// IsBlocked checks if a domain or IP is blocked
func (bm *BlockedItemsManager) IsBlocked(key string) bool {
	return bm.items.Contains(key)
}

// GetStatistics returns statistics about blocked items
func (bm *BlockedItemsManager) GetStatistics() map[string]interface{} {
	allItems := bm.items.GetAll()
	domainCount := 0
	ipCount := 0
	var oldestBlock, newestBlock time.Time

	for _, item := range allItems {
		if item.Type == ItemTypeDomain {
			domainCount++
		} else {
			ipCount++
		}

		if oldestBlock.IsZero() || item.FirstBlocked.Before(oldestBlock) {
			oldestBlock = item.FirstBlocked
		}
		if newestBlock.IsZero() || item.LastUpdated.After(newestBlock) {
			newestBlock = item.LastUpdated
		}
	}

	return map[string]interface{}{
		"total_blocked_domains": domainCount,
		"total_blocked_ips":     ipCount,
		"total_blocked_items":   bm.items.Count(),
		"oldest_block":          oldestBlock,
		"newest_block":          newestBlock,
	}
}

// GetList returns a detailed list of all blocked items
func (bm *BlockedItemsManager) GetList(limit int, offset int) map[string]interface{} {
	allItems := bm.items.GetAll()
	total := len(allItems)

	// Apply pagination
	if offset >= total {
		return map[string]interface{}{
			"total":  total,
			"offset": offset,
			"limit":  limit,
			"items":  []*BlockedItem{},
		}
	}

	end := offset + limit
	if end > total {
		end = total
	}

	// Get the slice for this page
	items := allItems[offset:end]

	// Convert to more JSON-friendly format
	itemsList := make([]map[string]interface{}, len(items))
	for i, item := range items {
		item.mutex.RLock()

		// Get the most common failure reason
		var topFailureReason string
		var topFailureCount int
		for reason, count := range item.FailureReasons {
			if count > topFailureCount {
				topFailureCount = count
				topFailureReason = reason.String()
			}
		}

		// Get port information
		portsList := make([]map[string]interface{}, len(item.Ports))
		portIdx := 0
		for port, info := range item.Ports {
			portsList[portIdx] = map[string]interface{}{
				"port":               port,
				"attempt_count":      info.AttemptCount,
				"last_attempt":       info.LastAttempt,
				"last_failure_reason": info.LastFailureReason.String(),
				"first_failure_time":  info.FirstFailureTime,
			}
			portIdx++
		}

		// Check if item is expired
		isExpired := time.Since(item.LastUpdated) > bm.ttl

		itemsList[i] = map[string]interface{}{
			"key":                item.Key,
			"type":               item.Type.String(),
			"first_blocked":      item.FirstBlocked,
			"last_updated":       item.LastUpdated,
			"total_attempts":     item.TotalAttempts,
			"ports":              portsList,
			"ip_list":            item.IPList,
			"top_failure_reason": topFailureReason,
			"failure_reasons":    item.FailureReasons,
            "failure_reasons_str": func() map[string]int {
                result := make(map[string]int)
                for reason, count := range item.FailureReasons {
                    result[reason.String()] = count
                }
                return result
            }(),
			"is_expired":         isExpired,
			"additional_info":    item.AdditionalInfo,
		}

		item.mutex.RUnlock()
	}

	return map[string]interface{}{
		"total":  total,
		"offset": offset,
		"limit":  limit,
		"items":  itemsList,
	}
}

// Remove removes a blocked item
func (bm *BlockedItemsManager) Remove(key string) {
	if bm.items.Delete(key) {
		bm.logger.Info("✅ Removed from blocked items: %s", key)
	}
}

// GetBlockedByType returns all blocked items of a specific type
func (bm *BlockedItemsManager) GetBlockedByType(itemType BlockedItemType) []*BlockedItem {
	return bm.items.GetByType(itemType)
}

// GetTopBlockedDomains returns the most frequently blocked domains
func (bm *BlockedItemsManager) GetTopBlockedDomains(limit int) []*BlockedItem {
	allItems := bm.items.GetByType(ItemTypeDomain)

	// Sort by total attempts
	sort.Slice(allItems, func(i, j int) bool {
		return allItems[i].TotalAttempts > allItems[j].TotalAttempts
	})

	if len(allItems) > limit {
		allItems = allItems[:limit]
	}

	return allItems
}

// GetTopBlockedIPs returns the most frequently blocked IPs
func (bm *BlockedItemsManager) GetTopBlockedIPs(limit int) []*BlockedItem {
	allItems := bm.items.GetByType(ItemTypeIPv4)
	ipv6Items := bm.items.GetByType(ItemTypeIPv6)
	allItems = append(allItems, ipv6Items...)

	// Sort by total attempts
	sort.Slice(allItems, func(i, j int) bool {
		return allItems[i].TotalAttempts > allItems[j].TotalAttempts
	})

	if len(allItems) > limit {
		allItems = allItems[:limit]
	}

	return allItems
}

// startCleanup starts the cleanup routine
func (bm *BlockedItemsManager) startCleanup() {
	// Cleanup every 5 minutes
	bm.cleanupTicker = time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-bm.cleanupTicker.C:
				expiredCount := bm.items.CleanupExpired(bm.ttl)
				if expiredCount > 0 {
					bm.logger.Info("🧹 Cleaned up %d expired blocked items", expiredCount)
				}
			case <-bm.stopCleanup:
				return
			}
		}
	}()
}

// Stop stops the BlockedItemsManager and cleanup routine
func (bm *BlockedItemsManager) Stop() {
	if bm.cleanupTicker != nil {
		bm.cleanupTicker.Stop()
		close(bm.stopCleanup)
	}
}

// parsePort extracts port number from address string
func parsePort(addr string) (int, error) {
	// If addr is just a port number
	if len(addr) <= 5 {
		var port int
		_, err := fmt.Sscanf(addr, "%d", &port)
		if err == nil {
			return port, nil
		}
	}

	// If addr is host:port
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Try to parse as just port
		var port int
		_, err = fmt.Sscanf(addr, "%d", &port)
		if err == nil {
			return port, nil
		}
		return 0, err
	}

	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	return port, err
}

// Copy creates a deep copy of a BlockedItem
func (bi *BlockedItem) Copy() *BlockedItem {
	bi.mutex.RLock()
	defer bi.mutex.RUnlock()

	itemCopy := &BlockedItem{
		Key:            bi.Key,
		Type:           bi.Type,
		FirstBlocked:   bi.FirstBlocked,
		LastUpdated:    bi.LastUpdated,
		TotalAttempts:  bi.TotalAttempts,
		Ports:          make(map[int]*PortInfo),
		IPList:         make([]string, len(bi.IPList)),
		FailureReasons: make(map[FailureReason]int),
		AdditionalInfo: make(map[string]interface{}),
	}

	// Copy ports
	for k, v := range bi.Ports {
		portCopy := *v
		itemCopy.Ports[k] = &portCopy
	}

	// Copy IP list
	copy(itemCopy.IPList, bi.IPList)

	// Copy failure reasons
	for k, v := range bi.FailureReasons {
		itemCopy.FailureReasons[k] = v
	}

	// Copy additional info
	for k, v := range bi.AdditionalInfo {
		itemCopy.AdditionalInfo[k] = v
	}

	return itemCopy
}
