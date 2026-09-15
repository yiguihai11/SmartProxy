package lantern

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var (
	ErrMaxAccountsReached = errors.New("maximum account limit reached and all accounts are exhausted")
	ErrNoAvailableAccount = errors.New("no available account with sufficient quota")
)

// AccountManager handles accounts.json loading, selection, creation limits, and quota status.
type AccountManager struct {
	filePath       string
	maxAccounts    int
	minRemainBytes int64
	accounts       []Account
	mu             sync.Mutex
}

// NewAccountManager creates and initializes an AccountManager.
func NewAccountManager(dataDir, fileName string, maxAccounts int, minRemainBytes int64) (*AccountManager, error) {
	if maxAccounts <= 0 {
		maxAccounts = 5
	}
	if minRemainBytes <= 0 {
		minRemainBytes = 1024 * 1024 // 1MB
	}
	if fileName == "" {
		fileName = "accounts.json"
	}
	if dataDir == "" {
		dataDir = "."
	}

	fullPath := filepath.Join(dataDir, fileName)
	am := &AccountManager{
		filePath:       fullPath,
		maxAccounts:    maxAccounts,
		minRemainBytes: minRemainBytes,
	}

	if err := am.load(); err != nil {
		return nil, err
	}
	return am, nil
}

func (am *AccountManager) load() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	data, err := os.ReadFile(am.filePath)
	if errors.Is(err, os.ErrNotExist) {
		am.accounts = []Account{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read accounts file: %w", err)
	}

	if len(data) == 0 {
		am.accounts = []Account{}
		return nil
	}

	var accs []Account
	if err := json.Unmarshal(data, &accs); err != nil {
		return fmt.Errorf("failed to parse accounts json: %w", err)
	}
	am.accounts = accs
	return nil
}

// Save persists the account list to disk.
func (am *AccountManager) Save() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	dir := filepath.Dir(am.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create accounts directory: %w", err)
	}

	data, err := json.MarshalIndent(am.accounts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal accounts: %w", err)
	}

	tmpFile := am.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write tmp accounts file: %w", err)
	}
	if err := os.Rename(tmpFile, am.filePath); err != nil {
		return fmt.Errorf("failed to commit accounts file: %w", err)
	}
	return nil
}

// List returns a copy of the accounts.
func (am *AccountManager) List() []Account {
	am.mu.Lock()
	defer am.mu.Unlock()

	res := make([]Account, len(am.accounts))
	copy(res, am.accounts)
	return res
}

// PickAvailable picks an available account that has quota_ok == true and is not currently marked exhausted.
// It prioritizes accounts with the highest remaining quota.
func (am *AccountManager) PickAvailable() (*Account, bool) {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now().Unix()
	var candidates []Account
	for _, acc := range am.accounts {
		// If exhausted_until is in the past, it's eligible to be tried again
		if acc.ExhaustedUntil > 0 && now < acc.ExhaustedUntil {
			continue
		}
		if acc.QuotaOK || (acc.LastCheck == 0) || (acc.Remain > am.minRemainBytes) {
			candidates = append(candidates, acc)
		}
	}

	if len(candidates) == 0 {
		return nil, false
	}

	// Sort candidates by remaining quota descending
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Remain > candidates[j].Remain
	})

	picked := candidates[0]
	return &picked, true
}

// CanRegister returns true if the current number of accounts is less than maxAccounts.
func (am *AccountManager) CanRegister() bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	return len(am.accounts) < am.maxAccounts
}

// AddAccount adds a newly registered account to the list.
func (am *AccountManager) AddAccount(acc Account) error {
	am.mu.Lock()
	if len(am.accounts) >= am.maxAccounts {
		am.mu.Unlock()
		return ErrMaxAccountsReached
	}
	am.accounts = append(am.accounts, acc)
	am.mu.Unlock()

	return am.Save()
}

// UpdateAccount updates status of an existing account matched by device_id.
func (am *AccountManager) UpdateAccount(acc Account) error {
	am.mu.Lock()
	found := false
	for i, existing := range am.accounts {
		if existing.DeviceID == acc.DeviceID {
			am.accounts[i] = acc
			found = true
			break
		}
	}
	if !found {
		if len(am.accounts) < am.maxAccounts {
			am.accounts = append(am.accounts, acc)
		} else {
			am.mu.Unlock()
			return ErrMaxAccountsReached
		}
	}
	am.mu.Unlock()

	return am.Save()
}

// MarkExhausted marks an account as exhausted until resetTime (or next UTC midnight + 1h if 0).
func (am *AccountManager) MarkExhausted(deviceID string, resetUnix int64) error {
	am.mu.Lock()
	if resetUnix <= 0 {
		// Default to next UTC 00:05
		now := time.Now().UTC()
		nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 5, 0, 0, time.UTC)
		resetUnix = nextMidnight.Unix()
	}

	for i, existing := range am.accounts {
		if existing.DeviceID == deviceID {
			am.accounts[i].QuotaOK = false
			am.accounts[i].Remain = 0
			am.accounts[i].ExhaustedUntil = resetUnix
			am.accounts[i].LastCheck = time.Now().Unix()
			break
		}
	}
	am.mu.Unlock()

	return am.Save()
}

// EarliestResetAccount returns the account that resets earliest among exhausted accounts.
func (am *AccountManager) EarliestResetAccount() *Account {
	am.mu.Lock()
	defer am.mu.Unlock()

	if len(am.accounts) == 0 {
		return nil
	}

	sorted := make([]Account, len(am.accounts))
	copy(sorted, am.accounts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ExhaustedUntil < sorted[j].ExhaustedUntil
	})

	return &sorted[0]
}
