package logbuf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultRetentionDays = 3
	DefaultMaxFileBytes  = 30 * 1024 * 1024 // 30 MB per daily log file
	logFilePrefix        = "smartproxy_"
	logFileSuffix        = ".log"
)

// DailyFileLogger manages daily rotating log files with retention policy and size capping.
type DailyFileLogger struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	maxFileBytes  int64
	currentDate   string // "2006-01-02"
	file          *os.File
	currentSize   int64
	location      *time.Location
}

var (
	fileLoggerMu      sync.RWMutex
	defaultFileLogger *DailyFileLogger
)

// NewDailyFileLogger creates a new DailyFileLogger for dir with retentionDays and location.
func NewDailyFileLogger(dir string, retentionDays int, loc *time.Location) (*DailyFileLogger, error) {
	if dir == "" {
		return nil, fmt.Errorf("log directory cannot be empty")
	}
	if retentionDays <= 0 {
		retentionDays = DefaultRetentionDays
	}
	if loc == nil {
		loc = shanghaiLocation()
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log dir %s: %w", dir, err)
	}

	l := &DailyFileLogger{
		dir:           dir,
		retentionDays: retentionDays,
		maxFileBytes:  DefaultMaxFileBytes,
		location:      loc,
	}

	// Clean up any stale files on startup
	l.cleanExpired(time.Now().In(loc))
	return l, nil
}

// InitFileLogger initializes the global default daily file logger.
func InitFileLogger(dir string, retentionDays int) error {
	fl, err := NewDailyFileLogger(dir, retentionDays, shanghaiLocation())
	if err != nil {
		return err
	}
	fileLoggerMu.Lock()
	if defaultFileLogger != nil {
		defaultFileLogger.Close()
	}
	defaultFileLogger = fl
	fileLoggerMu.Unlock()
	return nil
}

// GetDefaultFileLogger returns the global default daily file logger.
func GetDefaultFileLogger() *DailyFileLogger {
	fileLoggerMu.RLock()
	defer fileLoggerMu.RUnlock()
	return defaultFileLogger
}

// Close closes the underlying open file.
func (l *DailyFileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		l.currentDate = ""
		l.currentSize = 0
		return err
	}
	return nil
}

// WriteEntry writes a log entry into today's log file with automatic date rotation and retention check.
func (l *DailyFileLogger) WriteEntry(entry LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().In(l.location)
	dateStr := now.Format("2006-01-02")

	if l.file == nil || l.currentDate != dateStr {
		if l.file != nil {
			_ = l.file.Close()
			l.file = nil
		}

		filePath := filepath.Join(l.dir, fmt.Sprintf("%s%s%s", logFilePrefix, dateStr, logFileSuffix))
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}

		l.file = f
		l.currentDate = dateStr
		l.currentSize = fi.Size()

		// Run retention cleanup upon day transition
		l.cleanExpired(now)
	}

	ts := entry.Timestamp
	if ts == "" {
		ts = now.Format("2006-01-02 15:04:05")
	}
	level := entry.Level
	if level == "" {
		level = "INFO"
	}

	line := fmt.Sprintf("%s %-5s %s\n", ts, level, entry.Message)
	lineBytes := []byte(line)
	if l.currentSize+int64(len(lineBytes)) > l.maxFileBytes {
		// Size limit reached for today's file: skip to prevent disk overflow
		return nil
	}

	n, err := l.file.Write(lineBytes)
	l.currentSize += int64(n)
	return err
}

// ClearToday truncates today's log file to 0 bytes.
func (l *DailyFileLogger) ClearToday() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().In(l.location)
	dateStr := now.Format("2006-01-02")
	filePath := filepath.Join(l.dir, fmt.Sprintf("%s%s%s", logFilePrefix, dateStr, logFileSuffix))

	if l.file != nil {
		if err := l.file.Truncate(0); err != nil {
			return err
		}
		_, _ = l.file.Seek(0, 0)
		l.currentSize = 0
		return nil
	}

	if err := os.Truncate(filePath, 0); err != nil && !os.IsNotExist(err) {
		return err
	}
	l.currentSize = 0
	return nil
}

// cleanExpired removes log files in l.dir older than retentionDays.
// Must be called with or without lock (does not access l.file).
func (l *DailyFileLogger) cleanExpired(now time.Time) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}

	cutoffDate := now.AddDate(0, 0, -l.retentionDays)
	cutoffStr := cutoffDate.Format("2006-01-02")

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, logFilePrefix) || !strings.HasSuffix(name, logFileSuffix) {
			continue
		}
		// Extract date string between prefix and suffix
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, logFilePrefix), logFileSuffix)
		if len(datePart) != 10 {
			continue
		}
		if datePart < cutoffStr {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
}

// ListLogFiles returns sorted list of available daily log file names (most recent first).
func (l *DailyFileLogger) ListLogFiles() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, logFilePrefix) && strings.HasSuffix(name, logFileSuffix) {
			files = append(files, name)
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i] > files[j] // descending order (newest first)
	})
	return files
}

// ReadLogFile reads entries from a specific log file in l.dir (up to maxLines).
func (l *DailyFileLogger) ReadLogFile(filename string, maxLines int) ([]LogEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Prevent directory traversal attacks
	cleanName := filepath.Base(filename)
	if !strings.HasPrefix(cleanName, logFilePrefix) || !strings.HasSuffix(cleanName, logFileSuffix) {
		return nil, fmt.Errorf("invalid log filename: %s", cleanName)
	}

	filePath := filepath.Join(l.dir, cleanName)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if maxLines <= 0 {
		maxLines = 10000
	}

	scanner := bufio.NewScanner(f)
	var rawLines []string
	for scanner.Scan() {
		rawLines = append(rawLines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Keep up to maxLines
	if len(rawLines) > maxLines {
		rawLines = rawLines[len(rawLines)-maxLines:]
	}

	var result []LogEntry
	for idx, line := range rawLines {
		if len(line) >= 20 && line[4] == '-' && line[7] == '-' && line[10] == ' ' && line[13] == ':' && line[16] == ':' {
			timestamp := line[:19]
			rest := strings.TrimSpace(line[20:])
			var level, msg string
			if spaceIdx := strings.IndexByte(rest, ' '); spaceIdx != -1 {
				level = rest[:spaceIdx]
				msg = strings.TrimSpace(rest[spaceIdx+1:])
			} else {
				level = rest
				msg = ""
			}
			result = append(result, LogEntry{
				ID:        uint64(idx + 1),
				Timestamp: timestamp,
				Level:     level,
				Message:   msg,
			})
		} else {
			result = append(result, LogEntry{
				ID:      uint64(idx + 1),
				Message: line,
			})
		}
	}
	return result, nil
}

// ClearToday clears today's log file in the default logger.
func ClearToday() error {
	fileLoggerMu.RLock()
	fl := defaultFileLogger
	fileLoggerMu.RUnlock()
	if fl != nil {
		return fl.ClearToday()
	}
	return nil
}

// ListLogFiles returns available log file names in the default logger.
func ListLogFiles() []string {
	fileLoggerMu.RLock()
	fl := defaultFileLogger
	fileLoggerMu.RUnlock()
	if fl != nil {
		return fl.ListLogFiles()
	}
	return nil
}

// ReadLogFile reads lines from a log file in the default logger.
func ReadLogFile(filename string, maxLines int) ([]LogEntry, error) {
	fileLoggerMu.RLock()
	fl := defaultFileLogger
	fileLoggerMu.RUnlock()
	if fl != nil {
		return fl.ReadLogFile(filename, maxLines)
	}
	return nil, fmt.Errorf("file logger not initialized")
}

// AddExternalLog appends an external log line (e.g. from Android Kotlin layer)
// into the unified memory buffer and the daily file log.
func AddExternalLog(source, level, message string) {
	loc := shanghaiLocation()
	now := time.Now().In(loc)

	fullMsg := message
	if source != "" && !strings.HasPrefix(fullMsg, "["+source+"]") {
		fullMsg = fmt.Sprintf("[%s] %s", source, message)
	}

	entry := LogEntry{
		Timestamp: now.Format("2006-01-02 15:04:05"),
		Level:     strings.ToUpper(level),
		Message:   fullMsg,
	}
	Default.Add(entry)
}
