package logbuf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDailyFileLogger_WriteAndRead(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logbuf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	loc := shanghaiLocation()
	logger, err := NewDailyFileLogger(tempDir, 3, loc)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	now := time.Now().In(loc)
	dateStr := now.Format("2006-01-02")
	expectedFileName := fmt.Sprintf("smartproxy_%s.log", dateStr)

	// Write entries
	entries := []LogEntry{
		{Timestamp: "2026-09-24 10:00:00", Level: "INFO", Message: "Engine started"},
		{Timestamp: "2026-09-24 10:00:01", Level: "WARN", Message: "Slow upstream response"},
		{Timestamp: "2026-09-24 10:00:02", Level: "ERROR", Message: "[Android/VPN] Tun interface error"},
	}

	for _, entry := range entries {
		if err := logger.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry failed: %v", err)
		}
	}

	// List files
	files := logger.ListLogFiles()
	if len(files) != 1 || files[0] != expectedFileName {
		t.Fatalf("expected [%s], got %v", expectedFileName, files)
	}

	// Read entries
	readEntries, err := logger.ReadLogFile(expectedFileName, 10)
	if err != nil {
		t.Fatalf("ReadLogFile failed: %v", err)
	}
	if len(readEntries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(readEntries))
	}

	if readEntries[0].Level != "INFO" || readEntries[0].Message != "Engine started" {
		t.Errorf("entry 0 mismatch: %+v", readEntries[0])
	}
	if readEntries[1].Level != "WARN" || readEntries[1].Message != "Slow upstream response" {
		t.Errorf("entry 1 mismatch: %+v", readEntries[1])
	}
	if readEntries[2].Level != "ERROR" || readEntries[2].Message != "[Android/VPN] Tun interface error" {
		t.Errorf("entry 2 mismatch: %+v", readEntries[2])
	}
}

func TestDailyFileLogger_ClearToday(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logbuf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	loc := shanghaiLocation()
	logger, err := NewDailyFileLogger(tempDir, 3, loc)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	now := time.Now().In(loc)
	dateStr := now.Format("2006-01-02")
	fileName := fmt.Sprintf("smartproxy_%s.log", dateStr)

	_ = logger.WriteEntry(LogEntry{Level: "INFO", Message: "Test entry"})

	readBefore, err := logger.ReadLogFile(fileName, 10)
	if err != nil || len(readBefore) != 1 {
		t.Fatalf("expected 1 entry before clear, got %d (err: %v)", len(readBefore), err)
	}

	if err := logger.ClearToday(); err != nil {
		t.Fatalf("ClearToday failed: %v", err)
	}

	readAfter, err := logger.ReadLogFile(fileName, 10)
	if err != nil || len(readAfter) != 0 {
		t.Fatalf("expected 0 entries after clear, got %d (err: %v)", len(readAfter), err)
	}
}

func TestDailyFileLogger_RetentionCleanup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logbuf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create dummy log files
	oldFile := filepath.Join(tempDir, "smartproxy_2020-01-01.log")
	recentFile := filepath.Join(tempDir, "smartproxy_2026-09-23.log")
	todayFile := filepath.Join(tempDir, "smartproxy_2026-09-24.log")
	otherFile := filepath.Join(tempDir, "ignore_me.txt")

	_ = os.WriteFile(oldFile, []byte("old log\n"), 0644)
	_ = os.WriteFile(recentFile, []byte("recent log\n"), 0644)
	_ = os.WriteFile(todayFile, []byte("today log\n"), 0644)
	_ = os.WriteFile(otherFile, []byte("other file\n"), 0644)

	loc := shanghaiLocation()
	refTime, _ := time.ParseInLocation("2006-01-02", "2026-09-24", loc)

	logger, err := NewDailyFileLogger(tempDir, 3, loc)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	logger.cleanExpired(refTime)

	// oldFile (2020-01-01) should be removed
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("expected oldFile to be deleted, but it exists")
	}
	// recentFile (2026-09-23) should remain (within 3 days of 2026-09-24)
	if _, err := os.Stat(recentFile); os.IsNotExist(err) {
		t.Errorf("expected recentFile to remain, but it was deleted")
	}
	// todayFile should remain
	if _, err := os.Stat(todayFile); os.IsNotExist(err) {
		t.Errorf("expected todayFile to remain, but it was deleted")
	}
	// unrelated file should not be touched
	if _, err := os.Stat(otherFile); os.IsNotExist(err) {
		t.Errorf("expected otherFile to remain, but it was deleted")
	}
}

func TestDailyFileLogger_MaxFileBytes(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logbuf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	loc := shanghaiLocation()
	logger, err := NewDailyFileLogger(tempDir, 3, loc)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Set tiny limit: 100 bytes
	logger.maxFileBytes = 100

	// Write first entry (~50 bytes)
	_ = logger.WriteEntry(LogEntry{Level: "INFO", Message: "Short line 1"})
	// Write second entry (~50 bytes)
	_ = logger.WriteEntry(LogEntry{Level: "INFO", Message: "Short line 2"})
	// Write third entry - should be skipped due to exceeding maxFileBytes
	_ = logger.WriteEntry(LogEntry{Level: "INFO", Message: "This line should exceed the 100 bytes limit and get skipped"})

	now := time.Now().In(loc)
	fileName := fmt.Sprintf("smartproxy_%s.log", now.Format("2006-01-02"))
	fi, err := os.Stat(filepath.Join(tempDir, fileName))
	if err != nil {
		t.Fatalf("failed to stat log file: %v", err)
	}
	if fi.Size() > 100 {
		t.Errorf("file size %d exceeded maxFileBytes 100", fi.Size())
	}
}

func TestAddExternalLog_Unified(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "logbuf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := InitFileLogger(tempDir, 3); err != nil {
		t.Fatalf("InitFileLogger failed: %v", err)
	}
	defer func() {
		fileLoggerMu.Lock()
		if defaultFileLogger != nil {
			defaultFileLogger.Close()
			defaultFileLogger = nil
		}
		fileLoggerMu.Unlock()
	}()

	Default.Clear()

	AddExternalLog("Android/VPN", "info", "VPN service started")
	AddExternalLog("Android/VPN", "error", "Fatal error in TUN fd")

	entries := Default.GetAll()
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 entries, got %d", len(entries))
	}

	last2 := entries[len(entries)-2:]
	if !strings.Contains(last2[0].Message, "[Android/VPN] VPN service started") {
		t.Errorf("unexpected msg: %s", last2[0].Message)
	}
	if last2[0].Level != "INFO" {
		t.Errorf("unexpected level: %s", last2[0].Level)
	}
	if !strings.Contains(last2[1].Message, "[Android/VPN] Fatal error in TUN fd") {
		t.Errorf("unexpected msg: %s", last2[1].Message)
	}
	if last2[1].Level != "ERROR" {
		t.Errorf("unexpected level: %s", last2[1].Level)
	}

	// Verify file log also has them
	files := ListLogFiles()
	if len(files) == 0 {
		t.Fatalf("expected at least 1 log file")
	}
	fileEntries, err := ReadLogFile(files[0], 100)
	if err != nil {
		t.Fatalf("ReadLogFile failed: %v", err)
	}
	if len(fileEntries) < 2 {
		t.Fatalf("expected at least 2 entries in file log, got %d", len(fileEntries))
	}
}
