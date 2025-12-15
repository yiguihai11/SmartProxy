package socks5

import (
	"io"
)

// TrafficWriter 带流量统计的Writer包装器
type TrafficWriter struct {
	writer    io.Writer
	connID    string
	direction string // "upload" 或 "download"
}

// NewTrafficWriter 创建流量统计Writer
func NewTrafficWriter(writer io.Writer, connID, direction string) *TrafficWriter {
	return &TrafficWriter{
		writer:    writer,
		connID:    connID,
		direction: direction,
	}
}

// Write 实现io.Writer接口，并统计流量
func (tw *TrafficWriter) Write(p []byte) (n int, err error) {
	n, err = tw.writer.Write(p)
	if n > 0 {
		// 记录流量
		if trafficMonitor := GetGlobalTrafficMonitor(); trafficMonitor != nil {
			if tw.direction == "upload" {
				trafficMonitor.RecordUpload(tw.connID, int64(n))
			} else {
				trafficMonitor.RecordDownload(tw.connID, int64(n))
			}
		}
	}
	return n, err
}

// TrafficReader 带流量统计的Reader包装器
type TrafficReader struct {
	reader    io.Reader
	connID    string
	direction string // "upload" 或 "download"
}

// NewTrafficReader 创建流量统计Reader
func NewTrafficReader(reader io.Reader, connID, direction string) *TrafficReader {
	return &TrafficReader{
		reader:    reader,
		connID:    connID,
		direction: direction,
	}
}

// Read 实现io.Reader接口，并统计流量
func (tr *TrafficReader) Read(p []byte) (n int, err error) {
	n, err = tr.reader.Read(p)
	if n > 0 {
		// 记录流量
		if trafficMonitor := GetGlobalTrafficMonitor(); trafficMonitor != nil {
			if tr.direction == "download" {
				trafficMonitor.RecordDownload(tr.connID, int64(n))
			} else {
				trafficMonitor.RecordUpload(tr.connID, int64(n))
			}
		}
	}
	return n, err
}