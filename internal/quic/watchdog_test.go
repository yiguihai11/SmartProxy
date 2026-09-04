package quic

import (
	"sync/atomic"
	"testing"
	"time"

	"smartproxy/internal/dpi"
)

func cseg(off int, data []byte) []dpi.CryptoSeg {
	return []dpi.CryptoSeg{{Offset: off, Data: data}}
}

func TestRetransDetector(t *testing.T) {
	d := &retransDetector{}
	dcid := []byte{1, 2, 3}
	if d.retransmit(dcid, cseg(0, []byte("hello world"))) {
		t.Fatal("first segment must not be a retransmission")
	}
	if !d.retransmit(dcid, cseg(0, []byte("hello world"))) {
		t.Fatal("identical re-send must count as retransmission")
	}
	if d.retransmit(dcid, cseg(100, []byte("more"))) {
		t.Fatal("new offset must be new data, not retransmission")
	}
	if !d.retransmit(dcid, cseg(100, []byte("more"))) {
		t.Fatal("re-send of new segment must be retransmission")
	}
	// 另一条流隔离
	if d.retransmit([]byte{9, 9}, cseg(0, []byte("x"))) {
		t.Fatal("different DCID must not interfere")
	}
}

func TestWatchdogTimeout(t *testing.T) {
	var calls atomic.Int32
	w := NewWatchdog(50*time.Millisecond, func(reason string) {
		calls.Add(1)
	})
	w.Begin()
	time.Sleep(120 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("dead callback fired %d times, want 1", calls.Load())
	}
}

func TestWatchdogReplyCancels(t *testing.T) {
	var calls atomic.Int32
	w := NewWatchdog(50*time.Millisecond, func(reason string) {
		calls.Add(1)
	})
	w.Begin()
	w.OnServerReply()
	time.Sleep(120 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("reply must cancel timeout, fired %d", calls.Load())
	}
}

func TestWatchdogRetransmitKills(t *testing.T) {
	var calls atomic.Int32
	w := NewWatchdog(10*time.Second, func(reason string) {
		calls.Add(1)
	})
	w.Begin()
	dcid := []byte{7, 7, 7}
	w.OnClientDatagram(dcid, cseg(0, []byte("initial hello")))
	// 重传同段 → 立即判死,不等 timeout
	w.OnClientDatagram(dcid, cseg(0, []byte("initial hello")))
	if calls.Load() != 1 {
		t.Fatalf("retransmission with no reply must kill, fired %d", calls.Load())
	}
	// 判死只回调一次
	time.Sleep(20 * time.Millisecond)
	w.Stop()
	if calls.Load() != 1 {
		t.Fatalf("dead callback must fire once, got %d", calls.Load())
	}
}

func TestWatchdogStop(t *testing.T) {
	var calls atomic.Int32
	w := NewWatchdog(30*time.Millisecond, func(reason string) {
		calls.Add(1)
	})
	w.Begin()
	w.Stop()
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("Stop must suppress callback, fired %d", calls.Load())
	}
}

func TestWatchdogNeedsBegin(t *testing.T) {
	var calls atomic.Int32
	w := NewWatchdog(30*time.Millisecond, func(reason string) {
		calls.Add(1)
	})
	w.OnClientDatagram([]byte{1}, cseg(0, []byte("x")))
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatal("no Begin → no timer, must not fire")
	}
}

func TestSniffRejectsNonQUIC(t *testing.T) {
	s := NewSniff(time.Hour, 2048)
	// 一个明显不是 QUIC 长头的 UDP 载荷(短、普通字节)
	garbage := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if s.Ingest(garbage) == false {
		// 非 QUIC:首包即 ready
	}
	if !s.Ready() {
		t.Fatal("non-QUIC first datagram must settle immediately")
	}
	if s.QUIC() {
		t.Fatal("garbage must not be flagged QUIC")
	}
	// 判定固化后后续包为 no-op,不会崩
	s.Ingest([]byte{0xff, 0xff, 0xff, 0xff})
}

func TestDummyNotQUIC(t *testing.T) {
	for i := 0; i < 50; i++ {
		d := NewDummyDatagram()
		if len(d) < 40 {
			t.Fatalf("dummy too short: %d", len(d))
		}
		// 首字节不该构成 QUIC 客户端 Initial(长头 fixed bit + type=00)
		if d[0]&0x80 != 0 && d[0]&0x40 != 0 && d[0]&0x30 == 0 {
			t.Fatalf("dummy looks like QUIC Initial: first byte %#x", d[0])
		}
		_, _, pkts := dpi.DecryptInitialDatagram(d)
		if pkts > 0 {
			t.Fatal("dummy must not decrypt as client Initial")
		}
	}
}
