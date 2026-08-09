package udp

import (
	"net"
	"testing"
)

// TestSetDisableUDPFragmentationSmoke verifies the helper runs without error on a real UDP
// socket (on linux it sets IP_MTU_DISCOVER=IP_PMTUDISC_DO; elsewhere it is a no-op). The
// option is best-effort, so the contract is "no error on a valid socket".
func TestSetDisableUDPFragmentationSmoke(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	uc, ok := pc.(*net.UDPConn)
	if !ok {
		t.Skipf("packet conn is %T, want *net.UDPConn", pc)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := setDisableUDPFragmentation(raw); err != nil {
		t.Fatalf("setDisableUDPFragmentation: %v", err)
	}
}
