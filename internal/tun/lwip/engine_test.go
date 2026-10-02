//go:build with_lwip && cgo

package lwip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func calcIPv6UpperChecksum(srcIP, dstIP net.IP, nextHeader uint8, upperPayload []byte) uint16 {
	pseudoLen := 16 + 16 + 4 + 4 + len(upperPayload)
	pseudo := make([]byte, pseudoLen)
	copy(pseudo[0:16], srcIP.To16())
	copy(pseudo[16:32], dstIP.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(upperPayload)))
	pseudo[39] = nextHeader
	copy(pseudo[40:], upperPayload)
	c := checksum(pseudo)
	if c == 0 {
		return 0xffff
	}
	return c
}

func buildIPv4UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x5678)
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	// UDP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	pkt[26] = 0
	pkt[27] = 0

	if len(payload) > 0 {
		copy(pkt[28:], payload)
	}
	return pkt
}

func buildIPv6TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	totalLen := 40 + tcpLen
	pkt := make([]byte, totalLen)

	// IPv6 Header
	pkt[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpLen))
	pkt[6] = 6 // Next header: TCP
	pkt[7] = 64 // Hop limit
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// TCP Header
	tcpHeader := pkt[40:]
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seq)
	binary.BigEndian.PutUint32(tcpHeader[8:12], ack)
	tcpHeader[12] = 0x50 // Data offset 5 (20 bytes)
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)

	if len(payload) > 0 {
		copy(tcpHeader[20:], payload)
	}

	chk := calcIPv6UpperChecksum(srcIP, dstIP, 6, tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], chk)

	return pkt
}

func buildIPv6UDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 40 + udpLen
	pkt := make([]byte, totalLen)

	// IPv6 Header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17 // Next header: UDP
	pkt[7] = 64 // Hop limit
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// UDP Header
	udpHeader := pkt[40:]
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLen))

	if len(payload) > 0 {
		copy(udpHeader[8:], payload)
	}

	chk := calcIPv6UpperChecksum(srcIP, dstIP, 17, udpHeader)
	binary.BigEndian.PutUint16(udpHeader[6:8], chk)

	return pkt
}

func buildIPv4ICMP(srcIP, dstIP net.IP, icmpType, icmpCode uint8, id, seq uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1122)
	pkt[6] = 0x40
	pkt[7] = 0x00
	pkt[8] = 64
	pkt[9] = 1 // ICMP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	// ICMP Header
	pkt[20] = icmpType
	pkt[21] = icmpCode
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	if len(payload) > 0 {
		copy(pkt[28:], payload)
	}
	binary.BigEndian.PutUint16(pkt[22:24], checksum(pkt[20:]))

	return pkt
}

func buildIPv6ICMP(srcIP, dstIP net.IP, icmpType, icmpCode uint8, id, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	totalLen := 40 + icmpLen
	pkt := make([]byte, totalLen)

	// IPv6 Header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = 58 // Next header: ICMPv6
	pkt[7] = 64
	copy(pkt[8:24], srcIP.To16())
	copy(pkt[24:40], dstIP.To16())

	// ICMPv6 Header
	icmpHeader := pkt[40:]
	icmpHeader[0] = icmpType
	icmpHeader[1] = icmpCode
	binary.BigEndian.PutUint16(icmpHeader[4:6], id)
	binary.BigEndian.PutUint16(icmpHeader[6:8], seq)
	if len(payload) > 0 {
		copy(icmpHeader[8:], payload)
	}

	chk := calcIPv6UpperChecksum(srcIP, dstIP, 58, icmpHeader)
	binary.BigEndian.PutUint16(icmpHeader[2:4], chk)

	return pkt
}

func buildIPv4TCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	totalLen := 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)

	// IPv4 Header
	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234)
	pkt[6] = 0x40 // Don't fragment
	pkt[7] = 0x00
	pkt[8] = 64 // TTL
	pkt[9] = 6  // Protocol TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	// TCP Header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint32(pkt[24:28], seq)
	binary.BigEndian.PutUint32(pkt[28:32], ack)
	pkt[32] = 0x50 // Data offset 5 (20 bytes)
	pkt[33] = flags
	binary.BigEndian.PutUint16(pkt[34:36], 65535)

	if len(payload) > 0 {
		copy(pkt[40:], payload)
	}

	pseudo := make([]byte, 12+20+len(payload))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))
	copy(pseudo[12:], pkt[20:])
	binary.BigEndian.PutUint16(pkt[36:38], checksum(pseudo))

	return pkt
}

func TestEngine_TCP_Handshake_Data_Close(t *testing.T) {
	outPkts := make(chan []byte, 32)
	connChan := make(chan net.Conn, 1)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(1, 1, 1, 1)
	clientPort := uint16(45678)
	targetPort := uint16(80)

	// Step 1: Send SYN
	synPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 1000, 0, 0x02, nil)
	if err := engine.Input(synPkt); err != nil {
		t.Fatalf("engine.Input SYN failed: %v", err)
	}

	// Step 2: Receive SYN/ACK
	var synAck []byte
	select {
	case synAck = <-outPkts:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SYN/ACK")
	}

	if len(synAck) < 40 {
		t.Fatalf("packet too short: %d", len(synAck))
	}
	flags := synAck[33]
	if (flags & 0x12) != 0x12 {
		t.Fatalf("expected SYN|ACK flags (0x12), got 0x%02x", flags)
	}
	synAckSeq := binary.BigEndian.Uint32(synAck[24:28])

	// Step 3: Send client ACK to finish 3-way handshake
	ackPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 1001, synAckSeq+1, 0x10, nil)
	if err := engine.Input(ackPkt); err != nil {
		t.Fatalf("engine.Input ACK failed: %v", err)
	}

	// Step 4: Verify TCPHandler is invoked
	var conn net.Conn
	select {
	case conn = <-connChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCPHandler")
	}
	defer conn.Close()

	if conn.RemoteAddr().String() != "10.0.0.2:45678" {
		t.Errorf("expected RemoteAddr 10.0.0.2:45678, got %s", conn.RemoteAddr().String())
	}
	if conn.LocalAddr().String() != "1.1.1.1:80" {
		t.Errorf("expected LocalAddr 1.1.1.1:80, got %s", conn.LocalAddr().String())
	}

	// Step 5: Send client DATA -> Read from conn
	clientMsg := []byte("hello from client")
	dataPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 1001, synAckSeq+1, 0x18, clientMsg)
	if err := engine.Input(dataPkt); err != nil {
		t.Fatalf("engine.Input data failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("conn.Read failed: %v", err)
	}
	if !bytes.Equal(buf[:n], clientMsg) {
		t.Fatalf("expected %q, got %q", string(clientMsg), string(buf[:n]))
	}

	// Step 6: Write from conn -> Receive DATA packet from output
	proxyMsg := []byte("hello from proxy")
	wn, err := conn.Write(proxyMsg)
	if err != nil {
		t.Fatalf("conn.Write failed: %v", err)
	}
	if wn != len(proxyMsg) {
		t.Fatalf("conn.Write short write: %d vs %d", wn, len(proxyMsg))
	}

	// Look for outgoing data packet
	var proxyDataPkt []byte
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-outPkts:
			if len(pkt) >= 40 && bytes.Contains(pkt, proxyMsg) {
				proxyDataPkt = pkt
				goto dataVerified
			}
		case <-deadline:
			t.Fatal("timeout waiting for proxy DATA packet")
		}
	}
dataVerified:
	if proxyDataPkt == nil {
		t.Fatal("proxy data packet not received")
	}

	// Step 7: Close conn -> Receive FIN packet
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close failed: %v", err)
	}

	finFound := false
	finDeadline := time.After(2 * time.Second)
	for !finFound {
		select {
		case pkt := <-outPkts:
			if len(pkt) >= 40 && (pkt[33]&0x01) != 0 {
				finFound = true
			}
		case <-finDeadline:
			t.Fatal("timeout waiting for FIN packet from proxy")
		}
	}

	// Read after close should return EOF or ErrClosed
	_, rerr := conn.Read(buf)
	if rerr != io.EOF && rerr != net.ErrClosed {
		t.Logf("Read after close returned: %v (expected EOF or ErrClosed)", rerr)
	}
}

func TestEngine_TCP_Deadlines(t *testing.T) {
	outPkts := make(chan []byte, 32)
	connChan := make(chan net.Conn, 1)

	cfg := Config{
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(2, 2, 2, 2)
	clientPort := uint16(51234)
	targetPort := uint16(8080)

	// Handshake
	synPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 2000, 0, 0x02, nil)
	_ = engine.Input(synPkt)
	synAck := <-outPkts
	synAckSeq := binary.BigEndian.Uint32(synAck[24:28])

	ackPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 2001, synAckSeq+1, 0x10, nil)
	_ = engine.Input(ackPkt)

	conn := <-connChan
	defer conn.Close()

	// Test read deadline timeout
	err = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	buf := make([]byte, 128)
	_, rerr := conn.Read(buf)
	if rerr == nil {
		t.Fatal("expected timeout error, got nil")
	}

	// Clear read deadline, then send data
	_ = conn.SetReadDeadline(time.Time{})
	clientMsg := []byte("resume after deadline")
	dataPkt := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 2001, synAckSeq+1, 0x18, clientMsg)
	_ = engine.Input(dataPkt)

	n, rerr := conn.Read(buf)
	if rerr != nil {
		t.Fatalf("Read after clearing deadline failed: %v", rerr)
	}
	if !bytes.Equal(buf[:n], clientMsg) {
		t.Fatalf("expected %q, got %q", string(clientMsg), string(buf[:n]))
	}
}

func TestEngine_TCP_MultipleConns(t *testing.T) {
	outPkts := make(chan []byte, 64)
	connChan := make(chan net.Conn, 10)

	cfg := Config{
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)

	// Conn 1: to 1.1.1.1:80
	syn1 := buildIPv4TCP(clientIP, net.IPv4(1, 1, 1, 1), 60001, 80, 3000, 0, 0x02, nil)
	_ = engine.Input(syn1)
	synAck1 := <-outPkts
	seq1 := binary.BigEndian.Uint32(synAck1[24:28])
	ack1 := buildIPv4TCP(clientIP, net.IPv4(1, 1, 1, 1), 60001, 80, 3001, seq1+1, 0x10, nil)
	_ = engine.Input(ack1)

	// Conn 2: to 8.8.8.8:443
	syn2 := buildIPv4TCP(clientIP, net.IPv4(8, 8, 8, 8), 60002, 443, 4000, 0, 0x02, nil)
	_ = engine.Input(syn2)
	synAck2 := <-outPkts
	seq2 := binary.BigEndian.Uint32(synAck2[24:28])
	ack2 := buildIPv4TCP(clientIP, net.IPv4(8, 8, 8, 8), 60002, 443, 4001, seq2+1, 0x10, nil)
	_ = engine.Input(ack2)

	c1 := <-connChan
	c2 := <-connChan
	defer c1.Close()
	defer c2.Close()

	// Verify both connections were routed correctly
	addrs := map[string]bool{
		c1.LocalAddr().String(): true,
		c2.LocalAddr().String(): true,
	}
	if !addrs["1.1.1.1:80"] || !addrs["8.8.8.8:443"] {
		t.Fatalf("expected conns to 1.1.1.1:80 and 8.8.8.8:443, got %s and %s", c1.LocalAddr(), c2.LocalAddr())
	}
}

func TestEngine_TCP_Backpressure(t *testing.T) {
	outPkts := make(chan []byte, 128)
	connChan := make(chan net.Conn, 1)

	cfg := Config{
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(3, 3, 3, 3)
	clientPort := uint16(55555)
	targetPort := uint16(9000)

	// Step 1: Handshake
	syn := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 10000, 0, 0x02, nil)
	_ = engine.Input(syn)
	synAck := <-outPkts
	synAckSeq := binary.BigEndian.Uint32(synAck[24:28])

	ack := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, 10001, synAckSeq+1, 0x10, nil)
	_ = engine.Input(ack)

	conn := <-connChan
	defer conn.Close()

	// Step 2: Prepare a 50KB payload (exceeds default TCP_SND_BUF ~23KB)
	largePayload := make([]byte, 50000)
	for i := range largePayload {
		largePayload[i] = byte(i % 251)
	}

	writeDone := make(chan error, 1)
	go func() {
		n, werr := conn.Write(largePayload)
		if werr != nil {
			writeDone <- werr
			return
		}
		if n != len(largePayload) {
			writeDone <- io.ErrShortWrite
			return
		}
		writeDone <- nil
	}()

	// Step 3: Receive segments and acknowledge them
	receivedBytes := 0
	clientSeq := uint32(10001)
	timeout := time.After(5 * time.Second)

	for receivedBytes < len(largePayload) {
		select {
		case pkt := <-outPkts:
			if len(pkt) < 40 {
				continue
			}
			dataOffset := int((pkt[32] >> 4) * 4)
			payloadLen := len(pkt) - 20 - dataOffset
			if payloadLen > 0 {
				receivedBytes += payloadLen
				seq := binary.BigEndian.Uint32(pkt[24:28])
				ackNum := seq + uint32(payloadLen)

				// Send client ACK to acknowledge received data and reopen sndbuf
				clientAck := buildIPv4TCP(clientIP, targetIP, clientPort, targetPort, clientSeq, ackNum, 0x10, nil)
				_ = engine.Input(clientAck)
			}
		case <-timeout:
			t.Fatalf("timeout during backpressure test: received %d of %d bytes", receivedBytes, len(largePayload))
		}
	}

	select {
	case werr := <-writeDone:
		if werr != nil {
			t.Fatalf("conn.Write error: %v", werr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for conn.Write to complete")
	}

	if receivedBytes != len(largePayload) {
		t.Fatalf("received bytes mismatch: %d vs %d", receivedBytes, len(largePayload))
	}
}

func TestEngine_UDP_Echo(t *testing.T) {
	outPkts := make(chan []byte, 32)
	udpChan := make(chan *PacketConn, 1)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		UDPHandler: func(conn *PacketConn) {
			udpChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(8, 8, 8, 8)
	clientPort := uint16(40001)
	targetPort := uint16(53)

	// Inject UDP packet from client to 8.8.8.8:53
	queryData := []byte("PING_UDP_PAYLOAD")
	pkt := buildIPv4UDP(clientIP, targetIP, clientPort, targetPort, queryData)
	if err := engine.Input(pkt); err != nil {
		t.Fatalf("Input failed: %v", err)
	}

	var pconn *PacketConn
	select {
	case pconn = <-udpChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDPHandler")
	}

	// Verify endpoints
	if pconn.LocalAddr().String() != "10.0.0.2:40001" {
		t.Errorf("expected LocalAddr 10.0.0.2:40001, got %s", pconn.LocalAddr())
	}
	if pconn.RemoteAddr().String() != "8.8.8.8:53" {
		t.Errorf("expected RemoteAddr 8.8.8.8:53, got %s", pconn.RemoteAddr())
	}
	if pconn.Source().Addr.String() != "10.0.0.2" || pconn.Source().Port != 40001 {
		t.Errorf("expected Source 10.0.0.2:40001, got %s", pconn.Source())
	}
	if pconn.Destination().Addr.String() != "8.8.8.8" || pconn.Destination().Port != 53 {
		t.Errorf("expected Destination 8.8.8.8:53, got %s", pconn.Destination())
	}

	// Read packet using ReadPacket
	b := buf.NewPacket()
	defer b.Release()
	dst, err := pconn.ReadPacket(b)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if dst.Addr.String() != "8.8.8.8" || dst.Port != 53 {
		t.Errorf("ReadPacket dst mismatch: %s", dst)
	}
	if !bytes.Equal(b.Bytes(), queryData) {
		t.Errorf("payload mismatch: %s vs %s", string(b.Bytes()), string(queryData))
	}

	// Write response back using WritePacket
	respData := []byte("PONG_UDP_RESPONSE")
	respBuf := buf.As(respData)
	if err := pconn.WritePacket(respBuf, dst); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Verify TUN output
	select {
	case out := <-outPkts:
		if len(out) < 28 {
			t.Fatalf("output packet too short: %d", len(out))
		}
		if out[9] != 17 {
			t.Fatalf("expected UDP protocol (17), got %d", out[9])
		}
		srcP := binary.BigEndian.Uint16(out[20:22])
		dstP := binary.BigEndian.Uint16(out[22:24])
		if srcP != 53 || dstP != 40001 {
			t.Fatalf("UDP ports mismatch: %d -> %d", srcP, dstP)
		}
		if !bytes.Equal(out[28:], respData) {
			t.Fatalf("UDP response payload mismatch: %s", string(out[28:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP output packet")
	}

	// Also verify WriteTo
	secondResp := []byte("SECOND_UDP_REPLY")
	n, err := pconn.WriteTo(secondResp, &net.UDPAddr{IP: targetIP, Port: int(targetPort)})
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n != len(secondResp) {
		t.Fatalf("WriteTo short write: %d vs %d", n, len(secondResp))
	}

	select {
	case out := <-outPkts:
		if !bytes.Equal(out[28:], secondResp) {
			t.Fatalf("WriteTo payload mismatch: %s", string(out[28:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for second UDP output packet")
	}

	if err := pconn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestEngine_UDP_Deadlines(t *testing.T) {
	outPkts := make(chan []byte, 32)
	udpChan := make(chan *PacketConn, 1)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			outPkts <- packet
		},
		UDPHandler: func(conn *PacketConn) {
			udpChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(8, 8, 8, 8)
	pkt := buildIPv4UDP(clientIP, targetIP, 40002, 53, []byte("INIT"))
	_ = engine.Input(pkt)

	var pconn *PacketConn
	select {
	case pconn = <-udpChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDPHandler")
	}
	defer pconn.Close()

	// Drain initial packet
	bufData := make([]byte, 100)
	_, _, err = pconn.ReadFrom(bufData)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	// Set deadline in near future
	if err := pconn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	_, _, err = pconn.ReadFrom(bufData)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected ErrDeadlineExceeded, got: %v", err)
	}
}

func TestEngine_UDP_MultipleSessions(t *testing.T) {
	outPkts := make(chan []byte, 64)
	udpChan := make(chan *PacketConn, 4)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		UDPHandler: func(conn *PacketConn) {
			udpChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	target1 := net.IPv4(8, 8, 8, 8)
	target2 := net.IPv4(1, 1, 1, 1)

	// Client 1: 41001 -> 8.8.8.8:53
	// Client 2: 41002 -> 1.1.1.1:53
	_ = engine.Input(buildIPv4UDP(clientIP, target1, 41001, 53, []byte("C1-PING")))
	_ = engine.Input(buildIPv4UDP(clientIP, target2, 41002, 53, []byte("C2-PING")))

	conns := make(map[uint16]*PacketConn)
	for i := 0; i < 2; i++ {
		select {
		case c := <-udpChan:
			port := uint16(c.LocalAddr().(*net.UDPAddr).Port)
			conns[port] = c
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for 2 UDP connections")
		}
	}

	c1 := conns[41001]
	c2 := conns[41002]
	if c1 == nil || c2 == nil {
		t.Fatalf("failed to establish both UDP connections: %+v", conns)
	}
	defer c1.Close()
	defer c2.Close()

	// Reply to both
	_, _ = c1.WriteTo([]byte("C1-PONG"), &net.UDPAddr{IP: target1, Port: 53})
	_, _ = c2.WriteTo([]byte("C2-PONG"), &net.UDPAddr{IP: target2, Port: 53})

	replies := make(map[uint16]string)
	for i := 0; i < 2; i++ {
		select {
		case out := <-outPkts:
			if len(out) >= 28 && out[9] == 17 {
				dstPort := binary.BigEndian.Uint16(out[22:24])
				replies[dstPort] = string(out[28:])
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for 2 UDP replies")
		}
	}

	if replies[41001] != "C1-PONG" || replies[41002] != "C2-PONG" {
		t.Fatalf("unexpected UDP replies: %+v", replies)
	}
}

func TestEngine_IPv6_TCP(t *testing.T) {
	outPkts := make(chan []byte, 32)
	connChan := make(chan net.Conn, 1)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.ParseIP("fd00::2")
	targetIP := net.ParseIP("2606:4700::6810:84e5")
	clientPort := uint16(51234)
	targetPort := uint16(80)

	// Step 1: Send IPv6 TCP SYN
	synPkt := buildIPv6TCP(clientIP, targetIP, clientPort, targetPort, 2000, 0, 0x02, nil)
	if err := engine.Input(synPkt); err != nil {
		t.Fatalf("Input SYN failed: %v", err)
	}

	var synAckSeq uint32
	select {
	case out := <-outPkts:
		if len(out) < 60 {
			t.Fatalf("expected at least 60 bytes for IPv6 TCP packet, got %d", len(out))
		}
		if (out[0] >> 4) != 6 {
			t.Fatalf("expected IPv6 version, got %d", out[0]>>4)
		}
		if out[6] != 6 {
			t.Fatalf("expected NextHeader TCP (6), got %d", out[6])
		}
		flags := out[40+13]
		if (flags & 0x12) != 0x12 {
			t.Fatalf("expected SYN|ACK flags (0x12), got 0x%02x", flags)
		}
		synAckSeq = binary.BigEndian.Uint32(out[40+4 : 40+8])
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for IPv6 TCP SYN/ACK")
	}

	// Step 2: Send IPv6 TCP ACK to complete handshake
	ackPkt := buildIPv6TCP(clientIP, targetIP, clientPort, targetPort, 2001, synAckSeq+1, 0x10, nil)
	if err := engine.Input(ackPkt); err != nil {
		t.Fatalf("Input ACK failed: %v", err)
	}

	var conn net.Conn
	select {
	case conn = <-connChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCPHandler in IPv6")
	}
	defer conn.Close()

	// Verify IPv6 addresses on Conn
	if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(clientIP) {
		t.Errorf("RemoteAddr mismatch: %s vs %s", conn.RemoteAddr(), clientIP)
	}
	if !conn.LocalAddr().(*net.TCPAddr).IP.Equal(targetIP) {
		t.Errorf("LocalAddr mismatch: %s vs %s", conn.LocalAddr(), targetIP)
	}

	// Step 3: Write data from server to client over IPv6 TCP
	go func() {
		_, _ = conn.Write([]byte("PONG_IPV6_TCP"))
	}()

	select {
	case out := <-outPkts:
		if len(out) >= 60 && out[6] == 6 {
			payload := out[60:]
			if !bytes.Equal(payload, []byte("PONG_IPV6_TCP")) {
				t.Fatalf("IPv6 TCP data mismatch: %s", string(payload))
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for IPv6 TCP data packet")
	}
}

func TestEngine_IPv6_UDP(t *testing.T) {
	outPkts := make(chan []byte, 32)
	udpChan := make(chan *PacketConn, 1)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		UDPHandler: func(conn *PacketConn) {
			udpChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.ParseIP("fd00::2")
	targetIP := net.ParseIP("2001:4860:4860::8888")
	clientPort := uint16(52000)
	targetPort := uint16(53)

	queryData := []byte("PING_IPV6_UDP")
	pkt := buildIPv6UDP(clientIP, targetIP, clientPort, targetPort, queryData)
	if err := engine.Input(pkt); err != nil {
		t.Fatalf("Input IPv6 UDP failed: %v", err)
	}

	var pconn *PacketConn
	select {
	case pconn = <-udpChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for IPv6 UDPHandler")
	}
	defer pconn.Close()

	// Read packet
	b := buf.NewPacket()
	defer b.Release()
	dst, err := pconn.ReadPacket(b)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if !bytes.Equal(b.Bytes(), queryData) {
		t.Fatalf("payload mismatch: %s", string(b.Bytes()))
	}
	if !dst.Addr.Is6() {
		t.Fatalf("expected IPv6 destination, got %v", dst)
	}

	// Write response back
	respData := []byte("PONG_IPV6_UDP")
	respBuf := buf.As(respData)
	if err := pconn.WritePacket(respBuf, dst); err != nil {
		t.Fatalf("WritePacket IPv6 failed: %v", err)
	}

	select {
	case out := <-outPkts:
		if len(out) < 48 {
			t.Fatalf("output packet too short: %d", len(out))
		}
		if (out[0] >> 4) != 6 {
			t.Fatalf("expected IPv6, got %d", out[0]>>4)
		}
		if out[6] != 17 {
			t.Fatalf("expected UDP next header (17), got %d", out[6])
		}
		srcP := binary.BigEndian.Uint16(out[40:42])
		dstP := binary.BigEndian.Uint16(out[42:44])
		if srcP != 53 || dstP != 52000 {
			t.Fatalf("UDP IPv6 ports mismatch: %d -> %d", srcP, dstP)
		}
		if !bytes.Equal(out[48:], respData) {
			t.Fatalf("payload mismatch: %s", string(out[48:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for IPv6 UDP output packet")
	}
}

func TestEngine_ICMPv4_Echo(t *testing.T) {
	outPkts := make(chan []byte, 32)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(8, 8, 8, 8)
	pingPayload := []byte("PING_ICMP_DATA")

	// Type 8 = Echo Request, Code 0
	icmpReq := buildIPv4ICMP(clientIP, targetIP, 8, 0, 0x1234, 1, pingPayload)
	if err := engine.Input(icmpReq); err != nil {
		t.Fatalf("Input ICMP failed: %v", err)
	}

	select {
	case out := <-outPkts:
		if len(out) < 28 {
			t.Fatalf("ICMP reply packet too short: %d", len(out))
		}
		if out[9] != 1 {
			t.Fatalf("expected ICMP protocol (1), got %d", out[9])
		}
		// In IPv4 ICMP, type is at byte 20, code at byte 21
		icmpType := out[20]
		icmpCode := out[21]
		if icmpType != 0 || icmpCode != 0 {
			t.Fatalf("expected ICMP Echo Reply (type 0, code 0), got type=%d, code=%d", icmpType, icmpCode)
		}
		id := binary.BigEndian.Uint16(out[24:26])
		seq := binary.BigEndian.Uint16(out[26:28])
		if id != 0x1234 || seq != 1 {
			t.Fatalf("ICMP id/seq mismatch: id=0x%x, seq=%d", id, seq)
		}
		if !bytes.Equal(out[28:], pingPayload) {
			t.Fatalf("ICMP payload mismatch: %s", string(out[28:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ICMP Echo Reply")
	}
}

func TestEngine_ICMPv6_Echo(t *testing.T) {
	outPkts := make(chan []byte, 32)

	cfg := Config{
		IPv4:    net.IPv4(10, 0, 0, 2),
		Mask:    net.IPv4(255, 255, 255, 0),
		Gateway: net.IPv4(10, 0, 0, 1),
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.ParseIP("fd00::2")
	targetIP := net.ParseIP("2001:4860:4860::8888")
	pingPayload := []byte("PING_ICMP6_DATA")

	// Type 128 = ICMPv6 Echo Request, Code 0
	icmpReq := buildIPv6ICMP(clientIP, targetIP, 128, 0, 0x5678, 2, pingPayload)
	if err := engine.Input(icmpReq); err != nil {
		t.Fatalf("Input ICMPv6 failed: %v", err)
	}

	select {
	case out := <-outPkts:
		if len(out) < 48 {
			t.Fatalf("ICMPv6 reply packet too short: %d", len(out))
		}
		if (out[0] >> 4) != 6 {
			t.Fatalf("expected IPv6 version, got %d", out[0]>>4)
		}
		if out[6] != 58 {
			t.Fatalf("expected ICMPv6 next header (58), got %d", out[6])
		}
		// In IPv6, ICMPv6 header starts at byte 40
		icmpType := out[40]
		icmpCode := out[41]
		if icmpType != 129 || icmpCode != 0 {
			t.Fatalf("expected ICMPv6 Echo Reply (type 129, code 0), got type=%d, code=%d", icmpType, icmpCode)
		}
		id := binary.BigEndian.Uint16(out[44:46])
		seq := binary.BigEndian.Uint16(out[46:48])
		if id != 0x5678 || seq != 2 {
			t.Fatalf("ICMPv6 id/seq mismatch: id=0x%x, seq=%d", id, seq)
		}
		if !bytes.Equal(out[48:], pingPayload) {
			t.Fatalf("ICMPv6 payload mismatch: %s", string(out[48:]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ICMPv6 Echo Reply")
	}
}

func TestEngine_TCP_MTU_1400_MSS(t *testing.T) {
	outPkts := make(chan []byte, 16)
	connChan := make(chan net.Conn, 1)

	cfg := Config{
		MTU: 1400,
		OutputFn: func(packet []byte) {
			p := make([]byte, len(packet))
			copy(p, packet)
			outPkts <- p
		},
		TCPHandler: func(conn net.Conn) {
			connChan <- conn
		},
	}

	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer engine.Close()

	clientIP := net.IPv4(10, 0, 0, 2)
	targetIP := net.IPv4(1, 1, 1, 1)
	clientPort := uint16(45678)
	targetPort := uint16(80)

	// Send SYN with MSS 1360 option and Window Scale option (scale factor 7)
	// IPv4 header (20 bytes) + TCP header (20 bytes) + MSS opt (4 bytes) + Wscale opt (3 bytes + 1 NOP)
	totalLen := 20 + 20 + 8
	synPkt := make([]byte, totalLen)
	synPkt[0] = 0x45
	binary.BigEndian.PutUint16(synPkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(synPkt[4:6], 0x1234)
	synPkt[6] = 0x40
	synPkt[8] = 64
	synPkt[9] = 6 // TCP
	copy(synPkt[12:16], clientIP.To4())
	copy(synPkt[16:20], targetIP.To4())
	binary.BigEndian.PutUint16(synPkt[10:12], checksum(synPkt[0:20]))

	tcpHdr := synPkt[20:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], clientPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], targetPort)
	binary.BigEndian.PutUint32(tcpHdr[4:8], 1000)
	tcpHdr[12] = 0x70 // Data offset 7 (28 bytes)
	tcpHdr[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHdr[14:16], 65535)

	// TCP MSS Option (kind 2, len 4, value 1360)
	tcpHdr[20] = 0x02
	tcpHdr[21] = 0x04
	binary.BigEndian.PutUint16(tcpHdr[22:24], 1360)

	// TCP Window Scale Option (NOP=0x01, kind 3, len 3, shift 7)
	tcpHdr[24] = 0x01 // NOP
	tcpHdr[25] = 0x03
	tcpHdr[26] = 0x03
	tcpHdr[27] = 0x07

	pseudo := make([]byte, 12+len(tcpHdr))
	copy(pseudo[0:4], clientIP.To4())
	copy(pseudo[4:8], targetIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHdr)))
	copy(pseudo[12:], tcpHdr)
	binary.BigEndian.PutUint16(tcpHdr[16:18], checksum(pseudo))

	if err := engine.Input(synPkt); err != nil {
		t.Fatalf("engine.Input SYN failed: %v", err)
	}

	var synAck []byte
	select {
	case synAck = <-outPkts:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for SYN/ACK")
	}

	if len(synAck) < 40 {
		t.Fatalf("synAck too short: %d", len(synAck))
	}

	dataOffset := int((synAck[32] >> 4) * 4)
	if dataOffset < 24 {
		t.Fatalf("expected TCP options in SYN/ACK, dataOffset=%d", dataOffset)
	}

	opts := synAck[40 : 20+dataOffset]
	foundMSS := false
	foundWScale := false
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 { // End of options
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			break
		}
		if kind == 2 && optLen == 4 { // MSS option
			mssVal := binary.BigEndian.Uint16(opts[i+2 : i+4])
			if mssVal != 1360 {
				t.Fatalf("expected advertised MSS to be 1360 for MTU 1400, got %d", mssVal)
			}
			foundMSS = true
		}
		if kind == 3 && optLen == 3 { // Window Scale option
			scaleVal := opts[i+2]
			if scaleVal != 4 {
				t.Fatalf("expected advertised Window Scale to be 4, got %d", scaleVal)
			}
			foundWScale = true
		}
		i += optLen
	}

	if !foundMSS {
		t.Fatal("MSS option not found in SYN/ACK")
	}
	if !foundWScale {
		t.Fatal("Window Scale option not found in SYN/ACK")
	}
}



