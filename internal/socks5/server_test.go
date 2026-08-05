package socks5

import (
	"bytes"
	"io"
	"testing"
)

func TestHandshake_NoAuth(t *testing.T) {

	clientReq := []byte{0x05, 0x02, 0x00, 0x02}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := buf.Bytes()
	if len(resp) < 2 {
		t.Fatal("response too short")
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("expected [0x05, 0x00], got %x", resp)
	}
}

func TestHandshake_NoAuthWithCredentials_ServerNoAuth(t *testing.T) {

	clientReq := []byte{0x05, 0x02, 0x00, 0x02}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "user", "pass")
	if err == nil {
		t.Fatal("expected authentication error when server requires auth but client only offers NoAuth")
	}
}

func TestHandshake_AuthSuccess(t *testing.T) {

	clientReq := []byte{0x05, 0x01, 0x02}

	authSub := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}

	var buf bytes.Buffer
	buf.Write(clientReq)
	buf.Write(authSub)

	err := Handshake(&buf, "user", "pass")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resp := buf.Bytes()
	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Errorf("expected method selection [0x05, 0x02], got %x", resp[:2])
	}
	if resp[2] != 0x01 || resp[3] != 0x00 {
		t.Errorf("expected auth passed [0x01, 0x00], got %x", resp[2:])
	}
}

func TestHandshake_AuthFailure_WrongPassword(t *testing.T) {
	clientReq := []byte{0x05, 0x01, 0x02}
	authSub := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x05, 'w', 'r', 'o', 'n', 'g'}

	var buf bytes.Buffer
	buf.Write(clientReq)
	buf.Write(authSub)

	err := Handshake(&buf, "user", "pass")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if err.Error() != "authentication failed" {
		t.Errorf("expected 'authentication failed', got %q", err.Error())
	}

	resp := buf.Bytes()
	if len(resp) < 4 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[2] != 0x01 || resp[3] != 0x01 {
		t.Errorf("expected auth failed [0x01, 0x01], got %x", resp[2:])
	}
}

func TestHandshake_AuthFailure_WrongUsername(t *testing.T) {
	clientReq := []byte{0x05, 0x01, 0x02}
	authSub := []byte{0x01, 0x05, 'a', 'd', 'm', 'i', 'n', 0x04, 'p', 'a', 's', 's'}

	var buf bytes.Buffer
	buf.Write(clientReq)
	buf.Write(authSub)

	err := Handshake(&buf, "user", "pass")
	if err == nil {
		t.Fatal("expected error for wrong username, got nil")
	}
}

func TestHandshake_WrongVersion(t *testing.T) {
	clientReq := []byte{0x04, 0x01, 0x00}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

func TestHandshake_NoAcceptableMethod(t *testing.T) {

	clientReq := []byte{0x05, 0x01, 0x01}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for no acceptable method, got nil")
	}

	resp := buf.Bytes()
	if len(resp) < 2 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[0] != 0x05 || resp[1] != NoAccept {
		t.Errorf("expected [0x05, 0xFF], got %x", resp[:2])
	}
}

func TestHandshake_AuthRequired_NoAuthNotOffered(t *testing.T) {

	clientReq := []byte{0x05, 0x01, 0x02}
	authSub := []byte{0x01, 0x05, 't', 'e', 's', 't', '1', 0x05, 't', 'e', 's', 't', '1'}

	var buf bytes.Buffer
	buf.Write(clientReq)
	buf.Write(authSub)

	err := Handshake(&buf, "test1", "test1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	resp := buf.Bytes()
	if resp[2] != 0x01 || resp[3] != 0x00 {
		t.Errorf("expected auth passed, got %x", resp[2:])
	}
}

func TestHandshake_Auth_NoCredentials_OnServer(t *testing.T) {

	clientReq := []byte{0x05, 0x01, 0x02}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error, no acceptable auth method")
	}
}

func TestHandshake_Auth_InvalidAuthVersion(t *testing.T) {
	clientReq := []byte{0x05, 0x01, 0x02}
	authSub := []byte{0x02, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}

	var buf bytes.Buffer
	buf.Write(clientReq)
	buf.Write(authSub)

	err := Handshake(&buf, "user", "pass")
	if err == nil {
		t.Fatal("expected error for invalid auth version, got nil")
	}
}

func TestHandshake_IncompleteInitialRead(t *testing.T) {

	clientReq := []byte{0x05}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for incomplete read, got nil")
	}
}

func TestHandshake_IncompleteMethods(t *testing.T) {

	clientReq := []byte{0x05, 0x03, 0x00, 0x02}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for incomplete methods read, got nil")
	}
}

func TestHandshake_EmptyMethods(t *testing.T) {

	clientReq := []byte{0x05, 0x00}
	var buf bytes.Buffer
	buf.Write(clientReq)

	err := Handshake(&buf, "", "")
	if err == nil {
		t.Fatal("expected error for no acceptable method, got nil")
	}
}

func TestReceiveRequest_IPv4Connect(t *testing.T) {

	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	reader := bytes.NewReader(req)

	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != CommandConnect {
		t.Errorf("expected CONNECT, got %v", r.Command)
	}
	if r.Host != "127.0.0.1" {
		t.Errorf("expected 127.0.0.1, got %q", r.Host)
	}
	if r.Port != 80 {
		t.Errorf("expected port 80, got %d", r.Port)
	}
}

func TestReceiveRequest_DomainConnect(t *testing.T) {

	domain := "www.example.com"
	header := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	header = append(header, []byte(domain)...)
	header = append(header, 0x01, 0xBB)

	reader := bytes.NewReader(header)
	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != CommandConnect {
		t.Errorf("expected CONNECT, got %v", r.Command)
	}
	if r.Host != domain {
		t.Errorf("expected %q, got %q", domain, r.Host)
	}
	if r.Port != 443 {
		t.Errorf("expected port 443, got %d", r.Port)
	}
}

func TestReceiveRequest_IPv6Connect(t *testing.T) {

	header := []byte{0x05, 0x01, 0x00, 0x04}

	ipv6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	header = append(header, ipv6...)
	header = append(header, 0x04, 0x38)

	reader := bytes.NewReader(header)
	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != CommandConnect {
		t.Errorf("expected CONNECT, got %v", r.Command)
	}
	if r.Host != "::1" {
		t.Errorf("expected ::1, got %q", r.Host)
	}
	if r.Port != 1080 {
		t.Errorf("expected port 1080, got %d", r.Port)
	}
}

func TestReceiveRequest_UDPAssociate(t *testing.T) {
	header := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	reader := bytes.NewReader(header)
	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != CommandUDPAssociate {
		t.Errorf("expected UDP_ASSOCIATE, got %v", r.Command)
	}
}

func TestReceiveRequest_BindCommand(t *testing.T) {
	header := []byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	reader := bytes.NewReader(header)
	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Command != CommandBind {
		t.Errorf("expected BIND, got %v", r.Command)
	}
}

func TestReceiveRequest_WrongVersion(t *testing.T) {
	header := []byte{0x04, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for wrong version, got nil")
	}
}

func TestReceiveRequest_WrongRSV(t *testing.T) {
	header := []byte{0x05, 0x01, 0x01, 0x01, 0, 0, 0, 0, 0, 0}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for non-zero RSV, got nil")
	}
}

func TestReceiveRequest_UnsupportedATYP(t *testing.T) {
	header := []byte{0x05, 0x01, 0x00, 0x02, 0, 0}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for unsupported ATYP, got nil")
	}
}

func TestReceiveRequest_IncompleteHeader(t *testing.T) {
	header := []byte{0x05, 0x01}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for incomplete header, got nil")
	}
}

func TestReceiveRequest_IncompleteIPv4(t *testing.T) {
	header := []byte{0x05, 0x01, 0x00, 0x01, 127, 0}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for incomplete IPv4, got nil")
	}
}

func TestReceiveRequest_IncompleteDomain(t *testing.T) {
	header := []byte{0x05, 0x01, 0x00, 0x03, 10}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for incomplete domain, got nil")
	}
}

func TestReceiveRequest_IncompleteDomainContent(t *testing.T) {
	domain := "example.com"
	header := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	header = append(header, []byte(domain)[:5]...)
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for incomplete domain content, got nil")
	}
}

func TestReceiveRequest_IncompletePort(t *testing.T) {
	header := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for incomplete port, got nil")
	}
}

func TestReceiveRequest_LongDomain(t *testing.T) {

	domain := make([]byte, 255)
	for i := range domain {
		domain[i] = 'a'
	}
	header := []byte{0x05, 0x01, 0x00, 0x03, 0xFF}
	header = append(header, domain...)
	header = append(header, 0x00, 0x50)

	reader := bytes.NewReader(header)
	r, err := ReceiveRequest(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Host) != 255 {
		t.Errorf("expected domain length 255, got %d", len(r.Host))
	}
}

func TestReceiveRequest_EmptyDomain(t *testing.T) {

	header := []byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50}
	reader := bytes.NewReader(header)
	_, err := ReceiveRequest(reader)
	if err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
}

func TestSendReply_SuccessIPv4(t *testing.T) {
	var buf bytes.Buffer
	err := SendReply(&buf, ReplySuccess, "0.0.0.0", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := buf.Bytes()
	expectedLen := 4 + 4 + 2
	if len(resp) != expectedLen {
		t.Errorf("expected %d bytes, got %d", expectedLen, len(resp))
	}
	if resp[0] != Version5 || resp[1] != byte(ReplySuccess) || resp[2] != RSV || resp[3] != byte(AddrIPv4) {
		t.Errorf("unexpected header: %x", resp[:4])
	}
}

func TestSendReply_SuccessDomain(t *testing.T) {
	var buf bytes.Buffer
	err := SendReply(&buf, ReplySuccess, "localhost", 1080)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := buf.Bytes()
	if resp[0] != Version5 || resp[1] != byte(ReplySuccess) || resp[3] != byte(AddrDomain) {
		t.Errorf("unexpected header: %x", resp[:4])
	}

	if resp[4] != 9 {
		t.Errorf("expected domain length 9, got %d", resp[4])
	}
}

func TestSendReply_SuccessIPv6(t *testing.T) {
	var buf bytes.Buffer
	err := SendReply(&buf, ReplySuccess, "::1", 53)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := buf.Bytes()
	expectedLen := 4 + 16 + 2
	if len(resp) != expectedLen {
		t.Errorf("expected %d bytes, got %d", expectedLen, len(resp))
	}
	if resp[3] != byte(AddrIPv6) {
		t.Errorf("expected IPv6 ATYP, got %d", resp[3])
	}
}

func TestSendReply_VariousReplyCodes(t *testing.T) {
	codes := []Reply{
		ReplyGeneralFailure,
		ReplyNotAllowed,
		ReplyNetUnreachable,
		ReplyHostUnreachable,
		ReplyConnRefused,
		ReplyTTLExpired,
		ReplyCmdNotSupported,
		ReplyAddrNotSupport,
	}
	for _, code := range codes {
		var buf bytes.Buffer
		err := SendReply(&buf, code, "0.0.0.0", 0)
		if err != nil {
			t.Errorf("unexpected error for reply %d: %v", code, err)
		}
		resp := buf.Bytes()
		if resp[1] != byte(code) {
			t.Errorf("expected reply code %d, got %d", code, resp[1])
		}
	}
}

func TestSendReply_EmptyBindHost(t *testing.T) {
	var buf bytes.Buffer

	err := SendReply(&buf, ReplySuccess, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := buf.Bytes()
	if resp[3] != byte(AddrIPv4) {
		t.Errorf("expected IPv4 ATYP (0x01), got 0x%02x", resp[3])
	}
}

func TestSendReply_IPv4MappedInIPv6(t *testing.T) {

	var buf bytes.Buffer
	err := SendReply(&buf, ReplySuccess, "::ffff:192.0.2.1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := buf.Bytes()

	expectedLen := 4 + 4 + 2
	if len(resp) != expectedLen {
		t.Errorf("expected %d bytes (IPv4), got %d", expectedLen, len(resp))
	}
}

func TestCommand_String(t *testing.T) {
	tests := []struct {
		cmd      Command
		expected string
	}{
		{CommandConnect, "CONNECT"},
		{CommandBind, "BIND"},
		{CommandUDPAssociate, "UDP_ASSOCIATE"},
		{Command(0xFF), "UNKNOWN"},
		{Command(0x00), "UNKNOWN"},
	}

	for _, tc := range tests {
		got := tc.cmd.String()
		if got != tc.expected {
			t.Errorf("Command(%d).String() = %q, want %q", tc.cmd, got, tc.expected)
		}
	}
}

func TestFullNoAuthHandshake(t *testing.T) {

	type pipe struct {
		io.Reader
		io.Writer
	}

	serverBuf := new(bytes.Buffer)
	clientBuf := new(bytes.Buffer)

	clientBuf.Write([]byte{0x05, 0x01, 0x00})

	rw := struct {
		io.Reader
		io.Writer
	}{clientBuf, serverBuf}

	err := Handshake(rw, "", "")
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	resp := serverBuf.Bytes()
	if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
		t.Errorf("expected [0x05, 0x00], got %x", resp)
	}
}
