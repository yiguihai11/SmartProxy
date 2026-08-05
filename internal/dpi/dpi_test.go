package dpi

import (
	"encoding/binary"
	"testing"
)

func buildTLSClientHello(sni string) []byte {

	sniBytes := []byte(sni)

	sniPayload := make([]byte, 2+2+1+2+len(sniBytes))
	binary.BigEndian.PutUint16(sniPayload[0:2], uint16(1+2+len(sniBytes)))
	sniPayload[2] = 0x00
	binary.BigEndian.PutUint16(sniPayload[3:5], uint16(len(sniBytes)))
	copy(sniPayload[5:], sniBytes)

	ext := make([]byte, 4+len(sniPayload))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sniPayload)))
	copy(ext[4:], sniPayload)

	body := make([]byte, 2+32+1+0+2+2+1+1+2+len(ext))
	binary.BigEndian.PutUint16(body[0:2], 0x0303)

	body[34] = 0x00
	binary.BigEndian.PutUint16(body[35:37], 2)
	binary.BigEndian.PutUint16(body[37:39], 0x002F)
	body[39] = 0x01
	body[40] = 0x00
	binary.BigEndian.PutUint16(body[41:43], uint16(len(ext)))
	copy(body[43:], ext)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	length24 := make([]byte, 4)
	binary.BigEndian.PutUint32(length24, uint32(len(body)))
	copy(handshake[1:4], length24[1:4])
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:3], 0x0303)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record
}

func TestExtractSNI_Valid(t *testing.T) {
	tests := []string{
		"example.com",
		"www.google.com",
		"api.github.com",
		"test.example.co.uk",
	}
	for _, sni := range tests {
		payload := buildTLSClientHello(sni)
		got := ExtractSNI(payload)
		if got != sni {
			t.Errorf("ExtractSNI(%q) = %q, want %q", sni, got, sni)
		}
	}
}

func TestExtractSNI_Empty(t *testing.T) {
	if got := ExtractSNI(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
	if got := ExtractSNI([]byte{}); got != "" {
		t.Errorf("expected empty for empty, got %q", got)
	}
}

func TestExtractSNI_TooShort(t *testing.T) {
	if got := ExtractSNI([]byte{0x16, 0x03}); got != "" {
		t.Errorf("expected empty for short data, got %q", got)
	}
}

func TestExtractSNI_NotTLS(t *testing.T) {

	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x00}
	if got := ExtractSNI(payload); got != "" {
		t.Errorf("expected empty for non-TLS, got %q", got)
	}
}

func TestExtractSNI_RecordLengthExceedsPayload(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x03, 0xFF, 0xFF}
	if got := ExtractSNI(payload); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractSNI_NotClientHello(t *testing.T) {

	body := make([]byte, 38)
	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x02
	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:3], 0x0303)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	if got := ExtractSNI(record); got != "" {
		t.Errorf("expected empty for ServerHello, got %q", got)
	}
}

func TestExtractSNI_MalformedInput(t *testing.T) {

	tests := [][]byte{
		{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0xFF, 0xFF},
		{0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00},
		make([]byte, 100),
	}
	for i, payload := range tests {
		got := ExtractSNI(payload)
		if got != "" {
			t.Errorf("test %d: expected empty for malformed, got %q", i, got)
		}
	}
}

func TestExtractSNI_NoExtensions(t *testing.T) {

	body := make([]byte, 2+32+1+2+2+1+1+2)
	binary.BigEndian.PutUint16(body[0:2], 0x0303)
	body[34] = 0x00
	binary.BigEndian.PutUint16(body[35:37], 2)
	binary.BigEndian.PutUint16(body[37:39], 0x002F)
	body[39] = 0x01
	body[40] = 0x00
	binary.BigEndian.PutUint16(body[41:43], 0)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	length24 := make([]byte, 4)
	binary.BigEndian.PutUint32(length24, uint32(len(body)))
	copy(handshake[1:4], length24[1:4])
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:3], 0x0303)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	if got := ExtractSNI(record); got != "" {
		t.Errorf("expected empty when no extensions, got %q", got)
	}
}

func TestExtractSNI_SessionID(t *testing.T) {

	sni := "with-session.example.com"
	sniBytes := []byte(sni)
	payload := make([]byte, 2+2+1+2+len(sniBytes))
	binary.BigEndian.PutUint16(payload[0:2], uint16(1+2+len(sniBytes)))
	payload[2] = 0x00
	binary.BigEndian.PutUint16(payload[3:5], uint16(len(sniBytes)))
	copy(payload[5:], sniBytes)

	ext := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(payload)))
	copy(ext[4:], payload)

	sessionID := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	body := make([]byte, 2+32+1+len(sessionID)+2+2+1+1+2+len(ext))
	binary.BigEndian.PutUint16(body[0:2], 0x0303)
	body[34] = byte(len(sessionID))
	copy(body[35:], sessionID)
	pos := 35 + len(sessionID)
	binary.BigEndian.PutUint16(body[pos:pos+2], 2)
	binary.BigEndian.PutUint16(body[pos+2:pos+4], 0x002F)
	body[pos+4] = 0x01
	body[pos+5] = 0x00
	binary.BigEndian.PutUint16(body[pos+6:pos+8], uint16(len(ext)))
	copy(body[pos+8:], ext)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	length24 := make([]byte, 4)
	binary.BigEndian.PutUint32(length24, uint32(len(body)))
	copy(handshake[1:4], length24[1:4])
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	binary.BigEndian.PutUint16(record[1:3], 0x0303)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	got := ExtractSNI(record)
	if got != sni {
		t.Errorf("ExtractSNI with session_id = %q, want %q", got, sni)
	}
}

func TestExtractHTTPHost_AbsoluteURI(t *testing.T) {
	req := "GET http://example.com/path/to/resource HTTP/1.1\r\nHost: example.com\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "example.com" {
		t.Errorf("got %q, want example.com", got)
	}
}

func TestExtractHTTPHost_AbsoluteURIHttps(t *testing.T) {
	req := "CONNECT https://secure.example.com:443/ HTTP/1.1\r\nHost: secure.example.com\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "secure.example.com" {
		t.Errorf("got %q, want secure.example.com", got)
	}
}

func TestExtractHTTPHost_AbsoluteURIWithPort(t *testing.T) {
	req := "GET http://example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "example.com" {
		t.Errorf("got %q, want example.com (port stripped)", got)
	}
}

func TestExtractHTTPHost_HostHeader(t *testing.T) {
	req := "POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\nHost: api.example.com\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "api.example.com" {
		t.Errorf("got %q, want api.example.com", got)
	}
}

func TestExtractHTTPHost_HostHeaderWithPort(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: close\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "localhost" {
		t.Errorf("got %q, want localhost (port stripped)", got)
	}
}

func TestExtractHTTPHost_CaseInsensitive(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHOST: www.Example.COM\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "www.example.com" {
		t.Errorf("got %q, want www.example.com", got)
	}
}

func TestExtractHTTPHost_MultipleHeaders(t *testing.T) {
	req := "GET / HTTP/1.1\r\nUser-Agent: curl/7.0\r\nAccept: */*\r\nHost: target.example.com\r\nConnection: close\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "target.example.com" {
		t.Errorf("got %q, want target.example.com", got)
	}
}

func TestExtractHTTPHost_Empty(t *testing.T) {
	if got := ExtractHTTPHost(nil); got != "" {
		t.Errorf("expected empty for nil, got %q", got)
	}
	if got := ExtractHTTPHost([]byte{}); got != "" {
		t.Errorf("expected empty for empty, got %q", got)
	}
}

func TestExtractHTTPHost_NoHTTPData(t *testing.T) {
	if got := ExtractHTTPHost([]byte{0x16, 0x03, 0x03}); got != "" {
		t.Errorf("expected empty for non-HTTP data, got %q", got)
	}
}

func TestExtractHTTPHost_Malformed(t *testing.T) {
	tests := [][]byte{
		[]byte("NOT_HTTP_DATA\r\n\r\n"),
		[]byte("GET\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\n"),
		make([]byte, 5000),
	}
	for i, payload := range tests {
		got := ExtractHTTPHost(payload)
		if got != "" {
			t.Errorf("test %d: expected empty, got %q", i, got)
		}
	}
}

func TestExtractHTTPHost_RequestLineOnly(t *testing.T) {

	req := "GET http://direct.example.com/ HTTP/1.1\r\n\r\n"
	got := ExtractHTTPHost([]byte(req))
	if got != "direct.example.com" {
		t.Errorf("got %q, want direct.example.com", got)
	}
}
