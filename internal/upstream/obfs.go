package upstream

// Built-in simple-obfs (SIP003) client: obfs-http / obfs-tls. The protocol is ported
// byte-for-byte from shadowsocks/simple-obfs (https://github.com/shadowsocks/simple-obfs),
// from obfs_http.c / obfs_tls.c (client-side obfs_request / deobfs_response).
//
// How it works (same as obfs-local, but no external binary needed):
//   - First write: obfs-http prepends an HTTP GET header before the first SS packet;
//     obfs-tls hides the first SS packet inside the session_ticket extension of a TLS ClientHello.
//   - Subsequent writes: obfs-http passes plaintext straight through; obfs-tls adds a 5-byte 0x17 frame header per packet.
//   - Read side: the first read strips the server's obfs response header (obfs-http looks
//     for \r\n\r\n; obfs-tls parses the ServerHello + CCS + EncryptedHandshake header), and obfs-tls then decodes 0x17 frames.
//
// This plugin only obfuscates TCP; SS UDP bypasses the plugin and is sent directly to the server port (see ssUDPAssociate).

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// obfsConfig is the result of one SIP003 plugin parse. Only the http/tls obfuscations
// of simple-obfs are supported; other plugin binaries (v2ray-plugin, etc.) are not built into SmartProxy and error at connect time.
type obfsConfig struct {
	id     string // plugin binary name, e.g. "obfs-local"
	obfs   string // "http" | "tls"
	host   string // obfs-host (HTTP Host / TLS SNI)
	port   int    // SS server port; the HTTP Host header carries it when not 80 (matching obfs-local)
	method string // http-method, default "GET" (http only)
	uri    string // obfs-uri, default "/" (http only)
}

// parsePluginOptions parses the SIP003 ?plugin= parameter value, in the format:
//
//	<binary>;key=value;key=value...
//
// In the values, \ ; = are backslash-escaped (ss-android PluginOptions export format).
// Unknown keys are ignored to tolerate TCP-level options like fast-open / mptcp.
func parsePluginOptions(s string) (*obfsConfig, error) {
	if s == "" {
		return nil, errors.New("empty plugin options")
	}
	parts, err := splitPluginOptions(s)
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("empty plugin options")
	}
	cfg := &obfsConfig{id: parts[0], method: "GET", uri: "/"}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "obfs":
			cfg.obfs = v
		case "obfs-host":
			cfg.host = v
		case "http-method":
			cfg.method = v
		case "obfs-uri":
			cfg.uri = v
		case "fast-open", "mptcp":
			// TCP-level option, ignored
		}
	}
	if cfg.id != "obfs-local" {
		return nil, fmt.Errorf("unsupported SIP003 plugin %q: SmartProxy only ships obfs-local (http/tls)", cfg.id)
	}
	if cfg.obfs != "http" && cfg.obfs != "tls" {
		return nil, fmt.Errorf("unsupported obfs type %q (want http or tls)", cfg.obfs)
	}
	return cfg, nil
}

// splitPluginOptions splits on unescaped ';' and handles backslash escapes.
func splitPluginOptions(s string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == ';':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	return parts, nil
}

// wrapObfs wraps a TCP connection already established to the remote SS server with the
// obfs transport layer and returns an obfuscated net.Conn. obfs-http builds its first/subsequent packets in plaintext; obfs-tls hides the first packet inside ClientHello.
func wrapObfs(conn net.Conn, cfg *obfsConfig) (net.Conn, error) {
	switch cfg.obfs {
	case "http":
		return &httpObfsConn{Conn: conn, host: cfg.host, port: cfg.port, method: cfg.method, uri: cfg.uri, needStrip: true}, nil
	case "tls":
		return &tlsObfsConn{Conn: conn, host: cfg.host}, nil
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported obfs type %q", cfg.obfs)
	}
}

// writeAll loops until the whole buf is written (handles short TCP writes).
func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

var crlfcrlf = []byte("\r\n\r\n")

// ---------------------------------------------------------------------------
// obfs-http
// ---------------------------------------------------------------------------

// httpObfsConn implements the obfs-http client transport:
//   - Write: the first write prepends an HTTP GET request header (Content-Length = first packet size; the server only strips at \r\n\r\n,
//     not at the Content-Length boundary), then passes plaintext straight through;
//   - Read: the first read buffers up to \r\n\r\n, strips the server's 101 response header, and returns the rest; subsequent reads pass through.
type httpObfsConn struct {
	net.Conn

	host   string
	port   int // remote SS port; the Host header omits the port when ==80
	method string
	uri    string

	sentHeader bool
	needStrip  bool   // server response header not yet stripped
	buf        []byte // cache of bytes before \r\n\r\n is found
	leftover   []byte // data remaining after stripping the response header
}

const maxObfsHTTPHeader = 64 * 1024

func (c *httpObfsConn) buildRequest(contentLength int) []byte {
	var b strings.Builder
	b.WriteString(c.method)
	b.WriteByte(' ')
	b.WriteString(c.uri)
	b.WriteString(" HTTP/1.1\r\n")
	if c.host == "" {
		b.WriteString("Host: cloudfront.net\r\n")
	} else if c.port != 80 {
		b.WriteString("Host: " + c.host + ":" + fmt.Sprint(c.port) + "\r\n")
	} else {
		b.WriteString("Host: " + c.host + "\r\n")
	}
	// User-Agent: curl/7.<major>.<minor>, major/minor randomized (matching simple-obfs)
	b.WriteString("User-Agent: curl/7." + fmt.Sprint(randIntN(51)) + "." + fmt.Sprint(randIntN(2)) + "\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	b.WriteString("Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n")
	b.WriteString("Content-Length: " + fmt.Sprint(contentLength) + "\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

func (c *httpObfsConn) Write(p []byte) (int, error) {
	if c.sentHeader {
		if err := writeAll(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.sentHeader = true
	hdr := c.buildRequest(len(p))
	buf := make([]byte, 0, len(hdr)+len(p))
	buf = append(buf, hdr...)
	buf = append(buf, p...)
	if err := writeAll(c.Conn, buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *httpObfsConn) Read(p []byte) (int, error) {
	if c.needStrip {
		// Read until the server's obfs response header (\r\n\r\n) is fully buffered, then
		// strip it and hand the trailing bytes (the relayed SS data) to the upper layer.
		for bytes.Index(c.buf, crlfcrlf) < 0 {
			if len(c.buf) > maxObfsHTTPHeader {
				return 0, errors.New("obfs-http: server response header too large")
			}
			tmp := make([]byte, 8192)
			m, err := c.Conn.Read(tmp)
			if m > 0 {
				c.buf = append(c.buf, tmp[:m]...)
			}
			if err != nil {
				return 0, fmt.Errorf("obfs-http: reading server response: %w", err)
			}
		}
		rest := c.buf[bytes.Index(c.buf, crlfcrlf)+4:]
		c.buf = nil
		c.needStrip = false
		n := copy(p, rest)
		c.leftover = append(c.leftover[:0], rest[n:]...)
		if n > 0 {
			// Return what we have immediately: never block trying to fill p. The relayed
			// data may be the whole response and the peer may keep the connection open
			// (HTTP keep-alive), so a fill-read would hang the caller.
			return n, nil
		}
		// The obfs response header arrived alone (no SS data in this read yet): fall
		// through to serve leftover or do a fresh read of the SS stream.
	}
	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// ---------------------------------------------------------------------------
// obfs-tls
// ---------------------------------------------------------------------------

// tlsObfsConn implements the obfs-tls client transport:
//   - Write: the first write builds a TLS ClientHello (first packet hidden in the session_ticket
//     extension); subsequent packets are prefixed with a 5-byte 0x17 0x03 0x03 + uint16 len frame header;
//   - Read: the first read parses the fixed ServerHello (96B) + CCS (6B) + EncryptedHandshake
//     header (5B, len = first chunk size), then decodes 0x17 frames.
type tlsObfsConn struct {
	net.Conn
	host string

	sentHello bool

	// read-side state machine
	state    tlsReadState
	hdr      []byte // accumulates the fixed-length header currently being read
	msgLen   int    // length of the first data chunk (EncryptedHandshake.len)
	frameLen int    // payload length of the current 0x17 frame
	out      []byte // decoded frames pending delivery to the upper layer
}

type tlsReadState int

const (
	tlsStateHello      tlsReadState = iota // 96B ServerHello
	tlsStateCCS                            // 6B ChangeCipherSpec
	tlsStateEncHeader                      // 5B EncryptedHandshake header
	tlsStateFirstChunk                     // msgLen-byte first chunk (plaintext passthrough)
	tlsStateFrame                          // 0x17 frame
)

// simple-obfs template bytes (extracted byte-by-byte from the C source, see obfs_tls.c).
var tlsCipherSuites = []byte{
	0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
	0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
	0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
	0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
}

// tlsOthersExt = ec_point_formats + elliptic_curves + sig_algos + etm + ems,
// 66 bytes total, in the same order as simple-obfs' tls_ext_others_template.
var tlsOthersExt = []byte{
	0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02,
	0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
	0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
	0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
	0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
	0x00, 0x16, 0x00, 0x00,
	0x00, 0x17, 0x00, 0x00,
}

const (
	tlsHelloLen    = 138 // sizeof(struct tls_client_hello)
	tlsSNILen      = 9   // sizeof(struct tls_ext_server_name)
	tlsTicketLen   = 4   // sizeof(struct tls_ext_session_ticket)
	tlsOthersLen   = 66  // sizeof(struct tls_ext_others)
	tlsServerHello = 96  // sizeof(struct tls_server_hello)
	tlsCCSLen      = 6   // sizeof(struct tls_change_cipher_spec)
	tlsEncHeader   = 5   // sizeof(struct tls_encrypted_handshake)
	tlsMaxFrame    = 16384
)

// clientHello builds the obfs-tls TLS ClientHello (byte-identical to simple-obfs'
// obfs_tls_request): the first packet firstChunk is hidden in the session_ticket extension, and SNI carries host.
func (c *tlsObfsConn) clientHello(firstChunk []byte) []byte {
	host := c.host
	if host == "" {
		host = "cloudfront.net"
	}
	hostLen := len(host)
	bufLen := len(firstChunk)
	tlsLen := bufLen + tlsHelloLen + tlsSNILen + hostLen + tlsTicketLen + tlsOthersLen

	b := make([]byte, tlsLen)
	pos := 0

	// record header: content_type 0x16, version 0x0301, len = tlsLen-5
	b[pos] = 0x16
	b[pos+1] = 0x03
	b[pos+2] = 0x01
	binary.BigEndian.PutUint16(b[pos+3:], uint16(tlsLen-5))
	pos += 5
	// handshake header: type 0x01, 3-byte length = tlsLen-9
	b[pos] = 0x01
	binary.BigEndian.PutUint16(b[pos+2:], uint16(tlsLen-9))
	pos += 4
	// handshake version 0x0303
	b[pos], b[pos+1] = 0x03, 0x03
	pos += 2
	// random: unix time + 28 random bytes
	binary.BigEndian.PutUint32(b[pos:], uint32(time.Now().Unix()))
	pos += 4
	_, _ = rand.Read(b[pos : pos+28])
	pos += 28
	// session_id: 32 random bytes
	b[pos] = 32
	pos += 1
	_, _ = rand.Read(b[pos : pos+32])
	pos += 32
	// cipher_suites: 56 fixed bytes
	binary.BigEndian.PutUint16(b[pos:], uint16(len(tlsCipherSuites)))
	pos += 2
	copy(b[pos:], tlsCipherSuites)
	pos += len(tlsCipherSuites)
	// comp_methods: 1 byte 0x00
	b[pos] = 1
	pos += 1
	b[pos] = 0x00
	pos += 1
	// ext_len = ticket(4+bufLen) + SNI(9+hostLen) + others(66)
	extLen := tlsTicketLen + bufLen + tlsSNILen + hostLen + tlsOthersLen
	binary.BigEndian.PutUint16(b[pos:], uint16(extLen))
	pos += 2

	// session_ticket extension: type 0x0023, len=bufLen, data = first packet
	binary.BigEndian.PutUint16(b[pos:], 0x0023)
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(bufLen))
	pos += 2
	copy(b[pos:], firstChunk)
	pos += bufLen

	// SNI extension: type 0x0000, ext_len=hostLen+5, list_len=hostLen+3, type 0, name_len=hostLen
	binary.BigEndian.PutUint16(b[pos:], 0x0000)
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen+3+2))
	pos += 2
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen+3))
	pos += 2
	b[pos] = 0x00
	pos += 1
	binary.BigEndian.PutUint16(b[pos:], uint16(hostLen))
	pos += 2
	copy(b[pos:], host)
	pos += hostLen

	// remaining extensions (fixed 66 bytes)
	copy(b[pos:], tlsOthersExt)
	return b
}

func (c *tlsObfsConn) Write(p []byte) (int, error) {
	if !c.sentHello {
		c.sentHello = true
		if err := writeAll(c.Conn, c.clientHello(p)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	// subsequent data is split into 0x17 frames of ≤16384 bytes (matching simple-obfs' obfs_app_data)
	orig := len(p)
	for len(p) > 0 {
		chunk := len(p)
		if chunk > tlsMaxFrame {
			chunk = tlsMaxFrame
		}
		frame := make([]byte, 5+chunk)
		frame[0], frame[1], frame[2] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(frame[3:5], uint16(chunk))
		copy(frame[5:], p[:chunk])
		if err := writeAll(c.Conn, frame); err != nil {
			return 0, err
		}
		p = p[chunk:]
	}
	return orig, nil
}

// Read decodes the server's obfs response into frames and returns SS plaintext data.
func (c *tlsObfsConn) Read(p []byte) (int, error) {
	for {
		if len(c.out) > 0 {
			n := copy(p, c.out)
			c.out = c.out[n:]
			return n, nil
		}
		tmp := make([]byte, 16384)
		n, err := c.Conn.Read(tmp)
		if n > 0 {
			if ferr := c.feed(tmp[:n]); ferr != nil {
				return 0, ferr
			}
		}
		if err != nil {
			if len(c.out) > 0 {
				n := copy(p, c.out)
				c.out = c.out[n:]
				return n, nil
			}
			return 0, err
		}
	}
}

// feed feeds raw bytes into the read-side state machine and appends the decoded data to c.out.
func (c *tlsObfsConn) feed(b []byte) error {
	i := 0
	for i < len(b) {
		switch c.state {
		case tlsStateHello:
			need := tlsServerHello - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsServerHello {
				if c.hdr[0] != 0x16 {
					return errors.New("obfs-tls: bad server hello content type")
				}
				c.hdr = nil
				c.state = tlsStateCCS
			}
		case tlsStateCCS:
			need := tlsCCSLen - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsCCSLen {
				c.hdr = nil
				c.state = tlsStateEncHeader
			}
		case tlsStateEncHeader:
			need := tlsEncHeader - len(c.hdr)
			take := minInt(need, len(b)-i)
			c.hdr = append(c.hdr, b[i:i+take]...)
			i += take
			if len(c.hdr) == tlsEncHeader {
				c.msgLen = int(binary.BigEndian.Uint16(c.hdr[3:5]))
				c.hdr = nil
				if c.msgLen > 0 {
					c.state = tlsStateFirstChunk
				} else {
					c.state = tlsStateFrame
				}
			}
		case tlsStateFirstChunk:
			take := minInt(c.msgLen, len(b)-i)
			c.out = append(c.out, b[i:i+take]...)
			c.msgLen -= take
			i += take
			if c.msgLen == 0 {
				c.state = tlsStateFrame
			}
		case tlsStateFrame:
			if c.frameLen == 0 {
				need := 5 - len(c.hdr)
				take := minInt(need, len(b)-i)
				c.hdr = append(c.hdr, b[i:i+take]...)
				i += take
				if len(c.hdr) == 5 {
					if c.hdr[0] != 0x17 {
						return errors.New("obfs-tls: bad app data frame header")
					}
					c.frameLen = int(binary.BigEndian.Uint16(c.hdr[3:5]))
					c.hdr = nil
					if c.frameLen > tlsMaxFrame {
						return errors.New("obfs-tls: frame too large")
					}
				}
			} else {
				take := minInt(c.frameLen, len(b)-i)
				c.out = append(c.out, b[i:i+take]...)
				c.frameLen -= take
				i += take
			}
		}
	}
	return nil
}

// randIntN returns a random number in [0,n) (only used to fake the User-Agent version, no cryptographic randomness needed).
func randIntN(n int) int {
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := int(binary.LittleEndian.Uint64(b[:]))
	if v < 0 {
		v = -v
	}
	return v % n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
