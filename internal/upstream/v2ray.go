package upstream

// Built-in v2ray-plugin / xray-plugin (SIP003) client. Protocol aligned item by item
// with the Android version of teddysun/v2ray-plugin (https://github.com/teddysun/v2ray-plugin),
// all 5 transport modes:
//
//	websocket-http   -- mode=websocket, no tls
//	websocket-tls    -- mode=websocket, with tls
//	quic-tls         -- mode=quic (quic forces TLS)
//	grpc             -- mode=grpc, no tls
//	grpc-tls         -- mode=grpc, with tls
//
// The implementation directly reuses v2ray-core's transport layer (same as v2ray-plugin):
// websocket/grpc/quic each use internet.Dial to establish a transport connection to the
// SS server, then run the SS encryption layer on top.
// One key protocol fact (the behavior of v2ray-plugin generateConfig):
//
//   - websocket + mux != 0: the server-side dokodemo target is set to v1.mux.cool, and the
//     connection must use the v2ray mux (SMux variant) frame protocol -- the client creates
//     one mux session per SS TCP connection over a dedicated transport connection
//     (frame format per common/mux, verified against a real v2ray-plugin server);
//   - grpc / quic / websocket with mux=0: the server-side dokodemo target stays 127.0.0.1,
//     and the connection carries the raw SS byte stream directly, without mux frames.
//
// SS UDP does not go through the plugin (SIP003 semantics); ssUDPAssociate connects
// directly to the server's UDP port, see ss.go.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/v2fly/v2ray-core/v5/common/environment"
	"github.com/v2fly/v2ray-core/v5/common/environment/deferredpersistentstorage"
	"github.com/v2fly/v2ray-core/v5/common/environment/envctx"
	"github.com/v2fly/v2ray-core/v5/common/environment/filesystemimpl"
	"github.com/v2fly/v2ray-core/v5/common/environment/systemnetworkimpl"
	"github.com/v2fly/v2ray-core/v5/common/environment/transientstorageimpl"
	vnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc"
	"github.com/v2fly/v2ray-core/v5/transport/internet/quic"
	tlsv2 "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/websocket"

	"smartproxy/internal/fwmark"
)

// v2rayPluginConfig is the parse result of one v2ray-plugin/xray-plugin SIP003 plugin.
// Field semantics match teddysun/v2ray-plugin's startup arguments (see the flag defaults
// in its main.go).
type v2rayPluginConfig struct {
	id          string // plugin binary name: "v2ray-plugin" | "xray-plugin"
	mode        string // "websocket" | "grpc" | "quic" (default websocket)
	tls         bool   // whether TLS is enabled; forced true in quic mode
	host        string // websocket Host header / TLS SNI, default "cloudfront.com"
	path        string // websocket path, default "/"
	mux         int    // websocket mux concurrency; 0 disables mux (default 1)
	serviceName string // grpc service name, default "GunService"
	certRaw     string // client certificate pinning (certRaw), empty means no pinning
}

// parseV2rayPluginOptions parses v2ray-plugin's ?plugin= parameter value; the format
// is the same as obfs:
//
//	<binary>;key=value;key=value...   (a bare key such as tls means enabled)
//
// Unknown keys are ignored (for compatibility with platform options such as
// fast-open / mptcp / __android_vpn).
func parseV2rayPluginOptions(s string) (*v2rayPluginConfig, error) {
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
	cfg := &v2rayPluginConfig{
		id:          parts[0],
		mode:        "websocket",
		host:        "cloudfront.com",
		path:        "/",
		mux:         1,
		serviceName: "GunService",
	}
	for _, kv := range parts[1:] {
		k, v, hasVal := strings.Cut(kv, "=")
		switch k {
		case "mode":
			if hasVal {
				cfg.mode = v
			}
		case "tls":
			// a bare key (or tls=1) both enable; consistent with v2ray-plugin's opts.Get("tls")
			cfg.tls = true
		case "host":
			if hasVal {
				cfg.host = v
			}
		case "path":
			if hasVal {
				cfg.path = v
			}
		case "mux":
			// on parse failure keep the default 1 (same fallback as v2ray-plugin on Atoi failure)
			if hasVal {
				if n, aerr := strconv.Atoi(v); aerr == nil {
					cfg.mux = n
				}
			}
		case "serviceName":
			if hasVal {
				cfg.serviceName = v
			}
		case "certRaw":
			if hasVal {
				cfg.certRaw = v
			}
		case "fast-open", "mptcp", "__android_vpn":
			// TCP-layer / platform options, ignored
		}
	}
	if cfg.id != "v2ray-plugin" && cfg.id != "xray-plugin" {
		return nil, fmt.Errorf("unsupported SIP003 plugin %q (want v2ray-plugin or xray-plugin)", cfg.id)
	}
	switch cfg.mode {
	case "websocket", "grpc", "quic":
	default:
		return nil, fmt.Errorf("unsupported v2ray-plugin mode %q (want websocket, grpc or quic)", cfg.mode)
	}
	return cfg, nil
}

// normalizeV2rayCertRaw converts the certRaw in an ss:// link into a full PEM
// certificate (for client pinning, matching v2ray-plugin's readCertificate). It
// accepts three forms:
//   - already a full PEM (with BEGIN/END lines) -- returned as-is;
//   - a base64-encoded full PEM -- decoded and returned (ss-android export often
//     base64-encodes the whole thing);
//   - a bare PEM body (no BEGIN/END lines) -- BEGIN/END lines added per v2ray-plugin.
func normalizeV2rayCertRaw(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "-----BEGIN CERTIFICATE-----") {
		return raw
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, derr := enc.DecodeString(raw); derr == nil {
			s := string(decoded)
			if strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
				return s
			}
			break
		}
	}
	return "-----BEGIN CERTIFICATE-----\n" + raw + "\n-----END CERTIFICATE-----"
}

// v2rayPlugin parses the v2ray-plugin/xray-plugin plugin parameters of this ss
// upstream; returns (nil, nil) if not configured or not a v2ray plugin.
func (p *Proxy) v2rayPlugin() (*v2rayPluginConfig, error) {
	kind, err := p.ssPluginKind()
	if err != nil {
		return nil, err
	}
	if kind != "v2ray-plugin" && kind != "xray-plugin" {
		return nil, nil
	}
	cfg, err := parseV2rayPluginOptions(p.Plugin)
	if err != nil {
		return nil, fmt.Errorf("ss proxy %q: %w", MaskProxyURL(p.URL), err)
	}
	return cfg, nil
}

// dialV2ray establishes a v2ray transport connection to the SS server:
//   - websocket + mux!=0: returns a mux session stream (net.Conn); the SS encryption
//     layer writes on it get wrapped into mux frames; each SS TCP connection owns a
//     dedicated transport connection (equivalent to v2ray-plugin client with mux=1,
//     no cross-connection multiplexing, correctness first);
//   - other modes (grpc/quic/websocket with mux=0): returns the transport connection
//     itself; the raw SS bytes pass straight through.
func (p *Proxy) dialV2ray(ctx context.Context, cfg *v2rayPluginConfig) (net.Conn, error) {
	conn, err := dialV2rayTransport(ctx, cfg, p.Host, p.Port)
	if err != nil {
		return nil, fmt.Errorf("v2ray-plugin dial to %s: %w", MaskProxyURL(p.URL), err)
	}
	if cfg.mode == "websocket" && cfg.mux != 0 {
		return &v2rayMuxStream{conn: conn, id: 1}, nil
	}
	return conn, nil
}

// dialV2rayTransport uses v2ray-core's transport layer to establish a transport
// connection to serverHost:serverPort. The transport config matches v2ray-plugin's
// generateConfig item by item (websocket carries the Host header, quic forces TLS,
// grpc uses serviceName); with TLS enabled SNI=host, and with certRaw it pins via
// AUTHORITY_VERIFY. When fwmark is enabled, SO_MARK is propagated to the transport
// socket (consistent with p.dial).
func dialV2rayTransport(ctx context.Context, cfg *v2rayPluginConfig, serverHost string, serverPort int) (net.Conn, error) {
	var ts proto.Message
	protocolName := cfg.mode
	switch cfg.mode {
	case "websocket":
		ts = &websocket.Config{
			Path:   cfg.path,
			Header: []*websocket.Header{{Key: "Host", Value: cfg.host}},
		}
	case "grpc":
		// the grpc transport is registered as "gun" in v2ray-core; it also needs a
		// TransportEnvironment to read TransientStorage, otherwise dial will panic.
		protocolName = "gun"
		ts = &grpc.Config{ServiceName: cfg.serviceName}
		ctx = withV2rayTransportEnv(ctx)
	case "quic":
		ts = &quic.Config{Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE}}
		cfg.tls = true // quic forces TLS
	default:
		return nil, fmt.Errorf("unsupported v2ray-plugin mode %q", cfg.mode)
	}

	streamCfg := &internet.StreamConfig{
		ProtocolName: protocolName,
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: cfg.mode,
			Settings:     serial.ToTypedMessage(ts),
		}},
	}
	if fwmark.Enabled() {
		streamCfg.SocketSettings = &internet.SocketConfig{Mark: uint32(fwmark.Mark())}
	}
	if cfg.tls {
		tlsCfg := &tlsv2.Config{ServerName: cfg.host}
		if cfg.certRaw != "" {
			// consistent with the v2ray-plugin client: certs use AUTHORITY_VERIFY and
			// must be a full PEM (loadSelfCertPool goes through AppendCertsFromPEM).
			certificate := tlsv2.Certificate{Usage: tlsv2.Certificate_AUTHORITY_VERIFY}
			certificate.Certificate = []byte(normalizeV2rayCertRaw(cfg.certRaw))
			tlsCfg.Certificate = []*tlsv2.Certificate{&certificate}
		}
		streamCfg.SecurityType = serial.GetMessageType(tlsCfg)
		streamCfg.SecuritySettings = []*anypb.Any{serial.ToTypedMessage(tlsCfg)}
	}

	mss, err := internet.ToMemoryStreamConfig(streamCfg)
	if err != nil {
		return nil, err
	}
	dest := vnet.TCPDestination(vnet.ParseAddress(serverHost), vnet.Port(serverPort))
	conn, err := internet.Dial(ctx, dest, mss)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// withV2rayTransportEnv returns a ctx carrying a minimal TransportEnvironment; the
// grpc transport dialer needs it to read TransientStorage (missing it panics, see
// grpc/dial.go).
func withV2rayTransportEnv(ctx context.Context) context.Context {
	netImpl := systemnetworkimpl.NewSystemNetworkDefault()
	rootEnv := environment.NewRootEnvImpl(ctx,
		transientstorageimpl.NewScopedTransientStorageImpl(),
		netImpl.Dialer(),
		netImpl.Listener(),
		filesystemimpl.NewDefaultFileSystemDefaultImpl(),
		deferredpersistentstorage.NewDeferredPersistentStorage(ctx))
	proxyEnv := rootEnv.ProxyEnvironment("v2ray-plugin")
	transportEnv, err := proxyEnv.NarrowScopeToTransport("t")
	if err != nil {
		// environment construction is a purely in-memory operation; failure is an
		// impossible path, still return ctx as a fallback (grpc dial will error)
		return ctx
	}
	return envctx.ContextWithEnvironment(ctx, transportEnv)
}

// ---------------------------------------------------------------------------
// v2ray mux frame protocol (SMux variant of common/mux, frame format aligned byte
// by byte):
//
//	[2-byte meta_len BE][meta bytes][2-byte payload_len BE][payload]
//	meta: [2-byte session id][1-byte status][1-byte option]
//	      status: 0x01 New / 0x02 Keep / 0x03 End / 0x04 KeepAlive
//	      option: 0x01 Data / 0x02 Error
//	      New appends: [1-byte network=0x01 TCP][2-byte port BE][addr: type+value]
//	                   addr type: 0x01 IPv4 / 0x02 Domain / 0x03 IPv6 (port before addr)
// ---------------------------------------------------------------------------

const (
	v2rayStatusNew       = 0x01
	v2rayStatusKeep      = 0x02
	v2rayStatusEnd       = 0x03
	v2rayStatusKeepAlive = 0x04
	v2rayOptData         = 0x01
	v2rayOptError        = 0x02
	v2rayNetTCP          = 0x01
	v2rayAddrIPv4        = 0x01
	v2rayAddrDomain      = 0x02
	v2rayAddrIPv6        = 0x03

	// the v2ray client sets the fake target of a mux connection to v1.mux.cool:9527
	// (see mux/client.go); the server-side freedom outbound's DestinationOverride
	// overrides it to the SS server, so the target itself does not affect routing;
	// keep consistent with the real client.
	v2rayMuxTargetHost = "v1.mux.cool"
	v2rayMuxTargetPort = 9527

	// single-frame payload cap (uint16); chunk size chosen as 32KB, under the cap and
	// reduces frame header overhead.
	v2rayMuxChunk = 32 * 1024
)

// writeV2rayFrame writes one mux frame. When status=New, the target is encoded in
// the frame (port first, then addr type+value); other frames carry only
// session/status/option.
func writeV2rayFrame(w io.Writer, sessionID uint16, status byte, opt byte, targetHost string, targetPort int, payload []byte) error {
	var meta []byte
	if status == v2rayStatusNew {
		meta = make([]byte, 4, 20)
		meta[0] = v2rayNetTCP
		binary.BigEndian.PutUint16(meta[1:3], uint16(targetPort))
		if ip := net.ParseIP(targetHost); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				meta[3] = v2rayAddrIPv4
				meta = append(meta, ip4...)
			} else {
				meta[3] = v2rayAddrIPv6
				meta = append(meta, ip.To16()...)
			}
		} else {
			meta[3] = v2rayAddrDomain
			meta = append(meta, byte(len(targetHost)))
			meta = append(meta, targetHost...)
		}
	} else {
		meta = make([]byte, 0, 4)
	}
	hdr := []byte{byte(sessionID >> 8), byte(sessionID), status, opt}
	meta = append(hdr, meta...)

	buf := make([]byte, 0, 2+len(meta)+2+len(payload))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(meta)))
	buf = append(buf, meta...)
	if opt&v2rayOptData != 0 {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload)))
		buf = append(buf, payload...)
	}
	// a single Write atomically sends the whole frame (one websocket Write is one
	// binary message and cannot be split).
	_, err := w.Write(buf)
	return err
}

// readV2rayFrame reads one mux frame, returning the session id, status, option and
// payload. For New/Keep/End only the first 4 meta bytes (session/status/option) are
// parsed; payload is read only on Data. The server never sends us New frames, so the
// address part is not parsed.
func readV2rayFrame(r io.Reader) (sessionID uint16, status byte, opt byte, payload []byte, err error) {
	var lenBuf [2]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, 0, 0, nil, err
	}
	metaLen := binary.BigEndian.Uint16(lenBuf[:])
	if metaLen > 512 {
		return 0, 0, 0, nil, fmt.Errorf("v2ray mux: invalid meta len %d", metaLen)
	}
	meta := make([]byte, metaLen)
	if _, err = io.ReadFull(r, meta); err != nil {
		return 0, 0, 0, nil, err
	}
	sessionID = binary.BigEndian.Uint16(meta[0:2])
	status = meta[2]
	opt = meta[3]
	if opt&v2rayOptData != 0 {
		var plen [2]byte
		if _, err = io.ReadFull(r, plen[:]); err != nil {
			return 0, 0, 0, nil, err
		}
		pl := binary.BigEndian.Uint16(plen[:])
		payload = make([]byte, pl)
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, 0, 0, nil, err
		}
	}
	return sessionID, status, opt, payload, nil
}

// v2rayMuxStream implements one mux session (net.Conn): data from the SS encryption
// layer is wrapped into New (first write) / Keep (subsequent) frames sent over the
// transport connection; the read side decodes Data frames for this session and
// returns io.EOF after an End frame. Each stream owns a dedicated transport
// connection; reads and writes can run concurrently (gorilla websocket allows it).
type v2rayMuxStream struct {
	conn net.Conn
	id   uint16

	wr      sync.Mutex // serializes frame writes (incl. first-write New / End on close)
	sentNew bool
	closed  bool

	rd      sync.Mutex // serializes frame reads
	pending []byte     // payload left over from the previous frame
	eof     bool       // an End frame has been received
}

func (s *v2rayMuxStream) Write(p []byte) (int, error) {
	s.wr.Lock()
	defer s.wr.Unlock()
	if s.closed {
		return 0, net.ErrClosed
	}
	orig := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > v2rayMuxChunk {
			chunk = p[:v2rayMuxChunk]
		}
		status := byte(v2rayStatusKeep)
		if !s.sentNew {
			s.sentNew = true
			status = v2rayStatusNew
		}
		if err := writeV2rayFrame(s.conn, s.id, status, v2rayOptData, v2rayMuxTargetHost, v2rayMuxTargetPort, chunk); err != nil {
			return 0, err
		}
		p = p[len(chunk):]
	}
	return orig, nil
}

func (s *v2rayMuxStream) Read(p []byte) (int, error) {
	s.rd.Lock()
	defer s.rd.Unlock()
	for {
		if len(s.pending) > 0 {
			n := copy(p, s.pending)
			s.pending = s.pending[n:]
			return n, nil
		}
		if s.eof {
			return 0, io.EOF
		}
		_, status, opt, payload, err := readV2rayFrame(s.conn)
		if err != nil {
			return 0, err
		}
		if status == v2rayStatusEnd {
			s.eof = true
		}
		if opt&v2rayOptData != 0 && len(payload) > 0 {
			n := copy(p, payload)
			s.pending = append(s.pending[:0], payload[n:]...)
			return n, nil
		}
		if s.eof {
			return 0, io.EOF
		}
		// KeepAlive (0x04) / Keep with no data: ignore and keep waiting for a data frame
	}
}

func (s *v2rayMuxStream) Close() error {
	s.wr.Lock()
	defer s.wr.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.sentNew {
		// politely send End first so the server closes the session, then close the
		// transport connection (losing End is also safe: the server cleans up the
		// session on transport EOF as well).
		_ = writeV2rayFrame(s.conn, s.id, v2rayStatusEnd, 0, "", 0, nil)
	}
	return s.conn.Close()
}

func (s *v2rayMuxStream) LocalAddr() net.Addr                { return s.conn.LocalAddr() }
func (s *v2rayMuxStream) RemoteAddr() net.Addr               { return s.conn.RemoteAddr() }
func (s *v2rayMuxStream) SetDeadline(t time.Time) error      { return s.conn.SetDeadline(t) }
func (s *v2rayMuxStream) SetReadDeadline(t time.Time) error  { return s.conn.SetReadDeadline(t) }
func (s *v2rayMuxStream) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }
