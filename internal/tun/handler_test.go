package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"smartproxy/internal/config"
	"smartproxy/internal/dns"
	"smartproxy/internal/rules"
	"smartproxy/internal/upstream"
)

type MockRuleEngine struct {
	mock.Mock
}

func (m *MockRuleEngine) Load(path string) error {
	args := m.Called(path)
	return args.Error(0)
}
func (m *MockRuleEngine) Reload(path string) error {
	args := m.Called(path)
	return args.Error(0)
}
func (m *MockRuleEngine) IsPortBlocked(port int) bool {
	args := m.Called(port)
	return args.Bool(0)
}
func (m *MockRuleEngine) IsIPBlocked(ip string) bool {
	args := m.Called(ip)
	return args.Bool(0)
}
func (m *MockRuleEngine) IsDomainBlocked(domain string) bool {
	args := m.Called(domain)
	return args.Bool(0)
}
func (m *MockRuleEngine) MatchProxyRule(targetIP string, targetPort int, domain string) (alias string, matched bool) {
	args := m.Called(targetIP, targetPort, domain)
	return args.String(0), args.Bool(1)
}
func (m *MockRuleEngine) ProxyRules() []rules.ProxyRule {
	args := m.Called()
	return args.Get(0).([]rules.ProxyRule)
}

type MockRouter struct {
	mock.Mock
}

func (m *MockRouter) UpdateConfig(smartTimeout, blacklistTTL time.Duration) {
	m.Called(smartTimeout, blacklistTTL)
}
func (m *MockRouter) IsDomestic(ip string) bool {
	args := m.Called(ip)
	return args.Bool(0)
}
func (m *MockRouter) EstablishConnection(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, error) {
	args := m.Called(ctx, host, port, domain, engine)
	return args.Get(0).(net.Conn), args.Error(1)
}
func (m *MockRouter) SmartConnectWithFallback(ctx context.Context, host string, port int, domain string, firstPkt []byte, engine *rules.Engine) (net.Conn, error) {
	args := m.Called(ctx, host, port, domain, firstPkt, engine)
	return args.Get(0).(net.Conn), args.Error(1)
}
func (m *MockRouter) StartCleanup(interval time.Duration) {
	m.Called(interval)
}

type MockUpstreamManager struct {
	mock.Mock
}

func (m *MockUpstreamManager) Reload(cfg upstream.UpstreamConfig) {
	m.Called(cfg)
}
func (m *MockUpstreamManager) SelectProxy(targetIP string, targetPort int, domain string, engine *rules.Engine) (string, *upstream.Proxy) {
	args := m.Called(targetIP, targetPort, domain, engine)
	var proxy *upstream.Proxy
	if p, ok := args.Get(1).(*upstream.Proxy); ok {
		proxy = p
	}
	return args.String(0), proxy
}
func (m *MockUpstreamManager) ConnectDefault(ctx context.Context, host string, port int) (net.Conn, error) {
	args := m.Called(ctx, host, port)
	return args.Get(0).(net.Conn), args.Error(1)
}
func (m *MockUpstreamManager) Connect(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, string) {
	args := m.Called(ctx, host, port, domain, engine)
	conn, ok := args.Get(0).(net.Conn)
	if !ok {
		conn = nil
	}
	return conn, args.String(1)
}
func (m *MockUpstreamManager) UDPAssociate(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (*upstream.UDPProxyConn, error) {
	args := m.Called(ctx, host, port, domain, engine)
	return args.Get(0).(*upstream.UDPProxyConn), args.Error(1)
}

type MockDNSHandler struct {
	mock.Mock
}

func (m *MockDNSHandler) UpdateConfig(foreignIPv4, foreignIPv6 string, queryTimeout int, blockedIP, blockedIP6 string, enabled, preferEnabled bool, preferMode dns.PreferMode, preferPorts []int) {
	m.Called(foreignIPv4, foreignIPv6, queryTimeout, blockedIP, blockedIP6, enabled, preferEnabled, preferMode, preferPorts)
}
func (m *MockDNSHandler) Enabled() bool {
	args := m.Called()
	return args.Bool(0)
}
func (m *MockDNSHandler) IsDomestic(ip string) bool {
	args := m.Called(ip)
	return args.Bool(0)
}
func (m *MockDNSHandler) HandleDNS(ctx context.Context, queryWire []byte, targetIP string, targetPort int, engine *rules.Engine) []byte {
	args := m.Called(ctx, queryWire, targetIP, targetPort, engine)
	return args.Get(0).([]byte)
}
func (m *MockDNSHandler) BuildFakeResponse(queryWire []byte) []byte {
	args := m.Called(queryWire)
	return args.Get(0).([]byte)
}
func (m *MockDNSHandler) CacheGet(qname string, qtype uint16) []byte {
	args := m.Called(qname, qtype)
	return args.Get(0).([]byte)
}
func (m *MockDNSHandler) CacheSet(qname string, qtype uint16, wire []byte, ttl time.Duration) {
	m.Called(qname, qtype, wire, ttl)
}
func (m *MockDNSHandler) QueryUDP(ctx context.Context, queryWire []byte, host string, port int) ([]byte, error) {
	args := m.Called(ctx, queryWire, host, port)
	return args.Get(0).([]byte), args.Error(1)
}
func (m *MockDNSHandler) IsDNSClean(wire []byte) bool {
	args := m.Called(wire)
	return args.Bool(0)
}

type MockTun struct {
	mock.Mock
}

func (m *MockTun) Name() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockTun) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockTun) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockTun) UpdateRouteOptions(tunOptions singtun.Options) error {
	args := m.Called(tunOptions)
	return args.Error(0)
}

func (m *MockTun) Batch() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockTun) Read(p []byte) (int, error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockTun) Write(p []byte) (int, error) {
	args := m.Called(p)
	return args.Int(0), args.Error(1)
}

func (m *MockTun) LUID() string {
	args := m.Called()
	return args.String(0)
}

type MockStack struct {
	mock.Mock
}

func (m *MockStack) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockStack) Close() error {
	args := m.Called()
	return args.Error(0)
}

type MockNetConn struct {
	mock.Mock
	io.Reader
	io.Writer
}

func (m *MockNetConn) Read(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockNetConn) Write(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockNetConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockNetConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockNetConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockNetConn) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockNetConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockNetConn) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

type MockPacketConn struct {
	mock.Mock
}

func (m *MockPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	args := m.Called(buffer)
	return args.Get(0).(M.Socksaddr), args.Error(1)
}

func (m *MockPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	args := m.Called(buffer, destination)
	return args.Error(0)
}

func (m *MockPacketConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockPacketConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockPacketConn) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockPacketConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockPacketConn) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

type MockCloseHandlerFunc struct {
	mock.Mock
}

func (m *MockCloseHandlerFunc) Execute(err error) {
	m.Called(err)
}

func TestTUNHandler_Start(t *testing.T) {

	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockTun := new(MockTun)
	mockStack := new(MockStack)

	NewTUN = func(opts singtun.Options) (singtun.Tun, error) {
		assert.Equal(t, "test_tun", opts.Name)
		return mockTun, nil
	}
	NewTUNStack = func(stackType string, opts singtun.StackOptions) (singtun.Stack, error) {
		assert.Equal(t, "gvisor", stackType)
		assert.Equal(t, mockTun, opts.Tun)
		return mockStack, nil
	}

	cfg := &config.Config{
		TUN: config.TUNConfig{
			Enabled: true,
			Name:    "test_tun",
			MTU:     1500,
			Stack:   "gvisor",
		},
	}
	handler := NewHandler(cfg, nil, nil, nil, nil)

	mockTun.On("Name").Return("test_tun", nil)
	mockTun.On("Start").Return(nil)
	mockStack.On("Start").Return(nil)

	tunDev, tunStack, err := handler.Start(context.Background(), cfg.TUN)
	assert.NoError(t, err)
	assert.NotNil(t, tunDev)
	assert.NotNil(t, tunStack)

	mockTun.AssertExpectations(t)
	mockStack.AssertExpectations(t)
}

func TestNewHandler(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(cfg, nil, nil, nil, nil)
	assert.NotNil(t, h)
	assert.Equal(t, cfg, h.config.Load())
	assert.Nil(t, h.router)
	assert.Nil(t, h.ruleEng)
	assert.Nil(t, h.upstreamMgr)
	assert.Nil(t, h.dnsHandler)
}

func TestPrepareConnection(t *testing.T) {
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	dest, err := handler.PrepareConnection("tcp", M.Socksaddr{}, M.Socksaddr{}, nil, 0)
	assert.NoError(t, err)
	assert.Nil(t, dest)
}

func TestTUNHandler_Start_Disabled(t *testing.T) {
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	tunDev, tunStack, err := handler.Start(context.Background(), config.TUNConfig{Enabled: false})
	assert.NoError(t, err)
	assert.Nil(t, tunDev)
	assert.Nil(t, tunStack)
}

func TestTUNHandler_Start_FdMode_MTUDefault(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockTun := new(MockTun)
	mockStack := new(MockStack)

	NewTUN = func(opts singtun.Options) (singtun.Tun, error) {

		assert.Equal(t, uint32(1500), opts.MTU)
		assert.Equal(t, 42, opts.FileDescriptor)
		return mockTun, nil
	}
	NewTUNStack = func(stackType string, opts singtun.StackOptions) (singtun.Stack, error) {
		return mockStack, nil
	}

	mockTun.On("Name").Return("", nil)
	mockStack.On("Start").Return(nil)

	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	mockTun.On("Start").Return(nil)
	_, _, err := handler.Start(context.Background(), config.TUNConfig{
		Enabled:        true,
		FileDescriptor: 42,
		MTU:            0,
		Stack:          "gvisor",
	})
	assert.NoError(t, err)
	mockTun.AssertExpectations(t)
	mockStack.AssertExpectations(t)
}

func TestTUNHandler_Start_FdMode_NoAddresses(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockTun := new(MockTun)
	mockStack := new(MockStack)

	NewTUN = func(opts singtun.Options) (singtun.Tun, error) {

		assert.Empty(t, opts.Inet4Address)
		assert.Empty(t, opts.Inet6Address)
		return mockTun, nil
	}
	NewTUNStack = func(stackType string, opts singtun.StackOptions) (singtun.Stack, error) {
		return mockStack, nil
	}

	mockTun.On("Name").Return("", nil)
	mockStack.On("Start").Return(nil)

	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	mockTun.On("Start").Return(nil)
	_, _, err := handler.Start(context.Background(), config.TUNConfig{
		Enabled:        true,
		FileDescriptor: 42,
		MTU:            1500,
		Stack:          "gvisor",
	})
	assert.NoError(t, err)
}

func TestTUNHandler_Start_InvalidIPv4Prefix(t *testing.T) {
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	_, _, err := handler.Start(context.Background(), config.TUNConfig{
		Enabled:      true,
		Inet4Address: []string{"not-a-valid-prefix"},
		Stack:        "gvisor",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IPv4 prefix")
}

func TestTUNHandler_Start_InvalidIPv6Prefix(t *testing.T) {
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	_, _, err := handler.Start(context.Background(), config.TUNConfig{
		Enabled:      true,
		Inet6Address: []string{"xyz::/999"},
		Stack:        "gvisor",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IPv6 prefix")
}

func TestTUNHandler_Start_DefaultStack(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockTun := new(MockTun)
	mockStack := new(MockStack)

	NewTUN = func(opts singtun.Options) (singtun.Tun, error) {
		return mockTun, nil
	}
	NewTUNStack = func(stackType string, opts singtun.StackOptions) (singtun.Stack, error) {
		assert.Equal(t, "gvisor", stackType)
		return mockStack, nil
	}

	mockTun.On("Name").Return("test", nil)
	mockStack.On("Start").Return(nil)

	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)
	mockTun.On("Start").Return(nil)
	_, _, err := handler.Start(context.Background(), config.TUNConfig{
		Enabled: true,
		MTU:     1500,
		Stack:   "",
	})
	assert.NoError(t, err)
}

func TestTUNHandler_NewConnectionEx_NilDeps(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockNetConn)
	mockCloseHandler := new(MockCloseHandlerFunc)

	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)
	mockCloseHandler.On("Execute", mock.Anything).Once()

	src := M.Socksaddr{Addr: netip.MustParseAddr("192.168.1.1"), Port: 12345}
	dst := M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 80}

	assert.NotPanics(t, func() {
		handler.NewConnectionEx(context.Background(), mockConn, src, dst, mockCloseHandler.Execute)
	})

	mockConn.AssertExpectations(t)
	mockCloseHandler.AssertExpectations(t)
}

func TestTUNHandler_NewConnectionEx_NilDeps_OnCloseNil(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockNetConn)
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)

	src := M.Socksaddr{Addr: netip.MustParseAddr("192.168.1.1"), Port: 12345}
	dst := M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 80}

	assert.NotPanics(t, func() {
		handler.NewConnectionEx(context.Background(), mockConn, src, dst, nil)
	})
	mockConn.AssertExpectations(t)
}

func TestTUNHandler_NewPacketConnectionEx_NilDeps(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockPacketConn)
	mockCloseHandler := new(MockCloseHandlerFunc)

	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)
	mockCloseHandler.On("Execute", mock.Anything).Once()

	src := M.Socksaddr{Addr: netip.MustParseAddr("192.168.1.1"), Port: 12345}
	dst := M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 53}

	assert.NotPanics(t, func() {
		handler.NewPacketConnectionEx(context.Background(), mockConn, src, dst, mockCloseHandler.Execute)
	})

	mockConn.AssertExpectations(t)
	mockCloseHandler.AssertExpectations(t)
}

func TestTUNHandler_NewPacketConnectionEx_NilDeps_OnCloseNil(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockPacketConn)
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)

	src := M.Socksaddr{Addr: netip.MustParseAddr("192.168.1.1"), Port: 12345}
	dst := M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443}

	assert.NotPanics(t, func() {
		handler.NewPacketConnectionEx(context.Background(), mockConn, src, dst, nil)
	})
	mockConn.AssertExpectations(t)
}

func buildTLSClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	sniPayload := make([]byte, 2+1+2+sniLen)
	binary.BigEndian.PutUint16(sniPayload[0:2], uint16(1+2+sniLen))
	sniPayload[2] = 0x00
	binary.BigEndian.PutUint16(sniPayload[3:5], uint16(sniLen))
	copy(sniPayload[5:], sniBytes)

	ext := make([]byte, 2+2+len(sniPayload))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(sniPayload)))
	copy(ext[4:], sniPayload)

	handshake := make([]byte, 0, 2+32+1+2+2+1+1+2+len(ext))
	handshake = append(handshake, 0x03, 0x03)
	handshake = append(handshake, make([]byte, 32)...)
	handshake = append(handshake, 0x00)
	handshake = append(handshake, 0x00, 0x02)
	handshake = append(handshake, 0x00, 0x2f)
	handshake = append(handshake, 0x01, 0x00)
	handshake = append(handshake, byte(len(ext)>>8), byte(len(ext)))
	handshake = append(handshake, ext...)

	hsLen := len(handshake)
	hsRecord := make([]byte, 1+3+hsLen)
	hsRecord[0] = 0x01
	hsRecord[1] = byte(hsLen >> 16)
	hsRecord[2] = byte(hsLen >> 8)
	hsRecord[3] = byte(hsLen)
	copy(hsRecord[4:], handshake)

	tlsRecord := make([]byte, 5+len(hsRecord))
	tlsRecord[0] = 0x16
	tlsRecord[1] = 0x03
	tlsRecord[2] = 0x03
	binary.BigEndian.PutUint16(tlsRecord[3:5], uint16(len(hsRecord)))
	copy(tlsRecord[5:], hsRecord)

	return tlsRecord
}

func TestExtractDomain_SNI(t *testing.T) {
	tlsHello := buildTLSClientHello("www.example.com")
	assert.Equal(t, "www.example.com", ExtractDomain(tlsHello))
}

func TestExtractDomain_SNI_Uppercase(t *testing.T) {
	tlsHello := buildTLSClientHello("www.Example.COM")
	assert.Equal(t, "www.example.com", ExtractDomain(tlsHello))
}

func TestExtractDomain_HTTPHost(t *testing.T) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: test\r\n\r\n")
	assert.Equal(t, "api.example.com", ExtractDomain(httpReq))
}

func TestExtractDomain_HTTPHostWithPort(t *testing.T) {
	httpReq := []byte("GET / HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n")
	assert.Equal(t, "api.example.com", ExtractDomain(httpReq))
}

func TestExtractDomain_CONNECTMethod(t *testing.T) {
	httpReq := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	assert.Equal(t, "example.com", ExtractDomain(httpReq))
}

func TestExtractDomain_EmptyInput(t *testing.T) {
	assert.Equal(t, "", ExtractDomain(nil))
	assert.Equal(t, "", ExtractDomain([]byte{}))
}

func TestExtractDomain_RandomData(t *testing.T) {
	assert.Equal(t, "", ExtractDomain([]byte{0x00, 0x01, 0x02, 0x03}))
}

func TestExtractDomain_SNI_PreferredOverHTTP(t *testing.T) {

	tlsHello := buildTLSClientHello("secure.example.com")
	assert.Equal(t, "secure.example.com", ExtractDomain(tlsHello))
}

func TestExtractDomain_LongHostname(t *testing.T) {
	longHost := "a" + strings.Repeat("b", 40) + ".example.com"
	tlsHello := buildTLSClientHello(longHost)
	got := ExtractDomain(tlsHello)
	expected := strings.ToLower(longHost)
	assert.Equal(t, expected, got)
}

func TestTUNHandler_HandleDNS_NilDeps(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockPacketConn)
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)

	assert.NotPanics(t, func() {
		handler.handleDNS(context.Background(), mockConn, "8.8.8.8", 53)
	})
	mockConn.AssertExpectations(t)
}

func TestTUNHandler_HandleGenericUDP_NilDeps(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	mockConn := new(MockPacketConn)
	handler := NewHandler(&config.Config{}, nil, nil, nil, nil)

	mockConn.On("Close").Return(nil)

	assert.NotPanics(t, func() {
		handler.handleGenericUDP(context.Background(), mockConn,
			M.Socksaddr{Addr: netip.MustParseAddr("10.0.0.1"), Port: 12345},
			M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 443})
	})
	mockConn.AssertExpectations(t)
}

func TestReadClientHello_HTTP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	go func() {
		server.Write(req)
		server.Close()
	}()

	got, err := ReadClientHello(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, req) {
		t.Errorf("HTTP: got %q, want %q", got, req)
	}
	if cap(got) != len(got) {
		t.Errorf("HTTP: returned slice must be exact-size (len=%d cap=%d), caller owns it", len(got), cap(got))
	}
}

func TestReadClientHello_TLS_Small(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := bytes.Repeat([]byte{0xab}, 300)
	rec := make([]byte, 5+len(payload))
	rec[0] = 0x16 // TLS handshake record
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	go func() {
		server.Write(rec)
		server.Close()
	}()

	got, err := ReadClientHello(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rec) {
		t.Errorf("TLS small: got len=%d, want len=%d", len(got), len(rec))
	}
	if cap(got) != len(got) {
		t.Errorf("TLS small: returned slice must be exact-size")
	}
}

func TestReadClientHello_TLS_Large(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Record larger than the 4096-byte pooled buffer -> dedicated fallback path.
	payload := bytes.Repeat([]byte{0xcd}, 5000)
	rec := make([]byte, 5+len(payload))
	rec[0] = 0x16
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	go func() {
		server.Write(rec)
		server.Close()
	}()

	got, err := ReadClientHello(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, rec) {
		t.Errorf("TLS large: mismatch, got len=%d want len=%d", len(got), len(rec))
	}
}

func TestReadClientHello_ReturnedBufferIsCallerOwned(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req := []byte("POST /api HTTP/1.1\r\nHost: a.com\r\nContent-Length: 0\r\n\r\n")
	go func() {
		server.Write(req)
		server.Close()
	}()

	first, err := ReadClientHello(client, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// A second connection reuses the pooled buffer; the first result must survive.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()
	req2 := []byte("GET /other HTTP/1.1\r\nHost: b.com\r\n\r\n")
	go func() {
		server2.Write(req2)
		server2.Close()
	}()
	second, err := ReadClientHello(client2, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, req) {
		t.Errorf("first result corrupted after pool reuse: got %q want %q", first, req)
	}
	if !bytes.Equal(second, req2) {
		t.Errorf("second result wrong: got %q want %q", second, req2)
	}
}

// TestRemoteUDPReader_WritesNonEmptyPayload is a regression test for buf.As/buf.With.
// remoteUDPReader / handleDNS must wrap existing data with buf.As when writing it to the TUN:
// buf.With does not set end, so Bytes() returns an empty slice, which would write UDP replies / DNS responses as empty datagrams.
func TestRemoteUDPReader_WritesNonEmptyPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Build an upstream reply with a SOCKS5 UDP header: RSV(3) + ATYP=1 + IPv4(4) + Port(2) + payload
	payload := []byte("hello-udp")
	header := []byte{0, 0, 0, 0x01, 192, 168, 1, 1, 0, 53}
	upstreamPkt := append(header, payload...)

	go func() {
		server.Write(upstreamPkt)
		server.Close()
	}()

	tunConn := new(MockPacketConn)
	var captured *buf.Buffer
	tunConn.On("WritePacket", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		captured = args.Get(0).(*buf.Buffer)
	}).Return(nil)

	entry := &udpRemoteEntry{
		conn:    client,
		dst:     M.Socksaddr{Addr: netip.MustParseAddr("8.8.8.8"), Port: 53},
		isProxy: true,
	}
	errCh := make(chan error, 1)
	h := &TUNHandler{}
	h.remoteUDPReader(tunConn, entry, errCh)

	if captured == nil {
		t.Fatal("no WritePacket call captured")
	}
	if len(captured.Bytes()) == 0 {
		t.Fatal("reply datagram is empty: must use buf.As (buf.With Bytes() returns empty)")
	}
	if !bytes.Equal(captured.Bytes(), payload) {
		t.Fatalf("reply content = %q, want %q", captured.Bytes(), payload)
	}
}
