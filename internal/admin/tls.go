package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SetTLS configures the TCP admin listener. When enabled the listener serves HTTPS
// on the same port and 301-redirects plaintext HTTP to https. certFile/keyFile are
// optional PEM paths; when empty a self-signed cert+key is auto-generated next to
// the config file (or kept in memory when no config path is known). TLS settings
// take effect on the next Start; a running server keeps its current listener.
func (s *Server) SetTLS(certFile, keyFile string, enabled bool) {
	s.certFile = certFile
	s.keyFile = keyFile
	s.tlsEnabled = enabled
}

// buildTLSConfig loads the configured certificate pair, or falls back to an
// auto-generated self-signed certificate persisted next to the config file.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	cert, err := s.loadCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// The custom listener hands *tls.Conn to http.Server directly (not ServeTLS),
		// so HTTP/2 is not negotiated; serve the panel over HTTP/1.1 explicitly.
		NextProtos: []string{"http/1.1"},
	}, nil
}

func (s *Server) loadCertificate() (tls.Certificate, error) {
	if s.certFile != "" || s.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load admin TLS cert: %w", err)
		}
		return cert, nil
	}
	// Auto-generated self-signed pair, persisted so restarts reuse the same
	// certificate (the browser only warns once instead of on every start).
	dir := ""
	if s.configPath != "" {
		dir = filepath.Dir(s.configPath)
	}
	if dir != "" {
		certPath, keyPath := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			return cert, nil
		}
		return genSelfSigned(certPath, keyPath)
	}
	return genSelfSigned("", "")
}

// genSelfSigned creates an ECDSA P-256 self-signed server certificate (397-day
// validity, SANs for localhost). When certPath/keyPath are non-empty the PEM files
// are written there best-effort — the in-memory certificate is used regardless.
func genSelfSigned(certPath, keyPath string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	notBefore := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "smartproxy"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(397 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if certPath != "" && keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
			slog.Warn("admin self-signed cert dir create failed", "dir", filepath.Dir(certPath), "error", err)
		} else {
			if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
				slog.Warn("admin self-signed cert write failed", "path", certPath, "error", err)
			} else if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
				slog.Warn("admin self-signed key write failed", "path", keyPath, "error", err)
			} else {
				slog.Info("admin self-signed certificate generated", "cert", certPath, "key", keyPath)
			}
		}
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// peekConn replays a byte already read from c before delegating to the underlying
// connection, so the TCP listener can inspect the first byte and still hand the
// connection over unmodified to TLS or plaintext HTTP.
type peekConn struct {
	net.Conn
	buf []byte
}

func (c *peekConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// splitListener accepts connections on one port and splits them by first byte:
// 0x16 (a TLS ClientHello record) is wrapped in tls.Server and served as HTTPS;
// anything else is treated as plaintext HTTP so http.Server can 301 it to https.
type splitListener struct {
	net.Listener
	tlsCfg *tls.Config
}

func (l *splitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			// Only the listener itself failing (e.g. it was closed on shutdown) is
			// fatal for http.Server.Serve; a bad peer must never be surfaced as an
			// accept error or Serve would treat it as fatal and stop the whole server.
			return nil, err
		}
		// Peek one byte to distinguish TLS from plaintext. A fresh connection sends
		// either a ClientHello or the request line immediately; bound the peek with a
		// short deadline so a silent peer cannot pin the accept loop forever.
		buf := make([]byte, 1)
		if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			c.Close()
			continue
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			// A peer that connected and went away without sending anything (health
			// checkers, port scanners, half-open probes) must not kill the accept
			// loop: drop it and wait for the next connection.
			c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Time{})
		pc := &peekConn{Conn: c, buf: buf}
		if buf[0] == 0x16 {
			return tls.Server(pc, l.tlsCfg), nil
		}
		return pc, nil
	}
}
