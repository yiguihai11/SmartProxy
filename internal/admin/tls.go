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
	"strings"
	"time"
)

// SetTLS configures the TCP admin listener. When enabled the listener serves HTTPS
// on the same port and 301-redirects plaintext HTTP to https. certFile/keyFile are
// optional PEM paths; when empty a self-signed cert+key is auto-generated next to
// the config file (or kept in memory when no config path is known). extraSANs are
// additional hostnames/IPs written into that auto-generated cert (beyond the
// built-in localhost/127.0.0.1/::1), so a LAN address in admin_cert_sans is
// covered without supplying certificate files. TLS settings take effect on the
// next Start; a running server keeps its current listener.
func (s *Server) SetTLS(certFile, keyFile string, enabled bool, extraSANs ...string) {
	s.certFile = certFile
	s.keyFile = keyFile
	s.tlsEnabled = enabled
	s.tlsExtraSANs = extraSANs
}

// buildTLSConfig loads the configured certificate pair, or falls back to an
// auto-generated self-signed certificate persisted next to the config file.
func (s *Server) buildTLSConfig() (*tls.Config, error) {
	cert, certPEM, err := s.loadCertificate()
	if err != nil {
		return nil, err
	}
	// Keep the public certificate available for the panel's /admin.crt download
	// (handleAdminCert). With a baked CA this is the CA cert PEM — the thing devices
	// must install as a trusted root — not the runtime leaf. Never the private key.
	s.certPEM = certPEM
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		// The custom listener hands *tls.Conn to http.Server directly (not ServeTLS),
		// so HTTP/2 is not negotiated; serve the panel over HTTP/1.1 explicitly.
		NextProtos: []string{"http/1.1"},
	}, nil
}

func (s *Server) loadCertificate() (tls.Certificate, []byte, error) {
	if s.certFile != "" || s.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("load admin TLS cert: %w", err)
		}
		return cert, pemLeaf(cert), nil
	}
	// Auto-generated pair, persisted so restarts reuse the same certificate (the
	// browser only warns once instead of on every start). A baked CA — embedded in
	// the binary (shared by Android and desktop) or a user-supplied admin_ca.* next
	// to the config file — signs a short-lived leaf: the CA never changes, so devices
	// that installed it as a trusted root keep validating across app reinstalls, and
	// an admin_cert_sans edit only re-signs the leaf.
	dir := ""
	if s.configPath != "" {
		dir = filepath.Dir(s.configPath)
	}
	if caCert, ok := bakedCA(dir); ok {
		return s.loadCAIssuedLeaf(caCert, dir)
	}
	if dir != "" {
		certPath, keyPath := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			// Reuse a persisted cert only while it still covers the requested SANs;
			// otherwise regenerate so a changed admin_cert_sans takes effect instead
			// of silently serving a cert that is invalid for the panel's address.
			if certCoversSANs(cert, s.tlsExtraSANs) {
				return cert, pemLeaf(cert), nil
			}
		}
		cert, err := genSelfSigned(certPath, keyPath, s.tlsExtraSANs...)
		return cert, pemLeaf(cert), err
	}
	cert, err := genSelfSigned("", "", s.tlsExtraSANs...)
	return cert, pemLeaf(cert), err
}

// bakedCA returns the CA certificate used to sign admin leaves: a user-supplied
// admin_ca.{crt,key} next to the config file (dir) takes precedence, otherwise the
// CA embedded in the binary. ok is false only when neither is available (a binary
// built without the embedded certs), leaving the self-signed fallback.
func bakedCA(dir string) (tls.Certificate, bool) {
	if dir != "" {
		if cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "admin_ca.crt"), filepath.Join(dir, "admin_ca.key")); err == nil {
			return cert, true
		}
	}
	certPEM, err1 := embeddedCA.ReadFile("certs/admin_ca.crt")
	keyPEM, err2 := embeddedCA.ReadFile("certs/admin_ca.key")
	if err1 != nil || err2 != nil {
		return tls.Certificate{}, false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	return cert, true
}

// loadCAIssuedLeaf loads the leaf signed by the baked CA, re-signing when the
// persisted one no longer covers the requested SANs, is expired, or was signed by a
// different CA. The download PEM returned is the CA certificate itself, so /admin.crt
// installs the stable trust anchor rather than the ephemeral leaf.
func (s *Server) loadCAIssuedLeaf(ca tls.Certificate, dir string) (tls.Certificate, []byte, error) {
	// dir is "" when no config path is known (rare): keep the leaf in memory only.
	certPath, keyPath := "", ""
	if dir != "" {
		certPath, keyPath = filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			if certCoversSANs(cert, s.tlsExtraSANs) && leafSignedBy(cert, ca) {
				return cert, pemLeaf(ca), nil
			}
		}
	}
	cert, err := genCAIssuedLeaf(ca, certPath, keyPath, s.tlsExtraSANs...)
	return cert, pemLeaf(ca), err
}

// pemLeaf re-encodes the leaf certificate's DER bytes as PEM, for serving admin.crt.
func pemLeaf(cert tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
}

// genSelfSigned creates an ECDSA P-256 self-signed CA/server certificate
// (397-day validity, SANs for localhost plus any extraSANs). IsCA is set so
// Android's cert installer recognizes it as a CA certificate — otherwise the
// system treats it as a personal-identity cert and demands the private key to
// install. The one self-signed cert plays both roles: it is its own root CA and
// the panel's server cert, so installing it as a CA makes the panel trusted.
// When certPath/keyPath are non-empty the PEM files are written there
// best-effort — the in-memory certificate is used regardless.
func genSelfSigned(certPath, keyPath string, extraSANs ...string) (tls.Certificate, error) {
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
	extraDNS, extraIPs := splitSANs(extraSANs)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "smartproxy"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(397 * 24 * time.Hour),
		// CertSign is mandatory when IsCA is set (x509.CreateCertificate rejects
		// the combination otherwise); digitalSignature+keyEncipherment keep the
		// cert usable as a TLS server certificate too.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              append([]string{"localhost"}, extraDNS...),
		IPAddresses:           append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, extraIPs...),
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

// genCAIssuedLeaf creates an ECDSA P-256 server leaf signed by the baked CA
// (397-day validity, SANs for localhost/loopback plus any extraSANs) and persists
// it to certPath/keyPath best-effort. The CA stays untouched, so re-signing after a
// SAN edit does not invalidate devices that already trust the CA. Unlike
// genSelfSigned the leaf is not itself a CA (IsCA=false): only the CA is installed
// as a trusted root on devices.
func genCAIssuedLeaf(ca tls.Certificate, certPath, keyPath string, extraSANs ...string) (tls.Certificate, error) {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	caKey, ok := ca.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("admin CA private key is not an ECDSA key")
	}
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
	extraDNS, extraIPs := splitSANs(extraSANs)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "smartproxy"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(397 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string{"localhost"}, extraDNS...),
		IPAddresses:           append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, extraIPs...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
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
			slog.Warn("admin CA-issued leaf dir create failed", "dir", filepath.Dir(certPath), "error", err)
		} else {
			if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
				slog.Warn("admin CA-issued leaf cert write failed", "path", certPath, "error", err)
			} else if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
				slog.Warn("admin CA-issued leaf key write failed", "path", keyPath, "error", err)
			} else {
				slog.Info("admin CA-issued leaf certificate generated", "cert", certPath, "key", keyPath)
			}
		}
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// leafSignedBy reports whether cert's leaf was signed by ca, so a persisted leaf
// produced by a previous (possibly different) CA is not reused after the CA changed.
func leafSignedBy(cert tls.Certificate, ca tls.Certificate) bool {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return false
	}
	return leaf.CheckSignatureFrom(caLeaf) == nil
}

// splitSANs classifies SAN entries into DNS names and IP addresses, dropping
// wildcards and wildcard-ish bind addresses ("*", "::", "0.0.0.0") that are not
// valid as a concrete certificate SAN.
func splitSANs(entries []string) (dns []string, ips []net.IP) {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || e == "*" || e == "::" || e == "0.0.0.0" {
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, e)
	}
	return dns, ips
}

// certCoversSANs reports whether the leaf certificate still covers the built-in
// localhost SANs plus every requested extra SAN, and is not about to expire, so a
// persisted admin.crt is only reused while it is valid for the addresses the panel
// is served on.
func certCoversSANs(cert tls.Certificate, extraSANs []string) bool {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	// Expiring within the hour is treated as not covered so the caller regenerates
	// instead of serving a certificate that is about to be rejected by clients.
	if !leaf.NotAfter.After(time.Now().Add(time.Hour)) {
		return false
	}
	haveDNS := make(map[string]bool, len(leaf.DNSNames))
	for _, d := range leaf.DNSNames {
		haveDNS[d] = true
	}
	haveIP := make(map[string]bool, len(leaf.IPAddresses))
	for _, ip := range leaf.IPAddresses {
		haveIP[ip.String()] = true
	}
	for _, d := range []string{"localhost"} {
		if !haveDNS[d] {
			return false
		}
	}
	for _, s := range []string{"127.0.0.1", "::1"} {
		if !haveIP[s] {
			return false
		}
	}
	extraDNS, extraIPs := splitSANs(extraSANs)
	for _, d := range extraDNS {
		if !haveDNS[d] {
			return false
		}
	}
	for _, ip := range extraIPs {
		if !haveIP[ip.String()] {
			return false
		}
	}
	return true
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
