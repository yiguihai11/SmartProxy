package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// hasIP reports whether ips contains an address equal to want (net.IP is not
// comparable, so slices.Contains is not usable for it).
func hasIP(ips []net.IP, want net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}

// writeTestCA generates a throwaway ECDSA CA and writes admin_ca.{crt,key} into dir,
// simulating the CA extracted from Android assets to filesDir.
func writeTestCA(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SmartProxy Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "admin_ca.crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "admin_ca.key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readCAPEM loads the CA certificate written by writeTestCA for verification.
func readCAPEM(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "admin_ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("no PEM block in admin_ca.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAdmin_CAIssuedLeaf(t *testing.T) {
	dir := t.TempDir()
	writeTestCA(t, dir)
	caCert := readCAPEM(t, dir)
	caPEM, _ := os.ReadFile(filepath.Join(dir, "admin_ca.crt"))

	server := &Server{configPath: filepath.Join(dir, "config.json")}
	server.SetTLS("", "", true, "smartproxy.lan")

	// 1. 首次:签一张叶子,下载端点是 CA 本身。
	cert, download, err := server.loadCertificate()
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Error("served leaf must not itself be a CA")
	}
	if !slices.Contains(leaf.DNSNames, "smartproxy.lan") {
		t.Errorf("leaf missing smartproxy.lan SAN, got %v", leaf.DNSNames)
	}
	if !slices.Contains(leaf.DNSNames, "localhost") {
		t.Errorf("leaf missing built-in localhost SAN, got %v", leaf.DNSNames)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("leaf not signed by baked CA: %v", err)
	}
	if !bytes.Equal(download, caPEM) {
		t.Error("download PEM must be the CA certificate (the trust anchor), not the leaf")
	}
	if _, err := server.buildTLSConfig(); err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if !bytes.Equal(server.certPEM, caPEM) {
		t.Error("s.certPEM must be the CA certificate for /admin.crt")
	}

	// 2. SAN 未变:复用持久化叶子,不重签。
	cert2, _, err := server.loadCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert2.Certificate[0], cert.Certificate[0]) {
		t.Error("unchanged SANs should reuse the persisted leaf")
	}

	// 3. SAN 变更(如面板改 admin_cert_sans):重签新叶子,仍由同一 CA 签发。
	server2 := &Server{configPath: filepath.Join(dir, "config.json")}
	server2.SetTLS("", "", true, "smartproxy.lan", "192.168.1.50")
	cert3, _, err := server2.loadCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cert3.Certificate[0], cert.Certificate[0]) {
		t.Error("changed SAN should re-sign a new leaf")
	}
	leaf3, err := x509.ParseCertificate(cert3.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf3.DNSNames, "smartproxy.lan") || !hasIP(leaf3.IPAddresses, net.ParseIP("192.168.1.50")) {
		t.Errorf("re-signed leaf missing requested SANs: dns=%v ips=%v", leaf3.DNSNames, leaf3.IPAddresses)
	}
	if err := leaf3.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("re-signed leaf must still be signed by the same baked CA: %v", err)
	}

	// 4. CA 更换(理论上不该发生,防御):旧叶子不再复用,由新 CA 重签。
	writeTestCA(t, dir)
	newCA := readCAPEM(t, dir)
	server3 := &Server{configPath: filepath.Join(dir, "config.json")}
	server3.SetTLS("", "", true, "smartproxy.lan")
	cert4, _, err := server3.loadCertificate()
	if err != nil {
		t.Fatal(err)
	}
	leaf4, err := x509.ParseCertificate(cert4.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf4.CheckSignatureFrom(newCA); err != nil {
		t.Errorf("leaf signed by old CA was reused after CA change: %v", err)
	}
}

// TestAdmin_EmbeddedCA verifies the binary-embedded CA is used when no local
// admin_ca.* override exists (the default for both the Android AAR and desktop), so
// both builds serve leaves from the same trust anchor.
func TestAdmin_EmbeddedCA(t *testing.T) {
	dir := t.TempDir() // no admin_ca.* written → embedded CA is used
	caPEM, err := embeddedCA.ReadFile("certs/admin_ca.crt")
	if err != nil {
		t.Fatalf("embedded CA missing: %v", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		t.Fatal("no PEM block in embedded CA")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !caCert.IsCA {
		t.Error("embedded CA must be a CA certificate")
	}

	s := &Server{configPath: filepath.Join(dir, "config.json")}
	s.SetTLS("", "", true, "smartproxy.lan")
	cert, download, err := s.loadCertificate()
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf.DNSNames, "smartproxy.lan") {
		t.Errorf("leaf missing smartproxy.lan, got %v", leaf.DNSNames)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("leaf not signed by embedded CA: %v", err)
	}
	if !bytes.Equal(download, caPEM) {
		t.Error("download PEM should be the embedded CA certificate")
	}
}
