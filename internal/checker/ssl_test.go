package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juusomikkonen/domainturva/internal/config"
)

// makeCert returns a self-signed cert valid for 127.0.0.1 with the given NotAfter.
func makeCert(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestSSLChecker_DaysAndSelfSigned(t *testing.T) {
	notAfter := time.Now().Add(20 * 24 * time.Hour)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{makeCert(t, notAfter)}}
	srv.StartTLS()
	defer srv.Close()

	c := NewSSLChecker()
	site := config.Site{Name: "x", URL: srv.URL, Timeout: 5 * time.Second}
	r := c.Check(context.Background(), site)

	if r.DaysUntilCertExpiry < 19 || r.DaysUntilCertExpiry > 21 {
		t.Fatalf("expected ~20 days, got %d", r.DaysUntilCertExpiry)
	}
	if !r.CertUntrusted {
		t.Fatalf("expected untrusted (self-signed)")
	}
	if !r.CertSelfSigned {
		t.Fatalf("expected self-signed flag set")
	}
	if r.Status != StatusUp {
		t.Fatalf("expected up (cert is valid albeit untrusted), got %s", r.Status)
	}
}

func TestSSLChecker_Expired(t *testing.T) {
	notAfter := time.Now().Add(-24 * time.Hour)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{makeCert(t, notAfter)}}
	srv.StartTLS()
	defer srv.Close()

	c := NewSSLChecker()
	site := config.Site{Name: "x", URL: srv.URL, Timeout: 5 * time.Second}
	r := c.Check(context.Background(), site)
	if r.Status != StatusDown {
		t.Fatalf("expected down for expired cert, got %s", r.Status)
	}
}
