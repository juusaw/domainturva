package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/juusomikkonen/domainturva/internal/config"
)

// SSLChecker fetches the leaf certificate via tls.Dial and reports its expiry.
type SSLChecker struct {
	Now func() time.Time
}

func NewSSLChecker() *SSLChecker {
	return &SSLChecker{Now: time.Now}
}

func (c *SSLChecker) Check(ctx context.Context, s config.Site) CheckResult {
	r := CheckResult{SiteName: s.Name, Type: CheckSSL, At: c.now()}
	u, err := url.Parse(s.URL)
	if err != nil {
		r.Status = StatusDown
		r.Error = "parse url: " + err.Error()
		return r
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}

	cctx, cancel := context.WithTimeout(ctx, max(s.Timeout, 5*time.Second))
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		// Don't reject on validation: we want to *report* untrusted state.
		Config: &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
	}
	conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		r.Status = StatusDown
		r.Error = "tls dial: " + err.Error()
		return r
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		r.Status = StatusDown
		r.Error = "no peer certificates"
		return r
	}
	leaf := state.PeerCertificates[0]
	r.CertNotAfter = leaf.NotAfter
	r.CertSerial = leaf.SerialNumber.String()
	r.CertIssuer = leaf.Issuer.CommonName
	r.DaysUntilCertExpiry = int(time.Until(leaf.NotAfter).Hours() / 24)
	r.Status = StatusUp

	// Re-verify against system roots (we used InsecureSkipVerify above).
	roots, _ := x509.SystemCertPool()
	intermediates := x509.NewCertPool()
	for _, ic := range state.PeerCertificates[1:] {
		intermediates.AddCert(ic)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   c.now(),
	})
	if verr != nil {
		r.CertUntrusted = true
		var unknownAuth x509.UnknownAuthorityError
		if errors.As(verr, &unknownAuth) && isSelfSigned(leaf) {
			r.CertSelfSigned = true
		}
		r.Error = "cert verify: " + verr.Error()
	}

	if leaf.NotAfter.Before(c.now()) {
		r.Status = StatusDown
		r.Error = fmt.Sprintf("cert expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	return r
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Issuer.String() == c.Subject.String()
}

func (c *SSLChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
