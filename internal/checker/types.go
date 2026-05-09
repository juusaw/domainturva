// Package checker performs the individual checks against a site.
package checker

import "time"

// CheckType identifies the kind of check that produced a result.
type CheckType string

const (
	CheckHTTP   CheckType = "http"
	CheckSSL    CheckType = "ssl"
	CheckDomain CheckType = "domain"
)

// Status is the outcome of a check.
type Status string

const (
	StatusUp      Status = "up"
	StatusDown    Status = "down"
	StatusUnknown Status = "unknown"
)

// CheckResult is the unified result type produced by all checkers.
type CheckResult struct {
	SiteName string
	Type     CheckType
	Status   Status
	At       time.Time

	// HTTP fields
	StatusCode    int
	ResponseMS    int64
	TLSHandshakeMS int64

	// SSL fields
	CertNotAfter   time.Time
	CertSerial     string
	CertIssuer     string
	CertSelfSigned bool
	CertUntrusted  bool
	DaysUntilCertExpiry int

	// Domain fields
	DomainExpiry        time.Time
	DaysUntilDomainExpiry int
	DomainLookupOK      bool // false if both RDAP and WHOIS failed

	Error string
}
