// Package notifier defines the Notifier interface and the structured Alert type
// that flows through it. Implementations live in sibling files.
package notifier

import (
	"context"
	"encoding/json"
	"time"
)

// Severity classifies an alert.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// AlertType is a stable string identifying the kind of alert. Strings here are
// also used as keys in the routing config, so don't change them lightly.
const (
	TypeDown            = "down"
	TypeRecovered       = "recovered"
	TypeSSLExpiring     = "ssl_expiring"
	TypeDomainExpiring  = "domain_expiring"
	TypeSSLUntrusted    = "ssl_untrusted"
	TypeDegradedMonitor = "degraded_monitoring"
)

// Alert is the structured alert that notifiers format and send.
type Alert struct {
	SiteName string
	Type     string
	Severity Severity
	Title    string
	Message  string
	Details  map[string]any
	At       time.Time
}

// PayloadJSON returns a JSON encoding of the alert details for storage.
func (a Alert) PayloadJSON() string {
	b, _ := json.Marshal(map[string]any{
		"title":    a.Title,
		"message":  a.Message,
		"severity": a.Severity,
		"details":  a.Details,
	})
	return string(b)
}

// Notifier sends alerts to a single configured destination.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, a Alert) error
}
