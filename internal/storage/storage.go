// Package storage persists site state and the alert log.
package storage

import (
	"context"
	"time"
)

type SiteState struct {
	SiteName             string
	Status               string
	LastCheckAt          time.Time
	LastStatusChangeAt   time.Time
	ConsecutiveFailures  int
	LastError            string
}

type AlertRecord struct {
	ID         int64
	SiteName   string
	AlertType  string
	Threshold  int    // 0 if not applicable (e.g. ssl threshold days)
	CertSerial string // for SSL alerts, to detect renewals
	Payload    string // JSON
	SentAt     time.Time
	Notifier   string
	Status     string // 'sent' | 'failed'
}

type DomainCache struct {
	SiteName     string
	ExpiresAt    time.Time
	LastLookupAt time.Time
	LastOkAt     time.Time
	Source       string
	Error        string
}

// Storage is the persistence interface used by the rest of the system.
type Storage interface {
	GetSiteState(ctx context.Context, name string) (SiteState, bool, error)
	UpsertSiteState(ctx context.Context, s SiteState) error

	RecordAlert(ctx context.Context, a AlertRecord) error
	// FindRecentAlerts returns alerts for site/type since `since`, ordered by sent_at desc.
	FindRecentAlerts(ctx context.Context, siteName, alertType string, since time.Time) ([]AlertRecord, error)

	GetDomainCache(ctx context.Context, name string) (DomainCache, bool, error)
	UpsertDomainCache(ctx context.Context, d DomainCache) error

	Close() error
}
