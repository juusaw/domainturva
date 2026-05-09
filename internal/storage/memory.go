package storage

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is an in-memory Storage implementation, intended for tests.
type Memory struct {
	mu      sync.Mutex
	states  map[string]SiteState
	alerts  []AlertRecord
	domains map[string]DomainCache
	nextID  int64
}

func NewMemory() *Memory {
	return &Memory{
		states:  map[string]SiteState{},
		domains: map[string]DomainCache{},
	}
}

func (m *Memory) GetSiteState(_ context.Context, name string) (SiteState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[name]
	return s, ok, nil
}

func (m *Memory) UpsertSiteState(_ context.Context, s SiteState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[s.SiteName] = s
	return nil
}

func (m *Memory) RecordAlert(_ context.Context, a AlertRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	a.ID = m.nextID
	if a.Status == "" {
		a.Status = "sent"
	}
	m.alerts = append(m.alerts, a)
	return nil
}

func (m *Memory) FindRecentAlerts(_ context.Context, siteName, alertType string, since time.Time) ([]AlertRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AlertRecord
	for _, a := range m.alerts {
		if a.SiteName == siteName && a.AlertType == alertType && !a.SentAt.Before(since) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SentAt.After(out[j].SentAt) })
	return out, nil
}

func (m *Memory) GetDomainCache(_ context.Context, name string) (DomainCache, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.domains[name]
	return d, ok, nil
}

func (m *Memory) UpsertDomainCache(_ context.Context, d DomainCache) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domains[d.SiteName] = d
	return nil
}

func (m *Memory) Close() error { return nil }

// AllAlerts returns a snapshot of all alerts (for tests).
func (m *Memory) AllAlerts() []AlertRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AlertRecord, len(m.alerts))
	copy(out, m.alerts)
	return out
}
