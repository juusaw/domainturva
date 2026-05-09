package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestSQLite(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLite_Migrate_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}

func TestSQLite_SiteState_Roundtrip(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	in := SiteState{
		SiteName:            "a",
		Status:              "up",
		LastCheckAt:         now,
		LastStatusChangeAt:  now.Add(-time.Hour),
		ConsecutiveFailures: 0,
		LastError:           "",
	}
	if err := s.UpsertSiteState(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetSiteState(ctx, "a")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if got.Status != "up" || !got.LastCheckAt.Equal(now) {
		t.Fatalf("mismatch: %+v", got)
	}

	in.Status = "down"
	in.LastError = "boom"
	in.ConsecutiveFailures = 3
	if err := s.UpsertSiteState(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetSiteState(ctx, "a")
	if got.Status != "down" || got.LastError != "boom" || got.ConsecutiveFailures != 3 {
		t.Fatalf("update mismatch: %+v", got)
	}
}

func TestSQLite_AlertLog(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		err := s.RecordAlert(ctx, AlertRecord{
			SiteName: "a", AlertType: "down", SentAt: t0.Add(time.Duration(i) * time.Minute),
			Notifier: "n", Status: "sent",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.FindRecentAlerts(ctx, "a", "down", t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3, got %d", len(rows))
	}
	rows, err = s.FindRecentAlerts(ctx, "a", "down", t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("since-filter: expected 1, got %d", len(rows))
	}
}

func TestSQLite_DomainCache(t *testing.T) {
	s := newTestSQLite(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	d := DomainCache{
		SiteName: "a", ExpiresAt: now.Add(30 * 24 * time.Hour),
		LastLookupAt: now, LastOkAt: now, Source: "rdap",
	}
	if err := s.UpsertDomainCache(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetDomainCache(ctx, "a")
	if err != nil || !ok {
		t.Fatalf("get: %v %v", err, ok)
	}
	if got.Source != "rdap" {
		t.Fatalf("mismatch: %+v", got)
	}
}
