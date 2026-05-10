package alerting

import (
	"context"
	"testing"
	"time"

	"github.com/juusomikkonen/domainturva/internal/checker"
	"github.com/juusomikkonen/domainturva/internal/notifier"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

func newEngine(now time.Time) (*Engine, *storage.Memory) {
	mem := storage.NewMemory()
	e := &Engine{
		Store:          mem,
		SSLWarnDays:    []int{30, 14, 7, 1},
		DomainWarnDays: []int{60, 30, 14, 7},
		Now:            func() time.Time { return now },
	}
	return e, mem
}

func TestDecide_BaselineFirstFailureSilent(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, _ := newEngine(now)
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckHTTP, Status: checker.StatusDown, Error: "boom"}
	out, err := e.Process(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if out.NewState.Status != string(checker.StatusDown) {
		t.Fatalf("state should flip to down, got %s", out.NewState.Status)
	}
	if len(out.Alerts) != 0 {
		t.Fatalf("baseline-first must not alert, got %+v", out.Alerts)
	}
}

func TestDecide_UpToDownEmitsAlertOnFirstFailure(t *testing.T) {
	// HTTPChecker handles its own retries; the engine should flip on the
	// first down result it sees, not gate on accumulated failures.
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, mem := newEngine(now)
	mem.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "a", Status: string(checker.StatusUp), LastStatusChangeAt: now.Add(-time.Hour),
	})
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckHTTP, Status: checker.StatusDown, Error: "x"}
	out, _ := e.Process(context.Background(), r)
	if out.NewState.Status != string(checker.StatusDown) {
		t.Fatalf("should flip to down on first failure")
	}
	if len(out.Alerts) != 1 || out.Alerts[0].Alert.Type != notifier.TypeDown {
		t.Fatalf("expected down alert, got %+v", out.Alerts)
	}
}

func TestDecide_RecoveryEmitsAlertWithDowntime(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, mem := newEngine(now)
	mem.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "a", Status: string(checker.StatusDown), LastStatusChangeAt: now.Add(-15 * time.Minute),
	})
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckHTTP, Status: checker.StatusUp, StatusCode: 200}
	out, _ := e.Process(context.Background(), r)
	if out.NewState.Status != string(checker.StatusUp) {
		t.Fatalf("should flip to up")
	}
	if len(out.Alerts) != 1 || out.Alerts[0].Alert.Type != notifier.TypeRecovered {
		t.Fatalf("expected recovery alert")
	}
}

func TestDecide_DownStaysDownNoSecondAlert(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, mem := newEngine(now)
	mem.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "a", Status: string(checker.StatusDown), LastStatusChangeAt: now.Add(-10 * time.Minute),
	})
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckHTTP, Status: checker.StatusDown, Error: "still down"}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 0 {
		t.Fatalf("repeat down should not re-alert, got %+v", out.Alerts)
	}
}

func TestDecide_SSLThresholdOnceThenDedup(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, _ := newEngine(now)
	r := checker.CheckResult{
		SiteName: "a", Type: checker.CheckSSL,
		CertNotAfter: now.Add(10 * 24 * time.Hour), DaysUntilCertExpiry: 10, CertSerial: "ABC",
	}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 1 || out.Alerts[0].Threshold != 14 {
		t.Fatalf("expected single ssl alert at threshold 14, got %+v", out.Alerts)
	}
	// Persist the alert (simulating dispatcher), then check we don't re-alert.
	e.Store.RecordAlert(context.Background(), storage.AlertRecord{
		SiteName: "a", AlertType: notifier.TypeSSLExpiring, Threshold: 14, CertSerial: "ABC",
		SentAt: now, Notifier: "n", Status: "sent",
	})
	out, _ = e.Process(context.Background(), r)
	if len(out.Alerts) != 0 {
		t.Fatalf("should dedup, got %+v", out.Alerts)
	}
}

func TestDecide_SSLCertRenewedRearmsThreshold(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, _ := newEngine(now)
	// Earlier alert at threshold 14 with old serial.
	e.Store.RecordAlert(context.Background(), storage.AlertRecord{
		SiteName: "a", AlertType: notifier.TypeSSLExpiring, Threshold: 14, CertSerial: "OLD",
		SentAt: now.Add(-30 * 24 * time.Hour), Notifier: "n", Status: "sent",
	})
	r := checker.CheckResult{
		SiteName: "a", Type: checker.CheckSSL,
		CertNotAfter: now.Add(10 * 24 * time.Hour), DaysUntilCertExpiry: 10, CertSerial: "NEW",
	}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 1 {
		t.Fatalf("renewed cert should re-arm threshold, got %d alerts", len(out.Alerts))
	}
}

func TestDecide_SSLCrossesMultipleThresholdsOneAtATime(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, _ := newEngine(now)
	// 25 days left → only threshold 30 fires.
	r := checker.CheckResult{
		SiteName: "a", Type: checker.CheckSSL,
		CertNotAfter: now.Add(25 * 24 * time.Hour), DaysUntilCertExpiry: 25, CertSerial: "X",
	}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 1 || out.Alerts[0].Threshold != 30 {
		t.Fatalf("expected threshold 30 alert, got %+v", out.Alerts)
	}
}

func TestDecide_DegradedMonitoringAfter3Days(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, mem := newEngine(now)
	// Cache shows last successful lookup was 4 days ago.
	mem.UpsertDomainCache(context.Background(), storage.DomainCache{
		SiteName: "a", LastOkAt: now.Add(-4 * 24 * time.Hour), Error: "rdap timeout",
	})
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckDomain, DomainLookupOK: false}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 1 || out.Alerts[0].Alert.Type != notifier.TypeDegradedMonitor {
		t.Fatalf("expected degraded monitoring alert, got %+v", out.Alerts)
	}
}

func TestDecide_DegradedMonitoringSilentWithin3Days(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	e, mem := newEngine(now)
	mem.UpsertDomainCache(context.Background(), storage.DomainCache{
		SiteName: "a", LastOkAt: now.Add(-2 * 24 * time.Hour), Error: "x",
	})
	r := checker.CheckResult{SiteName: "a", Type: checker.CheckDomain, DomainLookupOK: false}
	out, _ := e.Process(context.Background(), r)
	if len(out.Alerts) != 0 {
		t.Fatalf("expected no alert, got %+v", out.Alerts)
	}
}

func TestCurrentThresholdBand(t *testing.T) {
	tt := []struct {
		days int
		want int
	}{
		{100, 0},
		{31, 0},
		{30, 30},
		{15, 30},
		{14, 14},
		{8, 14},
		{7, 7},
		{1, 1},
	}
	for _, c := range tt {
		got := currentThresholdBand(c.days, []int{30, 14, 7, 1})
		if got != c.want {
			t.Errorf("days=%d: got %d, want %d", c.days, got, c.want)
		}
	}
}
