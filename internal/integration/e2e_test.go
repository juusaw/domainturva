package integration

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juusomikkonen/domainturva/internal/alerting"
	"github.com/juusomikkonen/domainturva/internal/checker"
	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/notifier"
	"github.com/juusomikkonen/domainturva/internal/scheduler"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

type fakeNotifier struct {
	name   string
	mu     sync.Mutex
	alerts []notifier.Alert
}

func (f *fakeNotifier) Name() string { return f.name }
func (f *fakeNotifier) Notify(_ context.Context, a notifier.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
	return nil
}
func (f *fakeNotifier) snapshot() []notifier.Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]notifier.Alert, len(f.alerts))
	copy(out, f.alerts)
	return out
}

// TestE2E_UpDownUp drives a real scheduler against an httptest server whose
// status flips between 200 and 500 and asserts that exactly one DOWN and one
// RECOVERED alert are dispatched.
func TestE2E_UpDownUp(t *testing.T) {
	var serverHealthy atomic.Bool
	serverHealthy.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serverHealthy.Load() {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// Seed state to 'up' so the very first 'down' transition produces an
	// alert (avoids the baseline-first silent rule).
	now := time.Now().UTC()
	if err := store.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "site", Status: string(checker.StatusUp), LastCheckAt: now, LastStatusChangeAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		CheckInterval: 100 * time.Millisecond,
		Sites: []config.Site{{
			Name: "site", URL: srv.URL,
			ExpectStatus: []int{200},
			Interval:     100 * time.Millisecond,
			Timeout:      2 * time.Second,
			Retries:      0,
		}},
		Notifiers: []config.Notifier{{Name: "fake", Type: "slack", Webhook: "x"}},
		Routing: config.Routing{
			Default: []string{"fake"},
			PerType: map[string][]string{},
		},
		Storage: config.Storage{Path: dbPath},
	}

	fn := &fakeNotifier{name: "fake"}
	logger := slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))

	httpChecker := checker.NewHTTPChecker()
	httpChecker.RetryBackoff = 10 * time.Millisecond
	engine := &alerting.Engine{Store: store, Now: time.Now}
	dispatcher := notifier.NewDispatcher(map[string]notifier.Notifier{"fake": fn}, store, logger)
	dispatcher.RetryDelay = 10 * time.Millisecond

	sch := &scheduler.Scheduler{
		Cfg: cfg, HTTP: httpChecker, Storage: store, Engine: engine,
		Dispatcher: dispatcher, Logger: logger,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go sch.Run(ctx)

	// Wait until the site has been observed at least once as up.
	if !waitFor(2*time.Second, func() bool {
		s, _, _ := store.GetSiteState(ctx, "site")
		return s.Status == string(checker.StatusUp) && s.LastCheckAt.After(now)
	}) {
		cancel()
		t.Fatal("never observed initial up")
	}

	// Take server down.
	serverHealthy.Store(false)
	if !waitFor(3*time.Second, func() bool {
		alerts := fn.snapshot()
		for _, a := range alerts {
			if a.Type == notifier.TypeDown {
				return true
			}
		}
		return false
	}) {
		cancel()
		t.Fatalf("never received down alert; alerts=%+v", fn.snapshot())
	}

	// Bring server back.
	serverHealthy.Store(true)
	if !waitFor(3*time.Second, func() bool {
		alerts := fn.snapshot()
		for _, a := range alerts {
			if a.Type == notifier.TypeRecovered {
				return true
			}
		}
		return false
	}) {
		cancel()
		t.Fatalf("never received recovery alert; alerts=%+v", fn.snapshot())
	}

	cancel()

	// Final assertions: exactly one down + one recovered.
	alerts := fn.snapshot()
	var down, rec int
	for _, a := range alerts {
		switch a.Type {
		case notifier.TypeDown:
			down++
		case notifier.TypeRecovered:
			rec++
		}
	}
	if down != 1 || rec != 1 {
		t.Fatalf("expected 1 down + 1 recovered, got down=%d rec=%d (%+v)", down, rec, alerts)
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
