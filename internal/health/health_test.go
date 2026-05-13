package health

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

func newServer(t *testing.T, sites []config.Site, now time.Time, startOffset time.Duration) (*Server, *storage.Memory) {
	t.Helper()
	mem := storage.NewMemory()
	s := &Server{
		listen:  "127.0.0.1:0",
		cfg:     &config.Config{Sites: sites},
		store:   mem,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: now.Add(-startOffset),
		now:     func() time.Time { return now },
	}
	return s, mem
}

func decode(t *testing.T, w *httptest.ResponseRecorder) healthResponse {
	t.Helper()
	var got healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func TestHealthz_HappyPath(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s, mem := newServer(t, []config.Site{{Name: "a", Interval: 30 * time.Second}}, now, 10*time.Minute)
	mem.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "a", Status: "up", LastCheckAt: now.Add(-15 * time.Second),
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	got := decode(t, w)
	if got.Stale {
		t.Fatalf("expected not stale")
	}
	if got.Status != "ok" || got.Sites != 1 {
		t.Fatalf("body: %+v", got)
	}
}

func TestHealthz_StaleReturns503(t *testing.T) {
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s, mem := newServer(t, []config.Site{{Name: "a", Interval: 30 * time.Second}}, now, 10*time.Minute)
	// last check was 10 minutes ago; threshold is 2× 30s = 60s.
	mem.UpsertSiteState(context.Background(), storage.SiteState{
		SiteName: "a", Status: "up", LastCheckAt: now.Add(-10 * time.Minute),
	})

	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest("GET", "/healthz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", w.Code)
	}
	got := decode(t, w)
	if !got.Stale || got.Status != "stale" {
		t.Fatalf("body: %+v", got)
	}
}

func TestHealthz_StartupGraceReturns200(t *testing.T) {
	// Process just started; no checks have happened yet. Threshold is 60s.
	// Process age is 10s → within grace → return 200.
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s, _ := newServer(t, []config.Site{{Name: "a", Interval: 30 * time.Second}}, now, 10*time.Second)

	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest("GET", "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 during startup grace, got %d", w.Code)
	}
}

func TestHealthz_StartupGraceExpired(t *testing.T) {
	// Process is older than the threshold but no checks recorded → stale.
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	s, _ := newServer(t, []config.Site{{Name: "a", Interval: 30 * time.Second}}, now, 5*time.Minute)

	w := httptest.NewRecorder()
	s.handleHealthz(w, httptest.NewRequest("GET", "/healthz", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 after grace, got %d", w.Code)
	}
}

func TestServer_Disabled(t *testing.T) {
	s := New(&config.Config{}, storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if s.Enabled() {
		t.Fatal("expected disabled when Listen is empty")
	}
	// Run should return nil immediately.
	if err := s.Run(context.Background()); err != nil {
		t.Fatalf("Run on disabled server: %v", err)
	}
}

func TestServer_Run_GracefulShutdown(t *testing.T) {
	cfg := &config.Config{
		Sites:       []config.Site{{Name: "a", Interval: 30 * time.Second}},
		HealthCheck: config.HealthCheck{Listen: "127.0.0.1:0"},
	}
	srv := New(cfg, storage.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Manually start it so we can grab a Listener — Run uses ListenAndServe
	// which picks its own port. To keep the test simple, just verify the
	// server runs and shuts down without error within a short window.

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Let it bind, then cancel.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of ctx cancel")
	}
}
