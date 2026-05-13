// Package health serves an opt-in /healthz endpoint that reports basic
// liveness plus a staleness check derived from site_state.last_check_at.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/juusomikkonen/domainturva/internal/buildinfo"
	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

// Server is the /healthz HTTP server. Zero-value is not usable; use New.
type Server struct {
	listen  string
	cfg     *config.Config
	store   storage.Storage
	log     *slog.Logger
	started time.Time
	now     func() time.Time
}

func New(cfg *config.Config, store storage.Storage, log *slog.Logger) *Server {
	return &Server{
		listen:  cfg.HealthCheck.Listen,
		cfg:     cfg,
		store:   store,
		log:     log,
		started: time.Now(),
		now:     time.Now,
	}
}

// Enabled reports whether the server is configured to listen.
func (s *Server) Enabled() bool { return s.listen != "" }

// Run blocks until ctx is cancelled. Returns the listener error, if any.
// http.ErrServerClosed (the expected shutdown path) is swallowed.
func (s *Server) Run(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)

	srv := &http.Server{
		Addr:              s.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("health server listening", "addr", s.listen)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

type healthResponse struct {
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	UptimeSeconds int64     `json:"uptime_sec"`
	Sites         int       `json:"sites"`
	LatestCheckAt time.Time `json:"latest_check_at,omitempty"`
	StaleAfter    string    `json:"stale_after"`
	Stale         bool      `json:"stale"`
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	latest, threshold := s.healthState(r.Context(), now)

	body := healthResponse{
		Status:        "ok",
		Version:       buildinfo.Version,
		UptimeSeconds: int64(now.Sub(s.started).Seconds()),
		Sites:         len(s.cfg.Sites),
		LatestCheckAt: latest,
		StaleAfter:    threshold.String(),
	}

	// Staleness: a check has been missed. We give the process a startup grace
	// of one threshold window before flagging stale, so a freshly-started
	// monitor with no checks recorded yet returns 200.
	if latest.IsZero() {
		if now.Sub(s.started) > threshold {
			body.Status = "stale"
			body.Stale = true
		}
	} else if now.Sub(latest) > threshold {
		body.Status = "stale"
		body.Stale = true
	}

	code := http.StatusOK
	if body.Stale {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// healthState returns (latest LastCheckAt across all sites, stale threshold).
// The threshold is 2× the largest HTTP check interval — SSL/domain intervals
// are deliberately ignored because they can be hours long and a stuck
// scheduler is most visible on the frequent HTTP loop.
func (s *Server) healthState(ctx context.Context, now time.Time) (time.Time, time.Duration) {
	threshold := s.staleThreshold()
	var latest time.Time
	for _, site := range s.cfg.Sites {
		st, ok, err := s.store.GetSiteState(ctx, site.Name)
		if err != nil {
			s.log.Warn("healthz: site state read failed", "site", site.Name, "err", err)
			continue
		}
		if !ok {
			continue
		}
		if st.LastCheckAt.After(latest) {
			latest = st.LastCheckAt
		}
	}
	_ = now
	return latest, threshold
}

func (s *Server) staleThreshold() time.Duration {
	var max time.Duration
	for _, site := range s.cfg.Sites {
		if site.Interval > max {
			max = site.Interval
		}
	}
	if max == 0 {
		max = 60 * time.Second
	}
	return 2 * max
}
