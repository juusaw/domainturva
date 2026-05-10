// Package alerting computes state transitions and the alerts they should
// produce. The Decide function is intentionally pure so it can be unit-tested
// against many scenarios without I/O.
package alerting

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/juusomikkonen/domainturva/internal/checker"
	"github.com/juusomikkonen/domainturva/internal/notifier"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

// Engine wires the pure decision logic to persistent state and the alert log
// (used for SSL/domain dedup). It also detects degraded-monitoring conditions.
type Engine struct {
	Store          storage.Storage
	SSLWarnDays    []int
	DomainWarnDays []int
	Now            func() time.Time
}

// Outcome is the new persisted state plus any alerts that should be dispatched.
type Outcome struct {
	NewState storage.SiteState
	Alerts   []alertWithMeta
}

// alertWithMeta carries the AlertRecord fields (threshold, cert serial) needed
// for accurate logging alongside the user-facing Alert.
type alertWithMeta struct {
	Alert      notifier.Alert
	Threshold  int
	CertSerial string
}

// Process is the top-level entry point: takes a single CheckResult, reads any
// state/dedup info needed, and returns the new state plus alerts to dispatch.
//
// Caller is responsible for persisting NewState and dispatching Alerts.
//
// HTTP retries are owned by the HTTPChecker — by the time a CheckResult of
// status=down reaches us, all attempts have been exhausted. So the engine
// flips state on the first down result; it does not gate on accumulated
// consecutive failures.
func (e *Engine) Process(ctx context.Context, r checker.CheckResult) (Outcome, error) {
	now := e.now()
	prev, _, err := e.Store.GetSiteState(ctx, r.SiteName)
	if err != nil {
		return Outcome{}, err
	}
	if prev.SiteName == "" {
		prev.SiteName = r.SiteName
		prev.Status = string(checker.StatusUnknown)
		prev.LastStatusChangeAt = now
	}

	switch r.Type {
	case checker.CheckHTTP:
		newState, alerts := decideHTTP(prev, r, now)
		return Outcome{NewState: newState, Alerts: alerts}, nil
	case checker.CheckSSL:
		alerts, err := e.decideSSL(ctx, prev, r, now)
		if err != nil {
			return Outcome{}, err
		}
		// SSL checks don't change the up/down state; just refresh last_check_at.
		prev.LastCheckAt = now
		return Outcome{NewState: prev, Alerts: alerts}, nil
	case checker.CheckDomain:
		alerts, err := e.decideDomain(ctx, prev, r, now)
		if err != nil {
			return Outcome{}, err
		}
		prev.LastCheckAt = now
		return Outcome{NewState: prev, Alerts: alerts}, nil
	default:
		return Outcome{NewState: prev}, nil
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// decideHTTP implements the up/down state machine.
//
// Baseline rule: if prev.Status is "unknown", we never produce a down/recovery
// alert — the first observed state becomes the baseline. This avoids spurious
// pages on monitor restart.
func decideHTTP(prev storage.SiteState, r checker.CheckResult, now time.Time) (storage.SiteState, []alertWithMeta) {
	ns := prev
	ns.LastCheckAt = now
	ns.LastError = r.Error

	if r.Status == checker.StatusUp {
		ns.ConsecutiveFailures = 0
		ns.Status = string(checker.StatusUp)
		ns.LastError = ""
		if prev.Status == string(checker.StatusDown) {
			ns.LastStatusChangeAt = now
			downtime := now.Sub(prev.LastStatusChangeAt)
			return ns, []alertWithMeta{{Alert: notifier.Alert{
				SiteName: r.SiteName, Type: notifier.TypeRecovered, Severity: notifier.SeverityInfo,
				Title:   "Recovered",
				Message: fmt.Sprintf("%s is back up after %s.", r.SiteName, formatDuration(downtime)),
				Details: map[string]any{
					"downtime":    formatDuration(downtime),
					"status_code": r.StatusCode,
					"response_ms": r.ResponseMS,
				},
				At: now,
			}}}
		}
		if prev.Status != string(checker.StatusUp) {
			ns.LastStatusChangeAt = now
		}
		return ns, nil
	}

	// Failure path. The HTTPChecker has already exhausted its internal retry
	// budget by the time we see status=down, so flip on the first down result.
	ns.ConsecutiveFailures = prev.ConsecutiveFailures + 1
	if prev.Status == string(checker.StatusDown) {
		// Already down, no new alert.
		return ns, nil
	}
	wasUnknown := prev.Status == string(checker.StatusUnknown) || prev.Status == ""
	ns.Status = string(checker.StatusDown)
	ns.LastStatusChangeAt = now
	if wasUnknown {
		// Baseline-first: don't alert on the very first observation.
		return ns, nil
	}
	return ns, []alertWithMeta{{Alert: notifier.Alert{
		SiteName: r.SiteName, Type: notifier.TypeDown, Severity: notifier.SeverityCritical,
		Title:   "DOWN",
		Message: fmt.Sprintf("%s is down: %s", r.SiteName, r.Error),
		Details: map[string]any{
			"error":        r.Error,
			"status_code":  r.StatusCode,
			"consec_fails": ns.ConsecutiveFailures,
		},
		At: now,
	}}}
}

func (e *Engine) decideSSL(ctx context.Context, prev storage.SiteState, r checker.CheckResult, now time.Time) ([]alertWithMeta, error) {
	if r.CertUntrusted || r.CertSelfSigned {
		// One alert when this is freshly discovered.
		recent, err := e.Store.FindRecentAlerts(ctx, r.SiteName, notifier.TypeSSLUntrusted, now.Add(-7*24*time.Hour))
		if err != nil {
			return nil, err
		}
		if len(recent) == 0 {
			kind := "untrusted"
			if r.CertSelfSigned {
				kind = "self-signed"
			}
			return []alertWithMeta{{
				Alert: notifier.Alert{
					SiteName: r.SiteName, Type: notifier.TypeSSLUntrusted, Severity: notifier.SeverityWarning,
					Title:   "SSL cert " + kind,
					Message: fmt.Sprintf("%s cert is %s.", r.SiteName, kind),
					Details: map[string]any{"issuer": r.CertIssuer, "not_after": r.CertNotAfter.Format(time.RFC3339)},
					At:      now,
				},
				CertSerial: r.CertSerial,
			}}, nil
		}
		return nil, nil
	}

	if r.CertNotAfter.IsZero() {
		return nil, nil
	}

	threshold := currentThresholdBand(r.DaysUntilCertExpiry, e.SSLWarnDays)
	if threshold == 0 {
		return nil, nil
	}

	// Dedup: have we already alerted for this site at this threshold for this
	// cert serial in the last 90 days?
	recent, err := e.Store.FindRecentAlerts(ctx, r.SiteName, notifier.TypeSSLExpiring, now.Add(-90*24*time.Hour))
	if err != nil {
		return nil, err
	}
	for _, a := range recent {
		if a.Threshold == threshold && a.CertSerial == r.CertSerial && a.Status == "sent" {
			return nil, nil
		}
	}

	sev := notifier.SeverityWarning
	if threshold <= 7 {
		sev = notifier.SeverityCritical
	}
	return []alertWithMeta{{
		Alert: notifier.Alert{
			SiteName: r.SiteName, Type: notifier.TypeSSLExpiring, Severity: sev,
			Title:   fmt.Sprintf("SSL cert expires in %d days", threshold),
			Message: fmt.Sprintf("%s cert expires on %s (%d days).", r.SiteName, r.CertNotAfter.Format("2006-01-02"), r.DaysUntilCertExpiry),
			Details: map[string]any{
				"days_left": r.DaysUntilCertExpiry,
				"not_after": r.CertNotAfter.Format(time.RFC3339),
				"issuer":    r.CertIssuer,
				"serial":    r.CertSerial,
			},
			At: now,
		},
		Threshold:  threshold,
		CertSerial: r.CertSerial,
	}}, nil
}

func (e *Engine) decideDomain(ctx context.Context, prev storage.SiteState, r checker.CheckResult, now time.Time) ([]alertWithMeta, error) {
	if !r.DomainLookupOK {
		// Persistent lookup failure → degraded monitoring (>3 days since last OK).
		dc, _, err := e.Store.GetDomainCache(ctx, r.SiteName)
		if err != nil {
			return nil, err
		}
		if dc.LastOkAt.IsZero() || now.Sub(dc.LastOkAt) <= 3*24*time.Hour {
			return nil, nil
		}
		// Dedup: only alert once per 7 days.
		recent, err := e.Store.FindRecentAlerts(ctx, r.SiteName, notifier.TypeDegradedMonitor, now.Add(-7*24*time.Hour))
		if err != nil {
			return nil, err
		}
		if len(recent) > 0 {
			return nil, nil
		}
		return []alertWithMeta{{Alert: notifier.Alert{
			SiteName: r.SiteName, Type: notifier.TypeDegradedMonitor, Severity: notifier.SeverityWarning,
			Title:   "Domain lookup degraded",
			Message: fmt.Sprintf("%s domain lookups failing for >3 days; can't verify expiry.", r.SiteName),
			Details: map[string]any{"last_ok_at": dc.LastOkAt.Format(time.RFC3339), "last_error": dc.Error},
			At:      now,
		}}}, nil
	}

	if r.DomainExpiry.IsZero() {
		return nil, nil
	}
	threshold := currentThresholdBand(r.DaysUntilDomainExpiry, e.DomainWarnDays)
	if threshold == 0 {
		return nil, nil
	}

	// Dedup keyed on threshold + expiry timestamp (so renewal re-arms thresholds).
	recent, err := e.Store.FindRecentAlerts(ctx, r.SiteName, notifier.TypeDomainExpiring, now.Add(-365*24*time.Hour))
	if err != nil {
		return nil, err
	}
	expiryKey := r.DomainExpiry.UTC().Format(time.RFC3339)
	for _, a := range recent {
		if a.Threshold == threshold && a.CertSerial == expiryKey && a.Status == "sent" {
			return nil, nil
		}
	}

	sev := notifier.SeverityWarning
	if threshold <= 7 {
		sev = notifier.SeverityCritical
	}
	return []alertWithMeta{{
		Alert: notifier.Alert{
			SiteName: r.SiteName, Type: notifier.TypeDomainExpiring, Severity: sev,
			Title:   fmt.Sprintf("Domain expires in %d days", threshold),
			Message: fmt.Sprintf("%s domain expires on %s (%d days).", r.SiteName, r.DomainExpiry.Format("2006-01-02"), r.DaysUntilDomainExpiry),
			Details: map[string]any{
				"days_left":  r.DaysUntilDomainExpiry,
				"expires_at": r.DomainExpiry.Format(time.RFC3339),
			},
			At: now,
		},
		Threshold:  threshold,
		CertSerial: expiryKey, // reuses cert_serial column as a generic dedup key
	}}, nil
}

// currentThresholdBand returns the smallest threshold that daysLeft is at or
// below — the band the cert/domain has currently crossed into. Returns 0 if
// daysLeft is greater than every threshold (i.e. nothing crossed yet).
//
// Example with thresholds [30, 14, 7, 1]:
//
//	days=31 → 0   (no threshold crossed)
//	days=30 → 30  (just crossed 30)
//	days=15 → 30  (still in the 30-band, not yet at 14)
//	days=14 → 14  (just crossed 14)
//	days=7  → 7
//
// This is the band we dedup on: an alert fires once per (band, cert serial)
// pair, so each band transition produces exactly one alert.
func currentThresholdBand(daysLeft int, thresholds []int) int {
	if len(thresholds) == 0 {
		return 0
	}
	sorted := append([]int(nil), thresholds...)
	sort.Ints(sorted)
	for _, t := range sorted {
		if daysLeft <= t {
			return t
		}
	}
	return 0
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}

// AlertsForDispatch returns the dispatch-ready alerts.
func (o Outcome) AlertsForDispatch() []DispatchableAlert {
	out := make([]DispatchableAlert, 0, len(o.Alerts))
	for _, a := range o.Alerts {
		out = append(out, DispatchableAlert{
			Alert:      a.Alert,
			Threshold:  a.Threshold,
			CertSerial: a.CertSerial,
		})
	}
	return out
}

// DispatchableAlert is the public projection of an internal alert with the
// metadata the dispatcher needs for the alert log.
type DispatchableAlert struct {
	Alert      notifier.Alert
	Threshold  int
	CertSerial string
}
