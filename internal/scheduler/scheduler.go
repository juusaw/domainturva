// Package scheduler owns the goroutines that drive periodic checks and the
// single consumer that processes their results.
package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/juusomikkonen/domainturva/internal/alerting"
	"github.com/juusomikkonen/domainturva/internal/checker"
	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/notifier"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

// HTTPRunner is what the scheduler needs from an HTTP checker.
type HTTPRunner interface {
	Check(ctx context.Context, s config.Site) checker.CheckResult
}

// SSLRunner produces an SSL CheckResult for a site.
type SSLRunner interface {
	Check(ctx context.Context, s config.Site) checker.CheckResult
}

// DomainRunner produces a Domain CheckResult for a site.
type DomainRunner interface {
	Check(ctx context.Context, s config.Site) checker.CheckResult
}

type Scheduler struct {
	Cfg        *config.Config
	HTTP       HTTPRunner
	SSL        SSLRunner
	Domain     DomainRunner
	Storage    storage.Storage
	Engine     *alerting.Engine
	Dispatcher *notifier.Dispatcher
	Logger     *slog.Logger
}

// Run blocks until ctx is cancelled, returning when all goroutines have exited.
func (s *Scheduler) Run(ctx context.Context) {
	type job struct {
		site     config.Site
		typ      checker.CheckType
		interval time.Duration
	}
	var jobs []job
	for _, site := range s.Cfg.Sites {
		jobs = append(jobs, job{site, checker.CheckHTTP, site.Interval})
		if site.CheckSSL && s.SSL != nil {
			jobs = append(jobs, job{site, checker.CheckSSL, s.Cfg.SSLCheckInterval})
		}
		if site.CheckDomain && s.Domain != nil {
			jobs = append(jobs, job{site, checker.CheckDomain, s.Cfg.DomainCheckInterval})
		}
	}

	results := make(chan checker.CheckResult, max(4*len(jobs), 16))

	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			s.runWorker(ctx, j.site, j.typ, j.interval, results)
		}(j)
	}

	// Consumer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.consume(ctx, results)
	}()

	<-ctx.Done()
	wg.Wait()
}

func (s *Scheduler) runWorker(ctx context.Context, site config.Site, typ checker.CheckType, interval time.Duration, out chan<- checker.CheckResult) {
	// Jittered first delay (0..interval) to avoid thundering herd.
	jitter := jitterDuration(interval)
	timer := time.NewTimer(jitter)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		s.runOne(ctx, site, typ, out)
		timer.Reset(interval)
	}
}

func (s *Scheduler) runOne(ctx context.Context, site config.Site, typ checker.CheckType, out chan<- checker.CheckResult) {
	var r checker.CheckResult
	switch typ {
	case checker.CheckHTTP:
		r = s.HTTP.Check(ctx, site)
	case checker.CheckSSL:
		r = s.SSL.Check(ctx, site)
	case checker.CheckDomain:
		r = s.Domain.Check(ctx, site)
	default:
		return
	}
	select {
	case out <- r:
	case <-ctx.Done():
	}
}

func (s *Scheduler) consume(ctx context.Context, in <-chan checker.CheckResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case r, ok := <-in:
			if !ok {
				return
			}
			s.process(ctx, r)
		}
	}
}

func (s *Scheduler) process(ctx context.Context, r checker.CheckResult) {
	site := s.lookupSite(r.SiteName)
	retries := 1
	if site != nil {
		retries = site.Retries + 1
	}
	out, err := s.Engine.Process(ctx, r, retries)
	if err != nil {
		s.Logger.Error("alerting process failed", "site", r.SiteName, "err", err)
		return
	}
	if err := s.Storage.UpsertSiteState(ctx, out.NewState); err != nil {
		s.Logger.Error("upsert state failed", "site", r.SiteName, "err", err)
	}
	s.logResult(r, out.NewState)

	for _, da := range out.AlertsForDispatch() {
		recipients := s.Cfg.Routing.NotifiersFor(da.Alert.Type)
		s.Dispatcher.Dispatch(ctx, da.Alert, recipients, storage.AlertRecord{
			Threshold:  da.Threshold,
			CertSerial: da.CertSerial,
		})
	}
}

func (s *Scheduler) lookupSite(name string) *config.Site {
	for i := range s.Cfg.Sites {
		if s.Cfg.Sites[i].Name == name {
			return &s.Cfg.Sites[i]
		}
	}
	return nil
}

func (s *Scheduler) logResult(r checker.CheckResult, st storage.SiteState) {
	attrs := []any{
		"site", r.SiteName,
		"type", r.Type,
		"status", r.Status,
		"state", st.Status,
	}
	if r.StatusCode != 0 {
		attrs = append(attrs, "code", r.StatusCode, "ms", r.ResponseMS)
	}
	if r.DaysUntilCertExpiry != 0 {
		attrs = append(attrs, "cert_days", r.DaysUntilCertExpiry)
	}
	if r.DaysUntilDomainExpiry != 0 {
		attrs = append(attrs, "domain_days", r.DaysUntilDomainExpiry)
	}
	if r.Error != "" {
		attrs = append(attrs, "err", r.Error)
	}
	if r.Status == checker.StatusUp {
		s.Logger.Debug("check ok", attrs...)
	} else {
		s.Logger.Info("check result", attrs...)
	}
}

func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	n := int64(binary.BigEndian.Uint64(b[:]) & 0x7fffffffffffffff)
	return time.Duration(n % int64(d))
}
