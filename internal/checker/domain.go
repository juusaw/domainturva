package checker

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	whois "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/openrdap/rdap"

	"github.com/juusomikkonen/domainturva/internal/buildinfo"
	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

// DomainChecker resolves domain expiry via RDAP first, falling back to WHOIS.
// Results are cached in storage so we don't re-hammer registrars.
type DomainChecker struct {
	Storage  storage.Storage
	Logger   *slog.Logger
	CacheTTL time.Duration
	RDAP     *rdap.Client

	// WhoisQuery is called when RDAP doesn't have the TLD. The default impl
	// runs whois.Whois (which is not context-aware) on a goroutine and lets
	// the caller bail out via ctx; the underlying TCP connection may linger
	// for a while if the upstream registrar hangs, but the checker won't.
	WhoisQuery func(ctx context.Context, domain string) (string, error)

	// Per-call timeouts. We bound RDAP and WHOIS independently because RDAP
	// is HTTP-based and usually fast, while WHOIS is line-based and can stall.
	RDAPTimeout  time.Duration
	WhoisTimeout time.Duration

	Now func() time.Time
}

func NewDomainChecker(store storage.Storage, log *slog.Logger) *DomainChecker {
	return &DomainChecker{
		Storage:  store,
		Logger:   log,
		CacheTTL: 6 * time.Hour,
		RDAP: &rdap.Client{
			HTTP: &http.Client{
				Transport: buildinfo.WrapTransport(nil),
				Timeout:   15 * time.Second,
			},
		},
		WhoisQuery:   defaultWhoisQuery,
		RDAPTimeout:  15 * time.Second,
		WhoisTimeout: 30 * time.Second,
		Now:          time.Now,
	}
}

// defaultWhoisQuery wraps whois.Whois so it honours ctx cancellation. The
// inner whois call is not cancelable; if ctx fires first we abandon the
// goroutine, which will exit when the underlying TCP read returns.
func defaultWhoisQuery(ctx context.Context, domain string) (string, error) {
	type result struct {
		raw string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		raw, err := whois.Whois(domain)
		ch <- result{raw, err}
	}()
	select {
	case r := <-ch:
		return r.raw, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *DomainChecker) Check(ctx context.Context, s config.Site) CheckResult {
	now := c.Now()
	r := CheckResult{SiteName: s.Name, Type: CheckDomain, At: now}

	domain, err := registrableDomain(s.URL)
	if err != nil {
		r.Status = StatusDown
		r.Error = err.Error()
		return r
	}

	cached, ok, _ := c.Storage.GetDomainCache(ctx, s.Name)
	if ok && now.Sub(cached.LastLookupAt) < c.CacheTTL && !cached.ExpiresAt.IsZero() {
		r.Status = StatusUp
		r.DomainExpiry = cached.ExpiresAt
		r.DaysUntilDomainExpiry = int(time.Until(cached.ExpiresAt).Hours() / 24)
		r.DomainLookupOK = true
		return r
	}

	expiry, source, lookupErr := c.lookup(ctx, domain)
	if lookupErr != nil {
		c.Logger.Warn("domain lookup failed", "site", s.Name, "domain", domain, "err", lookupErr)
		// Persist failure but keep last_ok_at if we have it.
		dc := cached
		dc.SiteName = s.Name
		dc.LastLookupAt = now
		dc.Error = lookupErr.Error()
		_ = c.Storage.UpsertDomainCache(ctx, dc)

		r.Status = StatusUp // we don't fail the site for flaky WHOIS
		r.DomainLookupOK = false
		r.Error = lookupErr.Error()
		return r
	}

	dc := storage.DomainCache{
		SiteName:     s.Name,
		ExpiresAt:    expiry,
		LastLookupAt: now,
		LastOkAt:     now,
		Source:       source,
	}
	_ = c.Storage.UpsertDomainCache(ctx, dc)

	r.Status = StatusUp
	r.DomainExpiry = expiry
	r.DaysUntilDomainExpiry = int(time.Until(expiry).Hours() / 24)
	r.DomainLookupOK = true
	return r
}

func (c *DomainChecker) lookup(ctx context.Context, domain string) (time.Time, string, error) {
	if t, err := c.lookupRDAP(ctx, domain); err == nil {
		return t, "rdap", nil
	} else {
		c.Logger.Debug("rdap miss", "domain", domain, "err", err)
	}
	if t, err := c.lookupWhois(ctx, domain); err == nil {
		return t, "whois", nil
	} else {
		return time.Time{}, "", fmt.Errorf("rdap and whois both failed: %w", err)
	}
}

func (c *DomainChecker) lookupRDAP(ctx context.Context, domain string) (time.Time, error) {
	cctx, cancel := context.WithTimeout(ctx, c.RDAPTimeout)
	defer cancel()
	req := &rdap.Request{Type: rdap.DomainRequest, Query: domain}
	req = req.WithContext(cctx)
	resp, err := c.RDAP.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	d, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return time.Time{}, fmt.Errorf("rdap: unexpected response type")
	}
	for _, ev := range d.Events {
		if strings.EqualFold(ev.Action, "expiration") {
			t, err := time.Parse(time.RFC3339, ev.Date)
			if err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("rdap: no expiration event")
}

func (c *DomainChecker) lookupWhois(ctx context.Context, domain string) (time.Time, error) {
	cctx, cancel := context.WithTimeout(ctx, c.WhoisTimeout)
	defer cancel()
	raw, err := c.WhoisQuery(cctx, domain)
	if err != nil {
		return time.Time{}, err
	}
	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return time.Time{}, err
	}
	if parsed.Domain == nil || parsed.Domain.ExpirationDate == "" {
		return time.Time{}, fmt.Errorf("whois: no expiration date")
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, parsed.Domain.ExpirationDate); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("whois: unparseable expiration %q", parsed.Domain.ExpirationDate)
}

// registrableDomain extracts the hostname (sans leading "www.") from a URL.
// We don't do public-suffix-list resolution for v1: RDAP/WHOIS servers
// typically resolve subdomains to their parent registered domain anyway, and
// adding a PSL dependency for marginal correctness isn't worth it yet.
func registrableDomain(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no hostname in url %q", rawURL)
	}
	return strings.TrimPrefix(host, "www."), nil
}
