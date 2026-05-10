package checker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/openrdap/rdap"

	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// errTransport always errors. Used to make RDAP requests fail fast in tests
// that exercise the WHOIS fallback / failure paths.
type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("rdap unavailable in test")
}

func failingRDAPClient() *rdap.Client {
	return &rdap.Client{HTTP: &http.Client{Transport: errTransport{}, Timeout: time.Second}}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"https://example.com":         "example.com",
		"https://www.example.com":     "example.com",
		"https://sub.example.com":     "sub.example.com",
		"http://foo.bar.co.uk:8080/x": "foo.bar.co.uk",
	}
	for in, want := range cases {
		got, err := registrableDomain(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
	if _, err := registrableDomain("://not a url"); err == nil {
		t.Error("expected error for invalid url")
	}
}

func TestDomainChecker_WhoisTimeoutHonored(t *testing.T) {
	// Fake WhoisQuery hangs until ctx fires — verifies the per-call timeout
	// actually short-circuits rather than waiting for the underlying TCP.
	c := &DomainChecker{
		Storage:      storage.NewMemory(),
		Logger:       discardLogger(),
		CacheTTL:     6 * time.Hour,
		RDAPTimeout:  10 * time.Millisecond,
		WhoisTimeout: 50 * time.Millisecond,
		RDAP:         failingRDAPClient(),
		Now:          time.Now,
		WhoisQuery: func(ctx context.Context, _ string) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		},
	}
	start := time.Now()
	_, err := c.lookupWhois(context.Background(), "example.com")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("timeout did not fire promptly: %s", elapsed)
	}
}

func TestDomainChecker_CacheHit(t *testing.T) {
	mem := storage.NewMemory()
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(60 * 24 * time.Hour)
	mem.UpsertDomainCache(context.Background(), storage.DomainCache{
		SiteName:     "a",
		ExpiresAt:    expiry,
		LastLookupAt: now.Add(-1 * time.Hour),
		LastOkAt:     now.Add(-1 * time.Hour),
		Source:       "rdap",
	})

	whoisCalls := 0
	c := &DomainChecker{
		Storage:      mem,
		Logger:       discardLogger(),
		CacheTTL:     6 * time.Hour,
		RDAPTimeout:  10 * time.Millisecond,
		WhoisTimeout: 10 * time.Millisecond,
		RDAP:         failingRDAPClient(),
		Now:          func() time.Time { return now },
		WhoisQuery: func(_ context.Context, _ string) (string, error) {
			whoisCalls++
			return "", errors.New("should not be called on cache hit")
		},
	}
	r := c.Check(context.Background(), config.Site{Name: "a", URL: "https://example.com"})
	if !r.DomainLookupOK {
		t.Fatalf("expected DomainLookupOK true: %+v", r)
	}
	if !r.DomainExpiry.Equal(expiry) {
		t.Fatalf("expected expiry %s, got %s", expiry, r.DomainExpiry)
	}
	if whoisCalls != 0 {
		t.Fatalf("whois should not be invoked on cache hit, was called %d times", whoisCalls)
	}
}

func TestDomainChecker_LookupFailKeepsLastOkAt(t *testing.T) {
	mem := storage.NewMemory()
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	priorOk := now.Add(-7 * 24 * time.Hour)
	mem.UpsertDomainCache(context.Background(), storage.DomainCache{
		SiteName:     "a",
		LastLookupAt: priorOk,
		LastOkAt:     priorOk,
		ExpiresAt:    now.Add(30 * 24 * time.Hour),
		Source:       "rdap",
	})

	c := &DomainChecker{
		Storage:      mem,
		Logger:       discardLogger(),
		CacheTTL:     6 * time.Hour, // cache is 7 days old → forces re-lookup
		RDAPTimeout:  100 * time.Millisecond,
		WhoisTimeout: 100 * time.Millisecond,
		RDAP:         failingRDAPClient(),
		Now:          func() time.Time { return now },
		WhoisQuery: func(context.Context, string) (string, error) {
			return "", errors.New("whois unreachable")
		},
	}
	r := c.Check(context.Background(), config.Site{Name: "a", URL: "https://example.com"})
	if r.DomainLookupOK {
		t.Fatalf("expected DomainLookupOK=false after both lookups failed")
	}

	dc, ok, _ := mem.GetDomainCache(context.Background(), "a")
	if !ok {
		t.Fatal("cache row missing")
	}
	if !dc.LastOkAt.Equal(priorOk) {
		t.Fatalf("LastOkAt should be preserved across failures, got %s want %s", dc.LastOkAt, priorOk)
	}
	if !dc.LastLookupAt.Equal(now) {
		t.Fatalf("LastLookupAt should advance to now, got %s", dc.LastLookupAt)
	}
}
