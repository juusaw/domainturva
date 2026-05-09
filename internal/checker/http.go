package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/juusomikkonen/domainturva/internal/config"
)

// HTTPChecker runs a single HTTP check, applying retries.
type HTTPChecker struct {
	Client       *http.Client
	RetryBackoff time.Duration
	Now          func() time.Time
}

// NewHTTPChecker returns a checker that uses a single shared http.Client.
// Per-call timeouts are enforced via context.
func NewHTTPChecker() *HTTPChecker {
	return &HTTPChecker{
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects (>5)")
				}
				return nil
			},
		},
		RetryBackoff: 2 * time.Second,
		Now:          time.Now,
	}
}

// Read up to this many bytes when checking expect_body_contains.
const maxBodyBytes = 1 << 20 // 1 MiB

// Check performs the HTTP check for site s. It applies s.Retries+1 attempts
// total and only reports a failure after all attempts fail. Total elapsed time
// is bounded so retries cannot exceed the next check interval.
func (c *HTTPChecker) Check(ctx context.Context, s config.Site) CheckResult {
	deadline := c.Now().Add(s.Interval - 100*time.Millisecond)
	attempts := s.Retries + 1
	var last CheckResult
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Don't sleep past the deadline.
			sleepUntil := c.Now().Add(c.RetryBackoff)
			if sleepUntil.After(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return c.errorResult(s, ctx.Err())
			case <-time.After(c.RetryBackoff):
			}
		}
		last = c.attempt(ctx, s)
		if last.Status == StatusUp {
			return last
		}
	}
	return last
}

func (c *HTTPChecker) attempt(ctx context.Context, s config.Site) CheckResult {
	cctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	var tlsStart, tlsEnd time.Time
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { tlsStart = c.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			tlsEnd = c.Now()
		},
	}
	cctx = httptrace.WithClientTrace(cctx, trace)

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return c.errorResult(s, err)
	}
	req.Header.Set("User-Agent", "domainturva/1 (+https://github.com/juusomikkonen/domainturva)")

	start := c.Now()
	resp, err := c.Client.Do(req)
	if err != nil {
		return c.errorResult(s, err)
	}
	defer resp.Body.Close()

	r := CheckResult{
		SiteName:   s.Name,
		Type:       CheckHTTP,
		At:         start,
		StatusCode: resp.StatusCode,
		ResponseMS: c.Now().Sub(start).Milliseconds(),
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		r.TLSHandshakeMS = tlsEnd.Sub(tlsStart).Milliseconds()
	}

	statusOK := false
	for _, want := range s.ExpectStatus {
		if resp.StatusCode == want {
			statusOK = true
			break
		}
	}
	if !statusOK {
		r.Status = StatusDown
		r.Error = fmt.Sprintf("unexpected status %d (want %v)", resp.StatusCode, []int(s.ExpectStatus))
		return r
	}

	if s.ExpectBodyContains != "" {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			r.Status = StatusDown
			r.Error = "read body: " + err.Error()
			return r
		}
		if !strings.Contains(string(body), s.ExpectBodyContains) {
			r.Status = StatusDown
			r.Error = fmt.Sprintf("body did not contain %q", s.ExpectBodyContains)
			return r
		}
	}

	r.Status = StatusUp
	return r
}

func (c *HTTPChecker) errorResult(s config.Site, err error) CheckResult {
	return CheckResult{
		SiteName: s.Name,
		Type:     CheckHTTP,
		Status:   StatusDown,
		At:       c.Now(),
		Error:    err.Error(),
	}
}
