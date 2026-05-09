package checker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juusomikkonen/domainturva/internal/config"
)

func mkSite(url string) config.Site {
	return config.Site{
		Name:         "test",
		URL:          url,
		ExpectStatus: []int{200},
		Timeout:      2 * time.Second,
		Interval:     30 * time.Second,
		Retries:      0,
	}
}

func TestHTTPChecker_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Welcome"))
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	r := c.Check(context.Background(), mkSite(srv.URL))
	if r.Status != StatusUp {
		t.Fatalf("expected up, got %s (err=%s)", r.Status, r.Error)
	}
	if r.StatusCode != 200 {
		t.Fatalf("status code: %d", r.StatusCode)
	}
}

func TestHTTPChecker_StatusMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.Interval = 200 * time.Millisecond
	r := c.Check(context.Background(), s)
	if r.Status != StatusDown {
		t.Fatalf("expected down, got %s", r.Status)
	}
	if r.StatusCode != 500 {
		t.Fatalf("status code: %d", r.StatusCode)
	}
}

func TestHTTPChecker_BodyMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nope"))
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.ExpectBodyContains = "Welcome"
	r := c.Check(context.Background(), s)
	if r.Status != StatusDown {
		t.Fatalf("expected down")
	}
}

func TestHTTPChecker_BodyMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello Welcome world"))
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.ExpectBodyContains = "Welcome"
	r := c.Check(context.Background(), s)
	if r.Status != StatusUp {
		t.Fatalf("expected up, got %s (%s)", r.Status, r.Error)
	}
}

func TestHTTPChecker_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.Timeout = 100 * time.Millisecond
	r := c.Check(context.Background(), s)
	if r.Status != StatusDown {
		t.Fatalf("expected down on timeout, got %s", r.Status)
	}
}

func TestHTTPChecker_RedirectLoop(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	r := c.Check(context.Background(), mkSite(srv.URL))
	if r.Status != StatusDown {
		t.Fatalf("expected down on redirect loop, got %s", r.Status)
	}
}

func TestHTTPChecker_RetriesThenSucceed(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.Retries = 3
	r := c.Check(context.Background(), s)
	if r.Status != StatusUp {
		t.Fatalf("expected eventual up, got %s (%s)", r.Status, r.Error)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("expected 3 attempts, got %d", hits)
	}
}

func TestHTTPChecker_RetriesExhausted(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	c := NewHTTPChecker()
	c.RetryBackoff = 10 * time.Millisecond
	s := mkSite(srv.URL)
	s.Retries = 2
	r := c.Check(context.Background(), s)
	if r.Status != StatusDown {
		t.Fatalf("expected down")
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("expected 3 attempts, got %d", hits)
	}
}
