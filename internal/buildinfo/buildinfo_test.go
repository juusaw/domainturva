package buildinfo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserAgent_DefaultVersion(t *testing.T) {
	ua := UserAgent()
	if !strings.HasPrefix(ua, "domainturva/") {
		t.Fatalf("user agent missing prefix: %q", ua)
	}
}

func TestWrapTransport_SetsUA(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	c := &http.Client{Transport: WrapTransport(nil)}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if !strings.HasPrefix(seen, "domainturva/") {
		t.Fatalf("server saw UA %q, expected domainturva/...", seen)
	}
}

func TestWrapTransport_PreservesCallerUA(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	c := &http.Client{Transport: WrapTransport(nil)}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("User-Agent", "custom/1.0")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seen != "custom/1.0" {
		t.Fatalf("explicit UA was overwritten: got %q", seen)
	}
}
