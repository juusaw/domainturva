// Package buildinfo holds compile-time build metadata that other packages need
// to read (notably the user-agent for outbound requests). Version is set via
// -ldflags at build time.
package buildinfo

import (
	"fmt"
	"net/http"
)

// Version is overwritten at build time via -ldflags="-X .../buildinfo.Version=...".
var Version = "dev"

// UserAgent returns the User-Agent string sent on outbound HTTP requests.
func UserAgent() string {
	return fmt.Sprintf("domainturva/%s (+https://github.com/juusomikkonen/domainturva)", Version)
}

// WrapTransport returns a RoundTripper that sets the domainturva user-agent
// on every request that doesn't already have one. Pass nil to wrap
// http.DefaultTransport.
func WrapTransport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &uaTransport{base: rt, ua: UserAgent()}
}

type uaTransport struct {
	base http.RoundTripper
	ua   string
}

func (t *uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		// Clone request before mutating headers — RoundTrippers must not modify
		// the caller's request.
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.ua)
	}
	return t.base.RoundTrip(req)
}
