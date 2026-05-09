package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_HappyPath(t *testing.T) {
	t.Setenv("WEBHOOK", "https://hooks.example.com/abc")
	path := writeConfig(t, `
check_interval: 60s
sites:
  - name: example
    url: https://example.com
    expect_status: 200
    interval: 30s
    timeout: 10s
notifiers:
  - name: ops
    type: slack
    webhook: ${WEBHOOK}
routing:
  default: [ops]
storage:
  path: ./test.db
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Sites) != 1 || c.Sites[0].Name != "example" {
		t.Fatalf("unexpected sites: %+v", c.Sites)
	}
	if c.Notifiers[0].Webhook != "https://hooks.example.com/abc" {
		t.Fatalf("env not expanded: %q", c.Notifiers[0].Webhook)
	}
	if c.Sites[0].Interval != 30*time.Second {
		t.Fatalf("interval not parsed")
	}
	if c.Routing.NotifiersFor("default")[0] != "ops" {
		t.Fatalf("routing default lookup failed")
	}
}

func TestLoad_MissingEnv(t *testing.T) {
	path := writeConfig(t, `
sites:
  - name: example
    url: https://example.com
notifiers:
  - name: ops
    type: slack
    webhook: ${MISSING_VAR}
routing:
  default: [ops]
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "MISSING_VAR") {
		t.Fatalf("expected missing env error, got %v", err)
	}
}

func TestLoad_ExpectStatusVariants(t *testing.T) {
	path := writeConfig(t, `
sites:
  - name: a
    url: https://a.example
    expect_status: [200, 301]
notifiers:
  - name: ops
    type: slack
    webhook: x
routing:
  default: [ops]
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Sites[0].ExpectStatus) != 2 {
		t.Fatalf("expected 2 statuses, got %v", c.Sites[0].ExpectStatus)
	}
}

func TestValidate_Errors(t *testing.T) {
	cases := map[string]string{
		"no sites": `
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [ops]}
`,
		"duplicate site": `
sites:
  - {name: a, url: "https://a.example"}
  - {name: a, url: "https://b.example"}
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [ops]}
`,
		"bad url": `
sites:
  - {name: a, url: "not-a-url"}
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [ops]}
`,
		"unknown notifier in routing": `
sites:
  - {name: a, url: "https://a.example"}
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [missing]}
`,
		"interval too small": `
sites:
  - {name: a, url: "https://a.example", interval: 100ms}
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [ops]}
`,
		"check_ssl on http": `
sites:
  - {name: a, url: "http://a.example", check_ssl: true}
notifiers: [{name: ops, type: slack, webhook: x}]
routing: {default: [ops]}
`,
		"unknown notifier type": `
sites:
  - {name: a, url: "https://a.example"}
notifiers: [{name: ops, type: pager, webhook: x}]
routing: {default: [ops]}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, body)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}
