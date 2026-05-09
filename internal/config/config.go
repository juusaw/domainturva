// Package config loads, expands, and validates the YAML configuration.
package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CheckInterval       time.Duration `yaml:"check_interval"`
	SSLCheckInterval    time.Duration `yaml:"ssl_check_interval"`
	DomainCheckInterval time.Duration `yaml:"domain_check_interval"`

	Sites []Site `yaml:"sites"`

	SSLWarnDays    []int `yaml:"ssl_warn_days"`
	DomainWarnDays []int `yaml:"domain_warn_days"`

	Notifiers []Notifier `yaml:"notifiers"`
	Routing   Routing    `yaml:"routing"`
	Storage   Storage    `yaml:"storage"`
}

type Site struct {
	Name               string        `yaml:"name"`
	URL                string        `yaml:"url"`
	ExpectStatus       IntList       `yaml:"expect_status"`
	ExpectBodyContains string        `yaml:"expect_body_contains"`
	CheckSSL           bool          `yaml:"check_ssl"`
	CheckDomain        bool          `yaml:"check_domain"`
	Interval           time.Duration `yaml:"interval"`
	Timeout            time.Duration `yaml:"timeout"`
	Retries            int           `yaml:"retries"`
}

type Notifier struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Webhook string `yaml:"webhook"`

	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
}

type Routing struct {
	Default []string            `yaml:"-"`
	PerType map[string][]string `yaml:"-"`
}

type Storage struct {
	Path string `yaml:"path"`
}

// IntList accepts either a single int or a YAML sequence of ints.
type IntList []int

func (l *IntList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var v int
		if err := node.Decode(&v); err != nil {
			return err
		}
		*l = []int{v}
	case yaml.SequenceNode:
		var v []int
		if err := node.Decode(&v); err != nil {
			return err
		}
		*l = v
	default:
		return fmt.Errorf("expect_status: expected int or list of ints")
	}
	return nil
}

func (r *Routing) UnmarshalYAML(node *yaml.Node) error {
	raw := map[string][]string{}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	r.PerType = map[string][]string{}
	for k, v := range raw {
		if k == "default" {
			r.Default = v
		} else {
			r.PerType[k] = v
		}
	}
	return nil
}

// NotifiersFor returns the notifier names that should receive an alert of the
// given type. Falls back to Default if no specific routing is configured.
func (r Routing) NotifiersFor(alertType string) []string {
	if v, ok := r.PerType[alertType]; ok {
		return v
	}
	return r.Default
}

// Notifier types we recognise.
const (
	NotifierSlack = "slack"
	NotifierSMTP  = "smtp"
)

// Default values applied when fields are zero.
var defaults = struct {
	CheckInterval       time.Duration
	SSLCheckInterval    time.Duration
	DomainCheckInterval time.Duration
	SiteTimeout         time.Duration
	SiteRetries         int
	ExpectStatus        int
	StoragePath         string
}{
	CheckInterval:       60 * time.Second,
	SSLCheckInterval:    12 * time.Hour,
	DomainCheckInterval: 24 * time.Hour,
	SiteTimeout:         10 * time.Second,
	SiteRetries:         2,
	ExpectStatus:        200,
	StoragePath:         "./domainturva.db",
}

// Load reads a YAML file, expands ${VAR} env references, applies defaults,
// and validates the result.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded, err := expandEnv(string(raw))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal([]byte(expanded), &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(s string) (string, error) {
	var missing []string
	out := envRe.ReplaceAllStringFunc(s, func(m string) string {
		name := envRe.FindStringSubmatch(m)[1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return m
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("config references undefined env vars: %v", missing)
	}
	return out, nil
}

func (c *Config) applyDefaults() {
	if c.CheckInterval == 0 {
		c.CheckInterval = defaults.CheckInterval
	}
	if c.SSLCheckInterval == 0 {
		c.SSLCheckInterval = defaults.SSLCheckInterval
	}
	if c.DomainCheckInterval == 0 {
		c.DomainCheckInterval = defaults.DomainCheckInterval
	}
	if c.Storage.Path == "" {
		c.Storage.Path = defaults.StoragePath
	}
	for i := range c.Sites {
		s := &c.Sites[i]
		if s.Interval == 0 {
			s.Interval = c.CheckInterval
		}
		if s.Timeout == 0 {
			s.Timeout = defaults.SiteTimeout
		}
		if len(s.ExpectStatus) == 0 {
			s.ExpectStatus = []int{defaults.ExpectStatus}
		}
		if s.Retries == 0 {
			s.Retries = defaults.SiteRetries
		}
	}
}

func (c *Config) Validate() error {
	if len(c.Sites) == 0 {
		return fmt.Errorf("no sites configured")
	}
	seenSite := map[string]bool{}
	for i, s := range c.Sites {
		if s.Name == "" {
			return fmt.Errorf("sites[%d]: name is required", i)
		}
		if seenSite[s.Name] {
			return fmt.Errorf("sites[%d]: duplicate site name %q", i, s.Name)
		}
		seenSite[s.Name] = true
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("sites[%s]: invalid url %q", s.Name, s.URL)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("sites[%s]: url scheme must be http or https", s.Name)
		}
		if s.Interval < time.Second {
			return fmt.Errorf("sites[%s]: interval must be >= 1s", s.Name)
		}
		if s.Timeout < time.Second {
			return fmt.Errorf("sites[%s]: timeout must be >= 1s", s.Name)
		}
		if s.Retries < 0 {
			return fmt.Errorf("sites[%s]: retries must be >= 0", s.Name)
		}
		if s.CheckSSL && u.Scheme != "https" {
			return fmt.Errorf("sites[%s]: check_ssl requires https url", s.Name)
		}
	}

	seenNotif := map[string]bool{}
	for i, n := range c.Notifiers {
		if n.Name == "" {
			return fmt.Errorf("notifiers[%d]: name is required", i)
		}
		if seenNotif[n.Name] {
			return fmt.Errorf("notifiers[%d]: duplicate notifier name %q", i, n.Name)
		}
		seenNotif[n.Name] = true
		switch n.Type {
		case NotifierSlack:
			if n.Webhook == "" {
				return fmt.Errorf("notifiers[%s]: slack notifier requires webhook", n.Name)
			}
		case NotifierSMTP:
			if n.Host == "" || n.Port == 0 || n.From == "" || len(n.To) == 0 {
				return fmt.Errorf("notifiers[%s]: smtp notifier requires host, port, from, to", n.Name)
			}
		default:
			return fmt.Errorf("notifiers[%s]: unknown type %q", n.Name, n.Type)
		}
	}

	check := func(group string, names []string) error {
		for _, n := range names {
			if !seenNotif[n] {
				return fmt.Errorf("routing.%s references unknown notifier %q", group, n)
			}
		}
		return nil
	}
	if err := check("default", c.Routing.Default); err != nil {
		return err
	}
	for k, names := range c.Routing.PerType {
		if err := check(k, names); err != nil {
			return err
		}
	}
	if len(c.Routing.Default) == 0 && len(c.Routing.PerType) == 0 && len(c.Notifiers) > 0 {
		return fmt.Errorf("routing: no default or per-type routes configured")
	}

	for _, d := range c.SSLWarnDays {
		if d <= 0 {
			return fmt.Errorf("ssl_warn_days: values must be > 0")
		}
	}
	for _, d := range c.DomainWarnDays {
		if d <= 0 {
			return fmt.Errorf("domain_warn_days: values must be > 0")
		}
	}
	return nil
}
