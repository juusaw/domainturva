// domainturva is a self-hosted uptime monitor.
//
// Subcommands:
//
//	domainturva run        — start the monitor (default if none given)
//	domainturva check NAME — one-shot check of a single configured site
//	domainturva validate   — load+validate the config and exit
//	domainturva version    — print version info
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/juusomikkonen/domainturva/internal/alerting"
	"github.com/juusomikkonen/domainturva/internal/buildinfo"
	"github.com/juusomikkonen/domainturva/internal/checker"
	"github.com/juusomikkonen/domainturva/internal/config"
	"github.com/juusomikkonen/domainturva/internal/notifier"
	"github.com/juusomikkonen/domainturva/internal/scheduler"
	"github.com/juusomikkonen/domainturva/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		runCmd(os.Args[1:])
		return
	}
	switch os.Args[1] {
	case "run":
		runCmd(os.Args[2:])
	case "check":
		checkCmd(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	case "version":
		fmt.Println(versionString())
	case "-h", "--help", "help":
		usage()
	default:
		// Treat any unknown first arg as a flag for `run`.
		runCmd(os.Args[1:])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `domainturva — uptime monitor

Usage:
  domainturva [run]                    start the monitor
  domainturva check <site-name>        one-shot check
  domainturva validate                 validate config and exit
  domainturva version                  print version info

Flags (run / check / validate):
  --config <path>      config file path (default ./config.yaml)
  --log-format <fmt>   json | text (default json)
  --log-level <lvl>    debug | info | warn | error (default info)
`)
}

type commonFlags struct {
	configPath string
	logFormat  string
	logLevel   string
}

func parseCommon(args []string, fs *flag.FlagSet) (commonFlags, []string) {
	var c commonFlags
	fs.StringVar(&c.configPath, "config", "./config.yaml", "path to config file")
	fs.StringVar(&c.logFormat, "log-format", "json", "log format: json|text")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug|info|warn|error")
	_ = fs.Parse(args)
	return c, fs.Args()
}

func mkLogger(c commonFlags) *slog.Logger {
	var level slog.Level
	switch c.logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if c.logFormat == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cf, _ := parseCommon(args, fs)
	logger := mkLogger(cf)

	cfg, err := config.Load(cf.configPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	store, err := storage.OpenSQLite(cfg.Storage.Path)
	if err != nil {
		logger.Error("open storage failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	notifiers := buildNotifiers(cfg, logger)
	dispatcher := notifier.NewDispatcher(notifiers, store, logger)

	engine := &alerting.Engine{
		Store:          store,
		SSLWarnDays:    cfg.SSLWarnDays,
		DomainWarnDays: cfg.DomainWarnDays,
	}

	sched := &scheduler.Scheduler{
		Cfg:        cfg,
		HTTP:       checker.NewHTTPChecker(),
		SSL:        checker.NewSSLChecker(),
		Domain:     checker.NewDomainChecker(store, logger),
		Storage:    store,
		Engine:     engine,
		Dispatcher: dispatcher,
		Logger:     logger,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("domainturva starting",
		"version", versionString(), "sites", len(cfg.Sites), "notifiers", len(notifiers))
	sched.Run(ctx)
	logger.Info("domainturva stopped")
}

func checkCmd(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cf, rest := parseCommon(args, fs)
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: domainturva check <site-name>")
		os.Exit(2)
	}
	siteName := rest[0]
	logger := mkLogger(cf)

	cfg, err := config.Load(cf.configPath)
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}
	var site *config.Site
	for i := range cfg.Sites {
		if cfg.Sites[i].Name == siteName {
			site = &cfg.Sites[i]
			break
		}
	}
	if site == nil {
		fmt.Fprintf(os.Stderr, "no site named %q in config\n", siteName)
		os.Exit(1)
	}

	store := storage.NewMemory()
	httpC := checker.NewHTTPChecker()
	sslC := checker.NewSSLChecker()
	domC := checker.NewDomainChecker(store, logger)
	ctx := context.Background()

	r := httpC.Check(ctx, *site)
	fmt.Printf("HTTP    %s status=%s code=%d response_ms=%d err=%q\n",
		site.Name, r.Status, r.StatusCode, r.ResponseMS, r.Error)

	if site.CheckSSL {
		s := sslC.Check(ctx, *site)
		fmt.Printf("SSL     %s status=%s days=%d not_after=%s issuer=%s untrusted=%v self_signed=%v err=%q\n",
			site.Name, s.Status, s.DaysUntilCertExpiry, s.CertNotAfter.Format("2006-01-02"),
			s.CertIssuer, s.CertUntrusted, s.CertSelfSigned, s.Error)
	}
	if site.CheckDomain {
		d := domC.Check(ctx, *site)
		fmt.Printf("DOMAIN  %s status=%s days=%d expires=%s ok=%v err=%q\n",
			site.Name, d.Status, d.DaysUntilDomainExpiry, d.DomainExpiry.Format("2006-01-02"),
			d.DomainLookupOK, d.Error)
	}

	if r.Status != checker.StatusUp {
		os.Exit(1)
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cf, _ := parseCommon(args, fs)
	if _, err := config.Load(cf.configPath); err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("config OK")
}

func buildNotifiers(cfg *config.Config, logger *slog.Logger) map[string]notifier.Notifier {
	out := make(map[string]notifier.Notifier, len(cfg.Notifiers))
	for _, n := range cfg.Notifiers {
		switch n.Type {
		case config.NotifierSlack:
			out[n.Name] = notifier.NewSlack(n.Name, n.Webhook)
		case config.NotifierSMTP:
			out[n.Name] = notifier.NewSMTP(n.Name, n.Host, n.Port, n.Username, n.Password, n.From, n.To)
		default:
			logger.Warn("unknown notifier type, skipping", "name", n.Name, "type", n.Type)
		}
	}
	return out
}

func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return buildinfo.Version
	}
	return fmt.Sprintf("%s (go %s)", buildinfo.Version, info.GoVersion)
}
