# Build: Uptime Monitor in Go

## Goal

Build a self-hosted uptime monitoring tool in Go that ships as a single static binary. It should monitor HTTP(S) endpoints, check SSL certificate expiry, check domain registration expiry, and send notifications when anything goes wrong.

Before writing any code, read this whole spec, then ask me about anything ambiguous. After that, propose an implementation plan (file-by-file) and wait for me to approve it before you start coding.

## Hard constraints

- **Go 1.22+**, standard library first. Add dependencies only when they meaningfully reduce complexity.
- **CGO_ENABLED=0**. The output must cross-compile to a static Linux binary. This rules out `mattn/go-sqlite3` — use `modernc.org/sqlite` if SQLite is needed.
- **Single binary**. Embed any templates, migrations, or static assets via `embed.FS`.
- **Config-driven**, no hardcoded sites or secrets. Secrets come from env vars, referenced from the config via `${VAR_NAME}` syntax.
- **Graceful shutdown** on SIGINT/SIGTERM. In-flight checks should finish or time out cleanly.
- **Structured logging** via `log/slog` (stdlib). JSON output by default, text output if a `--log-format=text` flag is passed.

## Architecture

```
uptime/
  cmd/uptime/main.go          # entrypoint, signal handling, wiring
  internal/config/             # YAML parsing, env var expansion, validation
  internal/checker/
    http.go                    # HTTP uptime
    ssl.go                     # TLS cert expiry
    domain.go                  # WHOIS/RDAP domain expiry
    types.go                   # CheckResult, CheckType, Status enums
  internal/notifier/
    notifier.go                # Notifier interface
    slack.go
    discord.go
    smtp.go                    # optional, behind config
  internal/storage/
    storage.go                 # Storage interface
    sqlite.go                  # modernc.org/sqlite implementation
    migrations/                # embedded SQL migrations
  internal/scheduler/
    scheduler.go               # owns goroutines, tickers, fan-in channel
  internal/alerting/
    alerting.go                # state-transition logic, dedup, escalation
  config.example.yaml
  README.md
  Makefile                     # build, test, lint, run targets
```

If you have a strong reason to deviate from this layout, propose it in your plan rather than just doing it.

## Component specs

### Config (`internal/config`)

YAML format. Use `gopkg.in/yaml.v3`. Example:

```yaml
check_interval: 60s              # default if not specified per-site
ssl_check_interval: 12h
domain_check_interval: 24h

sites:
  - name: example
    url: https://example.com
    expect_status: 200           # default 200; can be a list
    expect_body_contains: "Welcome"   # optional substring match
    check_ssl: true
    check_domain: true
    interval: 30s                # override default
    timeout: 10s
    retries: 2                   # consecutive failures before alerting

ssl_warn_days: [30, 14, 7, 1]    # alert thresholds
domain_warn_days: [60, 30, 14, 7]

notifiers:
  - name: ops-slack
    type: slack
    webhook: ${SLACK_WEBHOOK_URL}
  - name: oncall-email
    type: smtp
    host: smtp.fastmail.com
    port: 587
    username: ${SMTP_USER}
    password: ${SMTP_PASS}
    from: alerts@example.com
    to: [me@example.com]

routing:
  default: [ops-slack]           # which notifiers receive which alerts
  domain: [ops-slack, oncall-email]   # override for specific check types

storage:
  path: ./uptime.db
```

Validate at load time: every `notifiers[].name` referenced in `routing` must exist; URLs must parse; intervals must be ≥1s; etc. Fail fast with a clear error message that points at the problem.

### HTTP checker (`internal/checker/http.go`)

- One `http.Client` per site (or a shared one with per-request context timeouts — your call, justify in the plan).
- Follow up to 5 redirects.
- Treat as **up** if: status matches `expect_status` AND (if specified) body contains `expect_body_contains`.
- Capture: status code, response time (ms), TLS handshake time if HTTPS, error string.
- Apply `retries`: a failure only counts as down after N consecutive failures. Retries should be spaced (small backoff, e.g. 2s) and total retry time should not exceed the next check interval.

### SSL checker (`internal/checker/ssl.go`)

- Use `crypto/tls.Dial` to fetch the leaf cert.
- Report days until `NotAfter`.
- Handle SNI correctly (use the hostname from the URL).
- Don't fail the check if the cert is *valid but expiring soon* — that's a separate alert path.
- Edge case: self-signed or untrusted certs — report this distinctly from "no cert."

### Domain checker (`internal/checker/domain.go`)

- Try RDAP first (`github.com/openrdap/rdap`), fall back to WHOIS (`github.com/likexian/whois` + `whois-parser`) if RDAP doesn't have the TLD.
- Cache results for at least 6 hours regardless of `domain_check_interval` — registrars rate-limit aggressively.
- If both lookups fail, log a warning but don't alert (we don't want flaky WHOIS to page anyone). Surface persistent failures (>3 days) as a separate "degraded monitoring" alert.

### Storage (`internal/storage`)

SQLite via `modernc.org/sqlite`. Two main tables:

```sql
CREATE TABLE site_state (
  site_name TEXT PRIMARY KEY,
  status TEXT NOT NULL,           -- 'up' | 'down' | 'unknown'
  last_check_at TIMESTAMP NOT NULL,
  last_status_change_at TIMESTAMP NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);

CREATE TABLE alert_log (
  id INTEGER PRIMARY KEY,
  site_name TEXT NOT NULL,
  alert_type TEXT NOT NULL,       -- 'down' | 'recovered' | 'ssl_expiring' | 'domain_expiring' | etc.
  payload TEXT,                   -- JSON details
  sent_at TIMESTAMP NOT NULL,
  notifier TEXT NOT NULL
);
```

Migrations embedded via `embed.FS`, applied on startup. Use simple numbered `.sql` files (`0001_init.sql`).

The Storage layer should expose a small interface so it's swappable and testable with an in-memory fake.

### Alerting logic (`internal/alerting`)

This is where the actual product lives. Be careful here.

- **Down alert** fires only on `up → down` transition (after retries exhausted), not on every failed check.
- **Recovery alert** fires on `down → up` transition, including how long it was down.
- **SSL alert** fires once per threshold crossed (using `alert_log` for dedup). If the cert is renewed and crosses the threshold again later, alert again.
- **Domain alert** same pattern as SSL.
- **Degraded monitoring alert** fires if domain/SSL checks have been failing (not the cert itself, the *check*) for >3 days.

Alert routing: look up which notifiers should receive each alert type via the `routing` config.

### Notifier (`internal/notifier`)

```go
type Notifier interface {
    Name() string
    Notify(ctx context.Context, alert Alert) error
}
```

`Alert` should be a structured type (site name, type, message, severity, details map). Each notifier formats it appropriately for its channel.

Slack and Discord: webhook POSTs with formatted blocks/embeds. SMTP: stdlib `net/smtp` with STARTTLS.

If a notifier fails, log it but don't crash. Retry once after 30s, then drop and write to `alert_log` with status `failed`.

### Scheduler (`internal/scheduler`)

- One goroutine per (site, check-type) pair, each with its own `time.Ticker`.
- Results published to a buffered channel (capacity ~ 4× number of sites).
- A single consumer goroutine processes results: persists state, evaluates alert conditions, dispatches to notifiers (in their own goroutines so a slow notifier doesn't block).
- All goroutines respect a parent `context.Context` for shutdown.

### CLI (`cmd/uptime/main.go`)

Flags:
- `--config` (default `./config.yaml`)
- `--log-format` (`json` | `text`, default `json`)
- `--log-level` (`debug` | `info` | `warn` | `error`, default `info`)

Subcommands (use `flag` package, no need for cobra unless it grows):
- `uptime run` — start the monitor (default if no subcommand)
- `uptime check <site-name>` — one-shot check, print result, exit. Useful for debugging.
- `uptime validate` — load and validate config, exit 0 or 1.
- `uptime version` — print version + build info (use `-ldflags` to inject).

## Testing expectations

- Unit tests for: config parsing/validation, alert state machine, body-match logic, SSL expiry calculation.
- Use `httptest.Server` for HTTP checker tests — cover 200/500/timeout/redirect-loop/body-mismatch.
- Storage tests against a temp SQLite file.
- One end-to-end test that wires a fake notifier + httptest server + temp DB and verifies an `up → down → up` cycle produces exactly two notifications with correct content.
- Aim for meaningful coverage of the `alerting` package specifically — that's where bugs hurt most. Don't chase coverage % on the boring glue code.

## Build & run

Provide a `Makefile` with at minimum:
- `make build` — produces `./bin/uptime`, static binary, stripped
- `make test` — runs unit tests with `-race`
- `make lint` — runs `go vet` and `staticcheck` if available
- `make run` — runs against `./config.yaml`

Build command should be:
```
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/uptime ./cmd/uptime
```

## README

Cover: what it is, install (download binary or `go install`), example config, running as a systemd service (include a unit file), supported notifiers, how to add a new notifier (point at the interface).

## Implementation order

Please build it in this order so we have a runnable thing early:

1. Skeleton + config loading + validation + `uptime validate` command.
2. HTTP checker + scheduler + console "notifier" that just logs alerts. Runnable end-to-end against real sites.
3. SQLite storage + state transition logic + dedup.
4. Slack notifier (real one). At this point it's actually useful.
5. SSL checker.
6. Domain checker (RDAP first, WHOIS fallback).
7. SMTP and Discord notifiers.
8. Tests filled in alongside each component (don't leave them all to the end, but also don't block step 1 on perfect coverage).
9. README + Makefile + example systemd unit.

After each numbered step, stop and tell me what's working so I can try it before you move on.

## Things to ask me before starting

If any of these are unclear, please ask:
- Do I want a web UI / status page, or is alerting-only fine for v1? (Default: alerting-only.)
- Any specific notifiers I care about beyond Slack/Discord/SMTP? (Telegram, PagerDuty, ntfy.sh are common asks.)
- Target deployment: a single VPS, multiple regions, container, something else?
- Anything that should explicitly be out of scope for v1?

## What "done" looks like for v1

I can:
1. Drop the binary and a `config.yaml` on a fresh Ubuntu VPS.
2. Run it under systemd.
3. Get a Slack message within ~2 minutes if a monitored site goes down.
4. Get a recovery message when it comes back.
5. Get a heads-up 30 days before any cert or domain expires.
6. Trust that a brief network blip on the monitor's side won't page me.
