# domainturva

Self-hosted uptime monitor in Go. Single static binary, FreeBSD-first.

Watches HTTP(S) endpoints, TLS certificate expiry, and domain registration
expiry, and sends alerts via Slack or SMTP when something goes sideways.

## Install

### Build from source

```sh
git clone https://github.com/juusomikkonen/domainturva
cd domainturva
make build-freebsd          # produces bin/domainturva-freebsd-amd64
```

`make build` produces a native binary for local testing.

### Cross-compile

```sh
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
    -o bin/domainturva-freebsd-amd64 ./cmd/domainturva
```

The binary is fully static (no CGO) and portable across FreeBSD installs of
the same arch.

## Configure

Copy `config.example.yaml` to your install path (e.g.
`/usr/local/etc/domainturva/config.yaml`) and edit it. Secrets come from env
vars referenced as `${VAR_NAME}` — the process must have those set, or
startup fails fast.

Validate the config any time:

```sh
domainturva validate --config /usr/local/etc/domainturva/config.yaml
```

## Run on FreeBSD (rc.d)

```sh
# Place the binary
sudo install -m 0755 bin/domainturva-freebsd-amd64 /usr/local/bin/domainturva

# Service user + dirs
sudo pw useradd domainturva -d /nonexistent -s /usr/sbin/nologin
sudo install -d -o domainturva -g domainturva /var/db/domainturva
sudo install -d -o root -g wheel -m 0755 /usr/local/etc/domainturva
sudo install -m 0640 -o root -g domainturva config.example.yaml \
    /usr/local/etc/domainturva/config.yaml

# Secrets file
sudo tee /usr/local/etc/domainturva/env >/dev/null <<'EOF'
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX
SMTP_USER=alerts@example.com
SMTP_PASS=...
EOF
sudo chmod 0640 /usr/local/etc/domainturva/env
sudo chown root:domainturva /usr/local/etc/domainturva/env

# rc.d script
sudo install -m 0755 contrib/domainturva.in /usr/local/etc/rc.d/domainturva

# Enable + start
sudo sysrc domainturva_enable="YES"
sudo service domainturva start
```

Logs land in `/var/log/domainturva.log` (JSON). `tail -f` it.

## Subcommands

```
domainturva run         # default: start the monitor
domainturva check NAME  # one-shot check of a single configured site
domainturva validate    # validate config, exit 0/1
domainturva version     # version + build info
```

Common flags:

```
--config <path>     default: ./config.yaml
--log-format json|text   default: json
--log-level debug|info|warn|error   default: info
```

## What it alerts on

| Alert type            | Trigger                                                  |
| --------------------- | -------------------------------------------------------- |
| `down`                | Site fails N+1 consecutive checks (`retries`).           |
| `recovered`           | Site goes up after being down. Includes downtime.        |
| `ssl_expiring`        | Cert crosses one of `ssl_warn_days`. Renewals re-arm.    |
| `ssl_untrusted`       | Cert is self-signed or chain doesn't validate.           |
| `domain_expiring`     | Registration crosses one of `domain_warn_days`.          |
| `degraded_monitoring` | Domain lookups (RDAP+WHOIS) failing for >3 days.         |

The first observed state for a brand-new site is treated as the baseline;
no alert fires until the *next* transition. This avoids spurious pages on
monitor restart.

## Healthcheck endpoint

Opt-in; set `healthcheck.listen` in the config to bind a small HTTP server.

```
GET /healthz
```

- `200 OK` with a JSON body when at least one HTTP check has completed within
  2× the longest configured site interval (or within the same window after
  startup — startup grace).
- `503 Service Unavailable` when the most recent check is older than that.

Example response:

```json
{
  "status": "ok",
  "version": "v0.1.0",
  "uptime_sec": 1234,
  "sites": 4,
  "latest_check_at": "2026-05-08T12:00:00Z",
  "stale_after": "1m0s",
  "stale": false
}
```

Bind to `127.0.0.1` unless something outside the box needs to reach it.

## Supported notifiers

- **slack** — incoming webhook
- **smtp** — STARTTLS

To add another: implement `notifier.Notifier` in `internal/notifier/`, wire
it into `buildNotifiers` in `cmd/domainturva/main.go`, and add validation
for its config in `internal/config`.

## Development

```sh
make test           # unit + integration with -race
make lint
make run            # native build, runs against ./config.yaml
```

The `internal/storage.Memory` fake makes it easy to write tests against the
alerting and scheduler packages without spinning up SQLite.
