CREATE TABLE IF NOT EXISTS site_state (
    site_name             TEXT PRIMARY KEY,
    status                TEXT NOT NULL,
    last_check_at         TEXT NOT NULL,
    last_status_change_at TEXT NOT NULL,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    last_error            TEXT
);

CREATE TABLE IF NOT EXISTS alert_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name   TEXT NOT NULL,
    alert_type  TEXT NOT NULL,
    threshold   INTEGER,
    cert_serial TEXT,
    payload     TEXT,
    sent_at     TEXT NOT NULL,
    notifier    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'sent'
);
CREATE INDEX IF NOT EXISTS idx_alert_log_site_type ON alert_log(site_name, alert_type, sent_at);

CREATE TABLE IF NOT EXISTS domain_cache (
    site_name      TEXT PRIMARY KEY,
    expires_at     TEXT,
    last_lookup_at TEXT NOT NULL,
    last_ok_at     TEXT,
    source         TEXT,
    error          TEXT
);
