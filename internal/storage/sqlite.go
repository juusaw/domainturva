package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create db parent dir %s: %w", dir, err)
		}
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite serialises writes; single conn avoids contention.
	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	applied := map[string]bool{}
	rows, err := s.db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	for _, name := range names {
		if applied[name] {
			continue
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, name, time.Now().UTC().Format(time.RFC3339)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLite) Close() error { return s.db.Close() }

const tsLayout = time.RFC3339Nano

func formatTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(tsLayout)
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		// Tolerate older RFC3339 entries.
		if t2, err2 := time.Parse(time.RFC3339, s); err2 == nil {
			return t2
		}
		return time.Time{}
	}
	return t
}

func (s *SQLite) GetSiteState(ctx context.Context, name string) (SiteState, bool, error) {
	var st SiteState
	var lastCheck, lastChange string
	var lastErr sql.NullString
	row := s.db.QueryRowContext(ctx,
		`SELECT site_name, status, last_check_at, last_status_change_at, consecutive_failures, last_error
		   FROM site_state WHERE site_name = ?`, name)
	err := row.Scan(&st.SiteName, &st.Status, &lastCheck, &lastChange, &st.ConsecutiveFailures, &lastErr)
	if errors.Is(err, sql.ErrNoRows) {
		return SiteState{}, false, nil
	}
	if err != nil {
		return SiteState{}, false, err
	}
	st.LastCheckAt = parseTS(lastCheck)
	st.LastStatusChangeAt = parseTS(lastChange)
	if lastErr.Valid {
		st.LastError = lastErr.String
	}
	return st, true, nil
}

func (s *SQLite) UpsertSiteState(ctx context.Context, st SiteState) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO site_state (site_name, status, last_check_at, last_status_change_at, consecutive_failures, last_error)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(site_name) DO UPDATE SET
		   status = excluded.status,
		   last_check_at = excluded.last_check_at,
		   last_status_change_at = excluded.last_status_change_at,
		   consecutive_failures = excluded.consecutive_failures,
		   last_error = excluded.last_error`,
		st.SiteName, st.Status, formatTS(st.LastCheckAt), formatTS(st.LastStatusChangeAt),
		st.ConsecutiveFailures, st.LastError)
	return err
}

func (s *SQLite) RecordAlert(ctx context.Context, a AlertRecord) error {
	if a.Status == "" {
		a.Status = "sent"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_log (site_name, alert_type, threshold, cert_serial, payload, sent_at, notifier, status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.SiteName, a.AlertType, a.Threshold, a.CertSerial, a.Payload, formatTS(a.SentAt), a.Notifier, a.Status)
	return err
}

func (s *SQLite) FindRecentAlerts(ctx context.Context, siteName, alertType string, since time.Time) ([]AlertRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, site_name, alert_type, threshold, cert_serial, payload, sent_at, notifier, status
		   FROM alert_log
		  WHERE site_name = ? AND alert_type = ? AND sent_at >= ?
		  ORDER BY sent_at DESC`,
		siteName, alertType, formatTS(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRecord
	for rows.Next() {
		var a AlertRecord
		var sent string
		var threshold sql.NullInt64
		var certSerial, payload sql.NullString
		if err := rows.Scan(&a.ID, &a.SiteName, &a.AlertType, &threshold, &certSerial, &payload, &sent, &a.Notifier, &a.Status); err != nil {
			return nil, err
		}
		a.SentAt = parseTS(sent)
		if threshold.Valid {
			a.Threshold = int(threshold.Int64)
		}
		if certSerial.Valid {
			a.CertSerial = certSerial.String
		}
		if payload.Valid {
			a.Payload = payload.String
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) GetDomainCache(ctx context.Context, name string) (DomainCache, bool, error) {
	var d DomainCache
	var expires, lastLookup, lastOk sql.NullString
	var source, errStr sql.NullString
	row := s.db.QueryRowContext(ctx,
		`SELECT site_name, expires_at, last_lookup_at, last_ok_at, source, error
		   FROM domain_cache WHERE site_name = ?`, name)
	err := row.Scan(&d.SiteName, &expires, &lastLookup, &lastOk, &source, &errStr)
	if errors.Is(err, sql.ErrNoRows) {
		return DomainCache{}, false, nil
	}
	if err != nil {
		return DomainCache{}, false, err
	}
	if expires.Valid {
		d.ExpiresAt = parseTS(expires.String)
	}
	if lastLookup.Valid {
		d.LastLookupAt = parseTS(lastLookup.String)
	}
	if lastOk.Valid {
		d.LastOkAt = parseTS(lastOk.String)
	}
	if source.Valid {
		d.Source = source.String
	}
	if errStr.Valid {
		d.Error = errStr.String
	}
	return d, true, nil
}

func (s *SQLite) UpsertDomainCache(ctx context.Context, d DomainCache) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO domain_cache (site_name, expires_at, last_lookup_at, last_ok_at, source, error)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(site_name) DO UPDATE SET
		   expires_at = excluded.expires_at,
		   last_lookup_at = excluded.last_lookup_at,
		   last_ok_at = excluded.last_ok_at,
		   source = excluded.source,
		   error = excluded.error`,
		d.SiteName, formatTS(d.ExpiresAt), formatTS(d.LastLookupAt), formatTS(d.LastOkAt), d.Source, d.Error)
	return err
}
