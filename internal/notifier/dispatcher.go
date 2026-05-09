package notifier

import (
	"context"
	"log/slog"
	"time"

	"github.com/juusomikkonen/domainturva/internal/storage"
)

// Dispatcher sends alerts to one or more notifiers, retrying once on failure
// and recording every send (success or failure) in the alert log.
type Dispatcher struct {
	Notifiers map[string]Notifier
	Storage   storage.Storage
	Logger    *slog.Logger

	RetryDelay time.Duration
	Now        func() time.Time
}

func NewDispatcher(notifiers map[string]Notifier, store storage.Storage, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		Notifiers:  notifiers,
		Storage:    store,
		Logger:     log,
		RetryDelay: 30 * time.Second,
		Now:        time.Now,
	}
}

// Dispatch sends the alert to the listed notifiers. Failures are logged and
// retried once after RetryDelay; the final outcome is recorded in alert_log.
// Each notifier runs in its own goroutine so a slow notifier doesn't block.
//
// Dispatch returns immediately; sends happen in the background. Pass a context
// that is cancelled on shutdown to abort in-flight retries cleanly.
func (d *Dispatcher) Dispatch(ctx context.Context, a Alert, notifierNames []string, extraRecord storage.AlertRecord) {
	for _, name := range notifierNames {
		n, ok := d.Notifiers[name]
		if !ok {
			d.Logger.Warn("dispatch: unknown notifier", "name", name, "site", a.SiteName, "type", a.Type)
			continue
		}
		go d.sendOne(ctx, n, a, extraRecord)
	}
}

func (d *Dispatcher) sendOne(ctx context.Context, n Notifier, a Alert, extra storage.AlertRecord) {
	err := n.Notify(ctx, a)
	if err != nil {
		d.Logger.Warn("notifier failed, retrying",
			"notifier", n.Name(), "site", a.SiteName, "type", a.Type, "err", err)
		select {
		case <-ctx.Done():
			d.record(ctx, n.Name(), a, extra, "failed")
			return
		case <-time.After(d.RetryDelay):
		}
		err = n.Notify(ctx, a)
	}
	status := "sent"
	if err != nil {
		d.Logger.Error("notifier failed permanently",
			"notifier", n.Name(), "site", a.SiteName, "type", a.Type, "err", err)
		status = "failed"
	}
	d.record(ctx, n.Name(), a, extra, status)
}

func (d *Dispatcher) record(ctx context.Context, notifierName string, a Alert, extra storage.AlertRecord, status string) {
	if d.Storage == nil {
		return
	}
	rec := storage.AlertRecord{
		SiteName:   a.SiteName,
		AlertType:  a.Type,
		Threshold:  extra.Threshold,
		CertSerial: extra.CertSerial,
		Payload:    a.PayloadJSON(),
		SentAt:     d.Now(),
		Notifier:   notifierName,
		Status:     status,
	}
	if err := d.Storage.RecordAlert(ctx, rec); err != nil {
		d.Logger.Error("alert log write failed", "err", err)
	}
}
