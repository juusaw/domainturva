package notifier

import (
	"context"
	"log/slog"
)

// Console is a Notifier that just logs alerts. Useful during early bring-up
// and for tests.
type Console struct {
	N      string
	Logger *slog.Logger
}

func (c *Console) Name() string { return c.N }

func (c *Console) Notify(_ context.Context, a Alert) error {
	c.Logger.Info("ALERT",
		"site", a.SiteName,
		"type", a.Type,
		"severity", a.Severity,
		"title", a.Title,
		"message", a.Message,
		"details", a.Details,
	)
	return nil
}
