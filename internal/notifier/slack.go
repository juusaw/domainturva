package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Slack posts alerts to a Slack incoming-webhook URL.
type Slack struct {
	N       string
	Webhook string
	Client  *http.Client
}

func NewSlack(name, webhook string) *Slack {
	return &Slack{
		N:       name,
		Webhook: webhook,
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *Slack) Name() string { return s.N }

type slackBlock struct {
	Type string         `json:"type"`
	Text *slackTextElem `json:"text,omitempty"`
}
type slackTextElem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type slackPayload struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

func (s *Slack) Notify(ctx context.Context, a Alert) error {
	emoji := severityEmoji(a.Severity)
	header := fmt.Sprintf("%s %s — %s", emoji, a.Title, a.SiteName)

	body := a.Message
	if len(a.Details) > 0 {
		body += "\n```"
		for k, v := range a.Details {
			body += fmt.Sprintf("\n%s: %v", k, v)
		}
		body += "\n```"
	}

	payload := slackPayload{
		Text: header,
		Blocks: []slackBlock{
			{Type: "header", Text: &slackTextElem{Type: "plain_text", Text: header}},
			{Type: "section", Text: &slackTextElem{Type: "mrkdwn", Text: body}},
		},
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Webhook, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("slack: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func severityEmoji(s Severity) string {
	switch s {
	case SeverityCritical:
		return ":rotating_light:"
	case SeverityWarning:
		return ":warning:"
	default:
		return ":information_source:"
	}
}
