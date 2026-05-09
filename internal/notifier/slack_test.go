package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSlack_Notify(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := NewSlack("ops", srv.URL)
	err := s.Notify(context.Background(), Alert{
		SiteName: "example",
		Type:     TypeDown,
		Severity: SeverityCritical,
		Title:    "DOWN",
		Message:  "site went down",
		Details:  map[string]any{"status": 500},
		At:       time.Now(),
	})
	if err != nil {
		t.Fatalf("notify: %v", err)
	}
	var payload slackPayload
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Text == "" || len(payload.Blocks) < 2 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestSlack_NotifyServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("nope"))
	}))
	defer srv.Close()
	s := NewSlack("ops", srv.URL)
	if err := s.Notify(context.Background(), Alert{SiteName: "x"}); err == nil {
		t.Fatal("expected error")
	}
}
