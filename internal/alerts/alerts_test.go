package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestQuietHours(t *testing.T) {
	n := New(config.AlertsConfig{QuietHours: "23:00-08:00"}, nil, "host", "")
	at := func(h, m int) time.Time { return time.Date(2026, 1, 1, h, m, 0, 0, time.Local) }
	if !n.inQuietHours(at(23, 30)) || !n.inQuietHours(at(7, 59)) {
		t.Fatal("expected quiet time")
	}
	if n.inQuietHours(at(12, 0)) {
		t.Fatal("unexpected quiet time")
	}
}

func TestNotifyDedupesAndQueues(t *testing.T) {
	st := testStore(t)
	cfg := config.AlertsConfig{
		Enabled:  true,
		Cooldown: config.Duration(time.Hour),
		Webhook:  &config.WebhookConfig{URL: "http://127.0.0.1:1/hook", Format: "generic"},
		Rules:    map[string][]string{"new_service": {"webhook"}},
	}
	n := New(cfg, st, "host", "https://admin.example.com")
	ev := Event{Type: "new_service", Title: "New service", Message: "port 1234", Fingerprint: "proc:x"}
	n.Notify(context.Background(), ev)
	n.Notify(context.Background(), ev)
	due, err := st.DueNotifications(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("expected one queued notification, got %d", len(due))
	}
	var p payload
	if err := json.Unmarshal([]byte(due[0].Payload), &p); err != nil {
		t.Fatal(err)
	}
	if p.URL != "https://admin.example.com" || p.Host != "host" {
		t.Fatalf("payload: %+v", p)
	}
}

func TestWebhookFormats(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	n := New(config.AlertsConfig{
		Enabled: true,
		Webhook: &config.WebhookConfig{URL: srv.URL, Format: "discord"},
		Rules:   map[string][]string{},
	}, nil, "host", "")
	p := payload{Event: Event{Type: "test", Title: "Title", Message: "Body"}, Host: "host"}
	if err := n.sendWebhook(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"content":"Title`) {
		t.Fatalf("discord body: %s", got)
	}

	n.cfg.Webhook.Format = "generic"
	if err := n.sendWebhook(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if m["host"] != "host" || m["event"] != "test" {
		t.Fatalf("generic body: %v", m)
	}
}

func TestBuildEmail(t *testing.T) {
	msg := string(buildEmail("binnacle@example.com", []string{"a@example.com"}, "Subject", "Body"))
	for _, want := range []string{"From: binnacle@example.com", "To: a@example.com", "Subject: Subject", "Body"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in email", want)
		}
	}
}

func TestUnknownChannel(t *testing.T) {
	n := New(config.AlertsConfig{}, nil, "", "")
	if err := n.send(context.Background(), "nope", payload{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestNotifyFallsBackToConfiguredChannels(t *testing.T) {
	st := testStore(t)
	cfg := config.AlertsConfig{
		Enabled:  true,
		Cooldown: config.Duration(time.Hour),
		Webhook:  &config.WebhookConfig{URL: "http://127.0.0.1:1/hook", Format: "generic"},
	}
	n := New(cfg, st, "host", "")
	if !n.Handles("new_service") {
		t.Fatal("fallback routing should handle new_service")
	}
	n.Notify(context.Background(), Event{Type: "new_service", Title: "x", Message: "y"})
	due, err := st.DueNotifications(context.Background(), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due: %+v %v", due, err)
	}
}
