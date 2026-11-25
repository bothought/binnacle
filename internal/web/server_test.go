package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bothought/binnacle/internal/actions"
	"github.com/bothought/binnacle/internal/alerts"
	"github.com/bothought/binnacle/internal/auth"
	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/hostruntime"
	"github.com/bothought/binnacle/internal/integrations"
	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/system"
)

func testServer(t *testing.T) (*Server, *store.Store, *config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Updates.Enabled = false
	cfg.Alerts.Enabled = false
	cfg.Actions = nil
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	_, _ = st.SyncServices(ctx, []store.Service{
		{Key: "unit:caddy.service", Name: "caddy", Kind: "systemd", Unit: "caddy.service", Exposure: "loopback", Visibility: "auto", Ports: []store.Port{{Proto: "tcp", Port: 443}}, Label: "Caddy"},
	})
	_ = st.SetBaseline(ctx, 1)
	_ = st.UpdateServiceMeta(ctx, "unit:caddy.service", "Caddy", "", "https://example.com", "infra", "public", true, false, "demo")
	_ = st.UpsertUpdate(ctx, store.Update{Key: "app:x", Name: "X", Current: "1.0", Latest: "2.0", Severity: "security", Source: "app", CheckedAt: 1})
	sys := system.New()
	rt := hostruntime.New()
	authMgr := auth.New(cfg.Auth, st)
	notifier := alerts.New(cfg.Alerts, st, "host", "")
	actionMgr := actions.New(nil, st, nil)
	srv, err := New(Deps{
		Config: cfg, ConfigPath: "/tmp/config.yaml", Store: st, Auth: authMgr, System: sys,
		Integrations: integrations.New(cfg.Integrations), Actions: actionMgr, Runtime: rt,
		Notifier: notifier, Version: "test", Demo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, cfg
}

func TestPagesRender(t *testing.T) {
	srv, _, _ := testServer(t)
	paths := []string{"/", "/partials/dashboard", "/services", "/updates", "/actions", "/settings", "/healthz"}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: status %d body %s", p, rr.Code, rr.Body.String()[:min(200, rr.Body.Len())])
		}
		if p != "/healthz" && p != "/partials/dashboard" && !strings.Contains(rr.Body.String(), "binnacle") {
			t.Errorf("%s: missing brand", p)
		}
	}
}

func TestStaticCSS(t *testing.T) {
	srv, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "--accent") {
		t.Fatalf("css status=%d", rr.Code)
	}
}

func TestServicesUpdateWithCSRF(t *testing.T) {
	srv, st, _ := testServer(t)
	body := strings.NewReader("csrf=" + srv.demoSession.CSRF + "&key=unit:caddy.service&label=Proxy&visibility=hidden&favorite=on")
	req := httptest.NewRequest(http.MethodPost, "/services/update", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	list, _ := st.ListServices(context.Background())
	if len(list) != 1 || list[0].Label != "Proxy" || list[0].Visibility != "hidden" {
		t.Fatalf("service not updated: %+v", list)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
