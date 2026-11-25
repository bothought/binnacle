package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bothought/binnacle/internal/config"
)

func TestCountKuma(t *testing.T) {
	up, down, pending, maintenance := countKuma(`
# HELP monitor_status
monitor_status{monitor_name="a",monitor_type="http"} 1
monitor_status{monitor_name="b",monitor_type="http"} 0
monitor_status{monitor_name="c",monitor_type="ping"} 2
monitor_status{monitor_name="d",monitor_type="ping"} 3
`)
	if up != 1 || down != 1 || pending != 1 || maintenance != 1 {
		t.Fatalf("counts: %d %d %d %d", up, down, pending, maintenance)
	}
}

func TestKumaProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("monitor_status{monitor_name=\"a\"} 1\nmonitor_status{monitor_name=\"b\"} 0\n"))
	}))
	defer srv.Close()
	p := &kumaProvider{cfg: config.KumaConfig{URL: srv.URL}, client: srv.Client()}
	sum := p.Fetch(context.Background())
	if sum.Status != "down" || !strings.Contains(sum.Detail, "1/2 up") {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestCaddyRoutes(t *testing.T) {
	body := `{"apps":{"http":{"servers":{"srv0":{"routes":[
		{"match":[{"host":["monitor.example.com"]}],"handle":[{"handler":"subroute","routes":[
			{"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:8091"}]}]}
		]}]},
		{"match":[{"host":["*.example.com"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"127.0.0.1:9091"}]}]}
	]}}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := &caddyProvider{cfg: config.CaddyConfig{AdminURL: srv.URL}, client: srv.Client()}
	sum := p.Fetch(context.Background())
	if sum.Status != "ok" {
		t.Fatalf("summary: %+v", sum)
	}
	routes := p.Routes()
	if len(routes["127.0.0.1:8091"]) != 1 || routes["127.0.0.1:8091"][0] != "monitor.example.com" {
		t.Fatalf("routes: %+v", routes)
	}
	if len(routes["127.0.0.1:9091"]) != 1 || routes["127.0.0.1:9091"][0] != "*.example.com" {
		t.Fatalf("wildcard routes: %+v", routes)
	}
}

func TestBeszelProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"items":[{"name":"a","status":"up"},{"name":"b","status":"down"}]}`))
	}))
	defer srv.Close()
	p := &beszelProvider{cfg: config.BeszelConfig{URL: srv.URL, Auth: "none"}, client: srv.Client()}
	sum := p.Fetch(context.Background())
	if sum.Status != "down" || !strings.Contains(sum.Detail, "2 systems") {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestCustomProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","title":"All good","detail":"12 checks"}`))
	}))
	defer srv.Close()
	p := &customProvider{cfg: config.CustomIntegration{Name: "Custom", URL: srv.URL}, client: srv.Client()}
	sum := p.Fetch(context.Background())
	if sum.Status != "ok" || sum.Detail != "12 checks" {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestManagerRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"warn","title":"Degraded","detail":"one job late"}`))
	}))
	defer srv.Close()
	m := New(config.IntegrationsConfig{Custom: []config.CustomIntegration{{Name: "Custom", URL: srv.URL}}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.Refresh(ctx)
	sums := m.Summaries()
	if len(sums) != 1 || sums[0].Status != "warn" {
		t.Fatalf("summaries: %+v", sums)
	}
}
