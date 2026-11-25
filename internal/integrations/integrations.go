// Package integrations summarizes optional external services.
package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/tidwall/gjson"
)

type Summary struct {
	Name      string
	Status    string // ok, warn, down, unknown
	Detail    string
	URL       string
	CheckedAt time.Time
	Error     string
	Metrics   []Metric
}

type Metric struct {
	Label string
	Value string
}

type Provider interface {
	Name() string
	Fetch(ctx context.Context) Summary
}

type Manager struct {
	mu        sync.RWMutex
	providers []Provider
	summary   map[string]Summary
	caddy     *caddyProvider
	client    *http.Client
}

func New(cfg config.IntegrationsConfig) *Manager {
	m := &Manager{
		summary: map[string]Summary{},
		client:  &http.Client{Timeout: 8 * time.Second},
	}
	if cfg.Beszel != nil {
		m.add(&beszelProvider{cfg: *cfg.Beszel, client: m.client})
	}
	if cfg.UptimeKuma != nil {
		m.add(&kumaProvider{cfg: *cfg.UptimeKuma, client: m.client})
	}
	if cfg.Caddy != nil {
		m.caddy = &caddyProvider{cfg: *cfg.Caddy, client: m.client}
		m.add(m.caddy)
	}
	for _, c := range cfg.Custom {
		m.add(&customProvider{cfg: c, client: m.client})
	}
	return m
}

func (m *Manager) add(p Provider) {
	m.summary[p.Name()] = Summary{Name: p.Name(), Status: "unknown", Detail: "not checked yet"}
	m.providers = append(m.providers, p)
}

func (m *Manager) Refresh(ctx context.Context) {
	m.mu.RLock()
	ps := make([]Provider, len(m.providers))
	copy(ps, m.providers)
	m.mu.RUnlock()
	var wg sync.WaitGroup
	for _, p := range ps {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			summary := p.Fetch(ctx)
			m.mu.Lock()
			m.summary[p.Name()] = summary
			m.mu.Unlock()
		}()
	}
	wg.Wait()
}

func (m *Manager) Summaries() []Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Summary, 0, len(m.summary))
	order := []string{"Beszel", "Uptime Kuma", "Caddy"}
	for _, name := range order {
		if s, ok := m.summary[name]; ok {
			out = append(out, s)
		}
	}
	seen := map[string]bool{}
	for _, s := range m.summary {
		seen[s.Name] = true
	}
	var rest []Summary
	for _, s := range m.summary {
		found := false
		for _, n := range order {
			if s.Name == n {
				found = true
			}
		}
		if !found {
			rest = append(rest, s)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].Name < rest[j].Name })
	return append(out, rest...)
}

// CaddyRoutes returns dial address -> public hostnames.
func (m *Manager) CaddyRoutes() map[string][]string {
	if m.caddy == nil {
		return nil
	}
	return m.caddy.Routes()
}

// RouteForDial returns the first public hostname for a dial address.
func (m *Manager) RouteForDial(dial string) string {
	routes := m.CaddyRoutes()
	if hs := routes[dial]; len(hs) > 0 {
		return hs[0]
	}
	return ""
}

func (m *Manager) Has(name string) bool {
	_, ok := m.summary[name]
	return ok
}

type beszelProvider struct {
	cfg    config.BeszelConfig
	client *http.Client
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (p *beszelProvider) Name() string { return "Beszel" }

func (p *beszelProvider) Fetch(ctx context.Context) Summary {
	s := Summary{Name: p.Name(), CheckedAt: time.Now(), URL: p.cfg.URL}
	base := strings.TrimRight(p.cfg.URL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/collections/systems/records?perPage=200&fields=id,name,host,status,info", nil)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	switch p.cfg.Auth {
	case "password":
		token, err := p.authToken(ctx, base)
		if err != nil {
			s.Status, s.Error = "down", "auth: "+err.Error()
			return s
		}
		req.Header.Set("Authorization", token)
	case "forward":
		email := p.cfg.RemoteEmail
		if email == "" {
			email = p.cfg.Email
		}
		if email != "" {
			req.Header.Set("Remote-Email", email)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		s.Status = "down"
		s.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s
	}
	var payload struct {
		Items []struct {
			Name   string          `json:"name"`
			Status string          `json:"status"`
			Info   json.RawMessage `json:"info"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		s.Status, s.Error = "warn", "unexpected API response"
		return s
	}
	up, down, pending, paused := 0, 0, 0, 0
	for _, it := range payload.Items {
		switch it.Status {
		case "up":
			up++
		case "down":
			down++
		case "pending":
			pending++
		case "paused":
			paused++
		}
	}
	s.Detail = fmt.Sprintf("%d systems · %d up", len(payload.Items), up)
	if down > 0 {
		s.Detail += fmt.Sprintf(" · %d down", down)
	}
	if pending > 0 {
		s.Detail += fmt.Sprintf(" · %d pending", pending)
	}
	if paused > 0 {
		s.Detail += fmt.Sprintf(" · %d paused", paused)
	}
	switch {
	case down > 0:
		s.Status = "down"
	case pending > 0 || len(payload.Items) == 0:
		s.Status = "warn"
	default:
		s.Status = "ok"
	}
	return s
}

func (p *beszelProvider) authToken(ctx context.Context, base string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Now().Before(p.expiry) {
		return p.token, nil
	}
	if p.cfg.Email == "" || p.cfg.Password == "" {
		return "", fmt.Errorf("email and password are required")
	}
	body := strings.NewReader(fmt.Sprintf(`{"identity":%q,"password":%q}`, p.cfg.Email, p.cfg.Password))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/collections/users/auth-with-password", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token")
	}
	p.token = out.Token
	p.expiry = time.Now().Add(30 * time.Minute)
	return out.Token, nil
}

type kumaProvider struct {
	cfg    config.KumaConfig
	client *http.Client
}

func (p *kumaProvider) Name() string { return "Uptime Kuma" }

func (p *kumaProvider) Fetch(ctx context.Context) Summary {
	s := Summary{Name: p.Name(), CheckedAt: time.Now(), URL: p.cfg.URL}
	u := p.cfg.URL
	if !strings.Contains(u, "/metrics") {
		u = strings.TrimRight(u, "/") + "/metrics"
		s.URL = strings.TrimSuffix(u, "/metrics")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	defer resp.Body.Close()
	f, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	if resp.StatusCode != http.StatusOK {
		s.Status, s.Error = "down", fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s
	}
	up, down, pending, maintenance := countKuma(string(f))
	if up+down+pending+maintenance == 0 {
		s.Status = "warn"
		s.Error = "no monitor_status metrics; enable Prometheus in Kuma"
		s.Detail = "metrics unavailable"
		return s
	}
	s.Detail = fmt.Sprintf("%d/%d up", up, up+down+pending+maintenance)
	if down > 0 {
		s.Detail += fmt.Sprintf(" · %d down", down)
	}
	if maintenance > 0 {
		s.Detail += fmt.Sprintf(" · %d maintenance", maintenance)
	}
	if down > 0 {
		s.Status = "down"
	} else if pending > 0 {
		s.Status = "warn"
	} else {
		s.Status = "ok"
	}
	return s
}

func countKuma(metrics string) (up, down, pending, maintenance int) {
	for _, line := range strings.Split(metrics, "\n") {
		if !strings.HasPrefix(line, "monitor_status{") {
			continue
		}
		idx := strings.LastIndex(line, " ")
		if idx < 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		switch val {
		case "1":
			up++
		case "0":
			down++
		case "2":
			pending++
		case "3":
			maintenance++
		}
	}
	return
}

type caddyProvider struct {
	cfg    config.CaddyConfig
	client *http.Client
	mu     sync.RWMutex
	routes map[string][]string
	count  int
	err    string
}

func (p *caddyProvider) Name() string { return "Caddy" }

func (p *caddyProvider) Fetch(ctx context.Context) Summary {
	s := Summary{Name: p.Name(), CheckedAt: time.Now()}
	base := strings.TrimRight(p.cfg.AdminURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/config/", nil)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	resp, err := p.client.Do(req)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		s.Status, s.Error = "down", fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		s.Status, s.Error = "down", "invalid admin API JSON"
		return s
	}
	routes := map[string]map[string]bool{}
	count := 0
	walkCaddy(doc, nil, routes, &count)
	flat := map[string][]string{}
	for dial, hosts := range routes {
		for h := range hosts {
			flat[dial] = append(flat[dial], h)
		}
		sort.Strings(flat[dial])
	}
	p.mu.Lock()
	p.routes = flat
	p.count = count
	p.err = ""
	p.mu.Unlock()
	s.Status = "ok"
	s.Detail = fmt.Sprintf("%d public route", count)
	if count != 1 {
		s.Detail += "s"
	}
	return s
}

func (p *caddyProvider) Routes() map[string][]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := map[string][]string{}
	for k, v := range p.routes {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func walkCaddy(v any, inherited []string, routes map[string]map[string]bool, count *int) {
	switch x := v.(type) {
	case map[string]any:
		hosts := inherited
		if m, ok := x["match"].([]any); ok {
			for _, item := range m {
				if mm, ok := item.(map[string]any); ok {
					if hs, ok := mm["host"].([]any); ok {
						hosts = append([]string(nil), inherited...)
						for _, h := range hs {
							if s, ok := h.(string); ok {
								hosts = append(hosts, s)
							}
						}
					}
				}
			}
		}
		if h, _ := x["handler"].(string); h == "reverse_proxy" {
			*count++
			if ups, ok := x["upstreams"].([]any); ok {
				for _, u := range ups {
					um, ok := u.(map[string]any)
					if !ok {
						continue
					}
					dial, _ := um["dial"].(string)
					if dial == "" || len(hosts) == 0 {
						continue
					}
					if routes[dial] == nil {
						routes[dial] = map[string]bool{}
					}
					for _, h := range hosts {
						routes[dial][h] = true
					}
				}
			}
		}
		for k, child := range x {
			if k == "match" {
				continue
			}
			walkCaddy(child, hosts, routes, count)
		}
	case []any:
		for _, child := range x {
			walkCaddy(child, inherited, routes, count)
		}
	}
}

type customProvider struct {
	cfg    config.CustomIntegration
	client *http.Client
}

func (p *customProvider) Name() string { return p.cfg.Name }

func (p *customProvider) Fetch(ctx context.Context) Summary {
	s := Summary{Name: p.Name(), CheckedAt: time.Now(), URL: p.cfg.URL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.URL, nil)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		s.Status, s.Error = "down", err.Error()
		return s
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		s.Status, s.Error = "down", fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s
	}
	statusPath := p.cfg.StatusPath
	if statusPath == "" {
		statusPath = "status"
	}
	rawStatus := strings.ToLower(gjson.GetBytes(body, statusPath).String())
	switch rawStatus {
	case "ok", "up", "healthy", "pass", "green":
		s.Status = "ok"
	case "warn", "warning", "degraded", "yellow":
		s.Status = "warn"
	case "down", "error", "fail", "failed", "red", "critical":
		s.Status = "down"
	default:
		s.Status = "unknown"
	}
	titlePath := p.cfg.TitlePath
	if titlePath == "" {
		titlePath = "title"
	}
	detailPath := p.cfg.DetailPath
	if detailPath == "" {
		detailPath = "detail"
	}
	s.Detail = gjson.GetBytes(body, detailPath).String()
	if s.Detail == "" {
		s.Detail = gjson.GetBytes(body, titlePath).String()
	}
	if link := gjson.GetBytes(body, p.cfg.LinkPath).String(); link != "" {
		if _, err := url.Parse(link); err == nil {
			s.URL = link
		}
	}
	return s
}
