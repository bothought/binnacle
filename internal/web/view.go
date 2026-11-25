package web

import (
	"context"
	"net/http"
	"sort"
	"strings"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/integrations"
	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/system"
)

type serviceView struct {
	store.Service
	Display    string
	PortText   string
	PublicURL  string
	Exposure   string
	Visibility string
	IsNew      bool
	FirstLabel string
	LastLabel  string
}

type actionView struct {
	config.ActionConfig
	Running bool
	Last    store.Run
	HasLast bool
}

type attentionItem struct {
	Kind  string
	Class string
	Text  string
	Link  string
}

type dashboardData struct {
	baseData
	Snap         system.Snapshot
	History      []system.Point
	Services     []serviceView
	NewCount     int
	HiddenCount  int
	PublicCount  int
	TotalCount   int
	Attention    []attentionItem
	Summaries    []integrations.Summary
	Actions      []actionView
	VisibleCount int
}

type servicesData struct {
	baseData
	Services    []serviceView
	Filter      string
	Query       string
	NewCount    int
	HiddenCount int
	PublicCount int
	TotalCount  int
	Caddy       bool
}

type updatesData struct {
	baseData
	Updates     []store.Update
	Filter      string
	OpenCount   int
	UrgentCount int
	AckCount    int
	Errors      []string
	Enabled     bool
}

type actionsData struct {
	baseData
	Actions []actionView
	Runs    []store.Run
}

type confirmData struct {
	baseData
	Action  config.ActionConfig
	Running bool
	Error   string
}

type runData struct {
	baseData
	Run    store.Run
	Output string
	Active bool
}

type settingsData struct {
	baseData
	Summaries   []integrations.Summary
	Channels    []string
	AuthMode    string
	ConfigPath  string
	StateDir    string
	RuntimeKind string
	ActionCount int
	UpdateCount int
	Scanned     int64
}

func (s *Server) serviceViews(ctx context.Context) []serviceView {
	services, _ := s.deps.Store.ListServices(ctx)
	baseline, _ := s.deps.Store.BaselineAt(ctx)
	routes := s.deps.Integrations.CaddyRoutes()
	byPort := map[int]string{}
	publicPorts := map[int]bool{}
	for dial, hosts := range routes {
		if len(hosts) == 0 {
			continue
		}
		p := portFromDial(dial)
		if p <= 0 {
			continue
		}
		publicPorts[p] = true
		for _, h := range hosts {
			if !strings.HasPrefix(h, "*.") {
				byPort[p] = h
				break
			}
		}
	}
	out := make([]serviceView, 0, len(services))
	for _, sv := range services {
		v := serviceView{Service: sv, Display: sv.DisplayName(), PortText: portText(sv.Ports), Exposure: sv.Exposure, Visibility: sv.EffectiveVisibility(), IsNew: sv.IsNew(baseline), FirstLabel: agoText(sv.FirstSeen), LastLabel: agoText(sv.LastSeen)}
		if v.Display == "" {
			v.Display = sv.Name
		}
		v.PublicURL = sv.URL
		for _, p := range sv.Ports {
			if publicPorts[p.Port] {
				if rankExposure("public") > rankExposure(v.Exposure) {
					v.Exposure = "public"
				}
			}
			if host := byPort[p.Port]; host != "" && v.PublicURL == "" {
				v.PublicURL = "https://" + host
			}
		}
		if sv.Visibility == "" || sv.Visibility == "auto" {
			if v.Exposure == "public" {
				v.Visibility = "public"
			} else {
				v.Visibility = "internal"
			}
		}
		out = append(out, v)
	}
	sortServiceViews(out)
	return out
}

func sortServiceViews(v []serviceView) {
	sort.SliceStable(v, func(i, j int) bool {
		a, b := v[i], v[j]
		if a.IsNew != b.IsNew {
			return a.IsNew
		}
		if a.Favorite != b.Favorite {
			return a.Favorite
		}
		if rankExposure(a.Exposure) != rankExposure(b.Exposure) {
			return rankExposure(a.Exposure) > rankExposure(b.Exposure)
		}
		return strings.ToLower(a.Display) < strings.ToLower(b.Display)
	})
}

func rankExposure(s string) int {
	switch s {
	case "public":
		return 4
	case "tailnet":
		return 3
	case "lan":
		return 2
	case "loopback":
		return 1
	}
	return 0
}

func portFromDial(dial string) int {
	idx := strings.LastIndex(dial, ":")
	if idx < 0 {
		return 0
	}
	var p int
	for _, r := range dial[idx+1:] {
		if r < '0' || r > '9' {
			return 0
		}
		p = p*10 + int(r-'0')
	}
	return p
}

func (s *Server) buildActions(ctx context.Context) []actionView {
	running := s.deps.Actions.Running()
	runs, _ := s.deps.Store.ListRuns(ctx, 100)
	last := map[string]store.Run{}
	for _, r := range runs {
		if _, ok := last[r.ActionID]; !ok {
			last[r.ActionID] = r
		}
	}
	var out []actionView
	for _, a := range s.deps.Actions.List() {
		v := actionView{ActionConfig: a, Running: running[a.ID]}
		if r, ok := last[a.ID]; ok {
			v.Last, v.HasLast = r, true
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) dashboardModel(r *http.Request) dashboardData {
	ctx := r.Context()
	views := s.serviceViews(ctx)
	d := dashboardData{
		baseData: s.base(r, "Overview", "overview"),
		Snap:     s.deps.System.Latest(),
		History:  s.deps.System.History(),
	}
	visible := make([]serviceView, 0, len(views))
	for _, v := range views {
		if v.IsNew && !v.Ignored {
			d.NewCount++
		}
		if v.Visibility == "hidden" || v.Ignored {
			d.HiddenCount++
		}
		if v.Exposure == "public" {
			d.PublicCount++
		}
		if v.Ignored || v.Visibility == "hidden" {
			continue
		}
		visible = append(visible, v)
	}
	d.TotalCount = len(views)
	d.VisibleCount = len(visible)
	if len(visible) > 8 {
		visible = visible[:8]
	}
	d.Services = visible

	updates, _ := s.deps.Store.ListUpdates(ctx)
	var urgent []store.Update
	for _, u := range updates {
		if u.Severity == "security" && !u.Acknowledged {
			urgent = append(urgent, u)
		}
	}
	if len(urgent) > 0 {
		for i, u := range urgent {
			if i >= 3 {
				break
			}
			d.Attention = append(d.Attention, attentionItem{
				Kind: "update", Class: "down", Text: "Urgent update: " + u.Name + " " + u.Current + " → " + u.Latest, Link: "/updates",
			})
		}
	}
	newViews := make([]serviceView, 0, 4)
	for _, v := range views {
		if v.IsNew && !v.Ignored {
			newViews = append(newViews, v)
		}
	}
	if len(newViews) > 0 {
		names := make([]string, 0, 3)
		for i, v := range newViews {
			if i >= 3 {
				break
			}
			names = append(names, v.Display+" ("+v.PortText+")")
		}
		d.Attention = append(d.Attention, attentionItem{
			Kind: "new", Class: "warn", Text: plural(len(newViews), "new service", "new services") + ": " + strings.Join(names, " · "), Link: "/services?show=new",
		})
	}
	if len(d.Snap.FailedUnits) > 0 {
		d.Attention = append(d.Attention, attentionItem{
			Kind: "unit", Class: "down", Text: plural(len(d.Snap.FailedUnits), "failed systemd unit", "failed systemd units") + ": " + strings.Join(limitStrings(d.Snap.FailedUnits, 3), ", "),
		})
	}
	if d.Snap.StagedVersion != "" && d.Snap.StagedVersion != d.Snap.OSImageVersion {
		d.Attention = append(d.Attention, attentionItem{
			Kind: "os", Class: "warn", Text: "OS update staged: " + d.Snap.StagedVersion + " — reboot to apply", Link: "/updates",
		})
	}
	for _, disk := range d.Snap.Disks {
		if disk.Percent >= s.deps.Config.Collector.DiskWarnPercent {
			d.Attention = append(d.Attention, attentionItem{
				Kind: "disk", Class: "warn", Text: "Disk " + disk.Mount + " is " + pctText(disk.Percent) + " full",
			})
		}
	}
	d.Summaries = s.deps.Integrations.Summaries()
	for _, sum := range d.Summaries {
		if sum.Status == "down" {
			d.Attention = append(d.Attention, attentionItem{
				Kind: "external", Class: "down", Text: sum.Name + " is unreachable" + errSuffix(sum.Error), Link: sum.URL,
			})
		}
	}
	if len(d.Attention) == 0 {
		d.Attention = append(d.Attention, attentionItem{Kind: "ok", Class: "ok", Text: "Nothing needs attention."})
	}
	d.Actions = s.buildActions(ctx)
	if len(d.Actions) > 6 {
		d.Actions = d.Actions[:6]
	}
	return d
}

func (s *Server) servicesModel(r *http.Request) servicesData {
	views := s.serviceViews(r.Context())
	filter := r.URL.Query().Get("show")
	if filter == "" {
		filter = "visible"
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	d := servicesData{baseData: s.base(r, "Services", "services"), Filter: filter, Query: q, Caddy: len(s.deps.Integrations.CaddyRoutes()) > 0}
	var filtered []serviceView
	for _, v := range views {
		d.TotalCount++
		if v.IsNew {
			d.NewCount++
		}
		if v.Visibility == "hidden" || v.Ignored {
			d.HiddenCount++
		}
		if v.Exposure == "public" {
			d.PublicCount++
		}
		switch filter {
		case "all":
		case "new":
			if !v.IsNew {
				continue
			}
		case "hidden":
			if v.Visibility != "hidden" && !v.Ignored {
				continue
			}
		default:
			if v.Visibility == "hidden" || v.Ignored {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(v.Display+" "+v.Name+" "+v.Unit+" "+v.Container+" "+v.PortText+" "+v.Label+" "+v.Group), q) {
			continue
		}
		filtered = append(filtered, v)
	}
	d.Services = filtered
	return d
}

func (s *Server) updatesModel(r *http.Request) updatesData {
	updates, _ := s.deps.Store.ListUpdates(r.Context())
	filter := r.URL.Query().Get("show")
	if filter == "" {
		filter = "open"
	}
	d := updatesData{baseData: s.base(r, "Updates", "updates"), Filter: filter, Enabled: s.deps.Config.Updates.Enabled}
	var filtered []store.Update
	for _, u := range updates {
		if u.Acknowledged {
			d.AckCount++
		} else {
			d.OpenCount++
		}
		if u.Severity == "security" && !u.Acknowledged {
			d.UrgentCount++
		}
		switch filter {
		case "all":
		case "urgent":
			if u.Severity != "security" || u.Acknowledged {
				continue
			}
		case "ack":
			if !u.Acknowledged {
				continue
			}
		default:
			if u.Acknowledged {
				continue
			}
		}
		filtered = append(filtered, u)
	}
	d.Updates = filtered
	return d
}

func (s *Server) settingsModel(r *http.Request) settingsData {
	updates, _ := s.deps.Store.ListUpdates(r.Context())
	d := settingsData{
		baseData:    s.base(r, "Settings", "settings"),
		Summaries:   s.deps.Integrations.Summaries(),
		AuthMode:    s.deps.Config.Auth.Mode,
		ConfigPath:  s.deps.ConfigPath,
		StateDir:    s.deps.Config.StateDir,
		RuntimeKind: s.deps.Runtime.Kind(),
		ActionCount: len(s.deps.Actions.List()),
		UpdateCount: len(updates),
	}
	d.Channels = s.channelList()
	if d.RuntimeKind == "" {
		d.RuntimeKind = "none detected"
	}
	for _, u := range updates {
		if u.CheckedAt > d.Scanned {
			d.Scanned = u.CheckedAt
		}
	}
	return d
}

func (s *Server) channelList() []string {
	var out []string
	cfg := s.deps.Config.Alerts
	if cfg.Email != nil {
		out = append(out, "email")
	}
	if cfg.Ntfy != nil {
		out = append(out, "ntfy")
	}
	if cfg.Webhook != nil {
		out = append(out, "webhook")
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func limitStrings(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string{}, s[:n]...), "…")
}

func pctText(f float64) string {
	return itoa(int(f+0.5)) + "%"
}

func errSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + shortText(s, 80) + ")"
}
