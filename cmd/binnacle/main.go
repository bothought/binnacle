// Command binnacle is a single-binary server admin panel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bothought/binnacle/internal/actions"
	"github.com/bothought/binnacle/internal/alerts"
	"github.com/bothought/binnacle/internal/auth"
	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/hostruntime"
	"github.com/bothought/binnacle/internal/integrations"
	"github.com/bothought/binnacle/internal/ports"
	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/system"
	"github.com/bothought/binnacle/internal/updates"
	"github.com/bothought/binnacle/internal/web"
	"golang.org/x/term"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "check":
		err = checkConfig(args)
	case "auth":
		err = authCommand(args)
	case "notify":
		err = notifyCommand(args)
	case "actions":
		err = actionsCommand(args)
	case "version":
		fmt.Printf("binnacle %s (%s, %s)\n", version, commit, date)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `binnacle - server admin panel

Usage:
  binnacle serve  [--config PATH] [--demo]
  binnacle check  [--config PATH]
  binnacle auth hash
  binnacle auth totp [--account NAME]
  binnacle notify test [--config PATH] [--channel email|ntfy|webhook]
  binnacle actions list [--config PATH]
  binnacle version

The default config path is $BINNACLE_CONFIG or ~/.config/binnacle/config.yaml.`)
}

func defaultConfigPath() string {
	if v := os.Getenv("BINNACLE_CONFIG"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "binnacle", "config.yaml")
}

func serve(args []string) error {
	fs := newFlagSet("serve")
	path := fs.String("config", "", "config file")
	demo := fs.Bool("demo", false, "run demo mode on 127.0.0.1:8099")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		*path = defaultConfigPath()
	}
	var cfg *config.Config
	var err error
	if *demo {
		cfg = demoConfig()
	} else {
		cfg, err = config.Load(*path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("config file not found at %s (copy config.example.yaml and run `binnacle check --config %s`)", *path, *path)
			}
			return err
		}
		warnPermissions(*path)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := store.Open(filepath.Join(cfg.StateDir, "state.db"))
	if err != nil {
		return fmt.Errorf("open state: %w", err)
	}
	defer st.Close()

	sys := system.New()
	snap := sys.Collect(ctx)
	host := cfg.Hostname
	if host == "" {
		host = snap.Hostname
	}
	notifier := alerts.New(cfg.Alerts, st, host, cfg.BaseURL)
	actionMgr := actions.New(cfg.Actions, st, func(run store.Run) {
		if !notifier.Enabled() {
			return
		}
		notifier.Notify(ctx, alerts.Event{
			Type: "action_failed", Urgent: false,
			Title:   "Action failed: " + run.Label,
			Message: fmt.Sprintf("Exit %d\n%s\n\n%s", run.ExitCode, run.Error, truncate(run.Output, 1500)),
			URL:     cfg.BaseURL + "/runs/" + run.ID, Fingerprint: run.ActionID,
		})
	})
	rt := hostruntime.New()
	portCollector := ports.New(cfg.Collector, rt)
	integrationsMgr := integrations.New(cfg.Integrations)
	updateMgr := updates.New(cfg.Updates, st, rt)
	authMgr := auth.New(cfg.Auth, st)

	if *demo {
		seedDemo(ctx, st, sys)
	}

	webServer, err := web.New(web.Deps{
		Config: cfg, ConfigPath: *path, Store: st, Auth: authMgr, System: sys,
		Integrations: integrationsMgr, Actions: actionMgr, Runtime: rt, Notifier: notifier,
		Version: version, Demo: *demo,
	})
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           webServer,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// Bind before the first port scan so the panel does not discover itself as
	// a brand-new service after the baseline was established.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(ln) }()

	if !*demo {
		go notifier.Worker(ctx)
		go systemLoop(ctx, sys, st, notifier, cfg, snap)
		go portsLoop(ctx, portCollector, st, notifier, cfg.Collector.Interval.Value())
		go integrationsLoop(ctx, integrationsMgr)
		if cfg.Updates.Enabled {
			go updatesLoop(ctx, updateMgr, st, notifier, cfg)
		}
		go digestLoop(ctx, st, notifier, cfg, host)
		go cleanupLoop(ctx, st)
	}

	log.Printf("binnacle %s listening on http://%s (auth=%s, runtime=%s)", version, cfg.Listen, cfg.Auth.Mode, rt.Kind())
	if *demo {
		log.Printf("demo mode: authentication bypassed, actions disabled, listen forced to 127.0.0.1")
	}

	select {
	case err := <-serveErr:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}
	return nil
}

func systemLoop(ctx context.Context, sys *system.Collector, st *store.Store, n *alerts.Notifier, cfg *config.Config, initial system.Snapshot) {
	lastFailed := map[string]bool{}
	for _, u := range initial.FailedUnits {
		lastFailed[u] = true
	}
	lastSample := time.Now()
	lastPrune := time.Now()
	alertDisk(sys.Latest(), n, cfg)
	ticker := time.NewTicker(cfg.Collector.MetricsInterval.Value())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := sys.Collect(ctx)
			if time.Since(lastSample) >= time.Minute {
				lastSample = time.Now()
				diskMax := 0.0
				for _, d := range snap.Disks {
					if d.Percent > diskMax {
						diskMax = d.Percent
					}
				}
				_ = st.InsertMetricSample(ctx, store.MetricSample{
					TS: snap.At.Unix(), CPU: snap.CPUPercent, Mem: snap.MemPercent, Disk: diskMax,
					Load1: snap.Load1, NetRx: snap.NetRx, NetTx: snap.NetTx,
				})
			}
			if time.Since(lastPrune) > time.Hour {
				lastPrune = time.Now()
				_ = st.PruneMetrics(ctx, time.Now().Add(-24*time.Hour).Unix())
			}
			for _, u := range snap.FailedUnits {
				if !lastFailed[u] {
					lastFailed[u] = true
					if n.Enabled() {
						n.Notify(ctx, alerts.Event{
							Type: "unit_failed", Title: "Failed systemd unit: " + u,
							Message: "The unit entered a failed state on " + snap.Hostname + ".",
							URL:     cfg.BaseURL + "/settings", Fingerprint: u,
						})
					}
				}
			}
			for u := range lastFailed {
				found := false
				for _, x := range snap.FailedUnits {
					if x == u {
						found = true
						break
					}
				}
				if !found {
					delete(lastFailed, u)
				}
			}
			alertDisk(snap, n, cfg)
		}
	}
}

func alertDisk(snap system.Snapshot, n *alerts.Notifier, cfg *config.Config) {
	if !n.Enabled() {
		return
	}
	for _, d := range snap.Disks {
		if d.Percent >= cfg.Collector.DiskWarnPercent {
			n.Notify(context.Background(), alerts.Event{
				Type: "disk", Title: fmt.Sprintf("Disk %s is %.0f%% full", d.Mount, d.Percent),
				Message: fmt.Sprintf("%s is using %.1f%% of %s.", d.Mount, d.Percent, humanBytes(d.Total)),
				URL:     cfg.BaseURL, Fingerprint: d.Mount,
			})
		}
	}
}

func portsLoop(ctx context.Context, collector *ports.Collector, st *store.Store, n *alerts.Notifier, interval time.Duration) {
	baseline, _ := st.BaselineAt(ctx)
	scan := func() {
		services, err := collector.Scan(ctx)
		if err != nil {
			log.Printf("ports: scan: %v", err)
			return
		}
		res, err := st.SyncServices(ctx, services)
		if err != nil {
			log.Printf("ports: sync: %v", err)
			return
		}
		if baseline == 0 {
			baseline = time.Now().Unix()
			_ = st.SetBaseline(ctx, baseline)
			return
		}
		notifyServiceChanges(ctx, n, res)
	}
	scan()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}

func notifyServiceChanges(ctx context.Context, n *alerts.Notifier, res store.SyncResult) {
	if !n.Enabled() {
		return
	}
	for _, sv := range res.Created {
		if sv.Ignored || sv.Muted {
			continue
		}
		n.Notify(ctx, alerts.Event{
			Type: "new_service", Title: "New service: " + sv.DisplayName(),
			Message:     fmt.Sprintf("%s is listening on %s (%s).", sv.DisplayName(), portString(sv.Ports), exposureString(sv.Exposure)),
			Fingerprint: sv.Key,
		})
	}
	for _, sv := range res.ExposureChanged {
		if sv.Ignored || sv.Muted {
			continue
		}
		n.Notify(ctx, alerts.Event{
			Type: "exposure", Urgent: sv.Exposure == "public",
			Title:       "Service exposure changed: " + sv.DisplayName(),
			Message:     fmt.Sprintf("%s is now %s on %s.", sv.DisplayName(), exposureString(sv.Exposure), portString(sv.Ports)),
			Fingerprint: sv.Key + ":" + sv.Exposure,
		})
	}
	for _, sv := range res.Lost {
		if sv.Ignored || sv.Muted {
			continue
		}
		n.Notify(ctx, alerts.Event{
			Type: "service_down", Title: "Service disappeared: " + sv.DisplayName(),
			Message:     fmt.Sprintf("%s is no longer listening on %s.", sv.DisplayName(), portString(sv.Ports)),
			Fingerprint: sv.Key,
		})
	}
	for _, sv := range res.Returned {
		if sv.Ignored || sv.Muted {
			continue
		}
		n.Notify(ctx, alerts.Event{
			Type: "service_up", Title: "Service returned: " + sv.DisplayName(),
			Message:     fmt.Sprintf("%s is listening again on %s.", sv.DisplayName(), portString(sv.Ports)),
			Fingerprint: sv.Key,
		})
	}
}

func integrationsLoop(ctx context.Context, m *integrations.Manager) {
	time.Sleep(time.Second)
	m.Refresh(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Refresh(ctx)
		}
	}
}

func updatesLoop(ctx context.Context, m *updates.Manager, st *store.Store, n *alerts.Notifier, cfg *config.Config) {
	if !cfg.Updates.Enabled {
		return
	}
	time.Sleep(10 * time.Second)
	for {
		res := m.Check(ctx)
		if len(res.Errors) > 0 {
			log.Printf("updates: %d error(s): %s", len(res.Errors), strings.Join(res.Errors, "; "))
		} else {
			log.Printf("updates: checked %d update(s)", res.Count)
		}
		if n.Handles("urgent_update") {
			urgent, _ := st.UnnotifiedUrgent(ctx)
			for _, u := range urgent {
				n.Notify(ctx, alerts.Event{
					Type: "urgent_update", Urgent: true,
					Title:   "Security update: " + u.Name,
					Message: fmt.Sprintf("%s %s → %s\n%s", u.Name, u.Current, u.Latest, u.URL),
					URL:     cfg.BaseURL + "/updates", Fingerprint: u.Key + ":" + u.Latest,
				})
				_ = st.MarkUpdateNotified(ctx, u.Key, u.Latest)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.Updates.Interval.Value()):
		}
	}
}

func cleanupLoop(ctx context.Context, st *store.Store) {
	run := func() {
		now := time.Now()
		_ = st.DeleteExpiredSessions(ctx)
		_ = st.PruneRuns(ctx, now.Add(-90*24*time.Hour).Unix())
		_ = st.PruneNotifications(ctx, now.Add(-30*24*time.Hour).Unix())
		_ = st.PruneServiceEvents(ctx, now.Add(-90*24*time.Hour).Unix())
		_ = st.PruneMetrics(ctx, now.Add(-24*time.Hour).Unix())
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func digestLoop(ctx context.Context, st *store.Store, n *alerts.Notifier, cfg *config.Config, host string) {
	if !cfg.Alerts.Enabled || !cfg.Alerts.Digest || !n.Enabled() {
		return
	}
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			if now.Hour() != cfg.Alerts.DigestHour {
				continue
			}
			key := "digest:" + now.Format("2006-01-02")
			if _, ok, _ := st.GetSetting(ctx, key); ok {
				continue
			}
			body, count := buildDigest(ctx, st)
			if count == 0 {
				_ = st.SetSetting(ctx, key, "empty")
				continue
			}
			channels := cfg.Alerts.Rules["digest"]
			if len(channels) == 0 {
				channels = n.Configured()
			}
			n.NotifyChannels(ctx, alerts.Event{Type: "digest", Title: "Daily summary for " + host, Message: body, URL: cfg.BaseURL}, channels)
			_ = st.SetSetting(ctx, key, "sent")
		}
	}
}

func buildDigest(ctx context.Context, st *store.Store) (string, int) {
	updates, _ := st.ListUpdates(ctx)
	var lines []string
	count := 0
	for _, u := range updates {
		if u.Acknowledged {
			continue
		}
		count++
		lines = append(lines, fmt.Sprintf("- [%s] %s %s → %s", u.Severity, u.Name, u.Current, u.Latest))
	}
	if count == 0 {
		return "", 0
	}
	sort.Strings(lines)
	return fmt.Sprintf("%d open update(s):\n\n%s", count, strings.Join(lines, "\n")), count
}

func checkConfig(args []string) error {
	fs := newFlagSet("check")
	path := fs.String("config", "", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		*path = defaultConfigPath()
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	fmt.Printf("ok: %s\nlisten: %s\nauth: %s\nactions: %d\nupdates: %v\n", *path, cfg.Listen, cfg.Auth.Mode, len(cfg.Actions), cfg.Updates.Enabled)
	return nil
}

func authCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: binnacle auth hash|totp")
	}
	switch args[0] {
	case "hash":
		var pw string
		if v := os.Getenv("BINNACLE_PASSWORD"); v != "" {
			pw = v
		} else {
			fmt.Fprint(os.Stderr, "Password: ")
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr)
			fmt.Fprint(os.Stderr, "Repeat: ")
			b2, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr)
			if string(b) != string(b2) {
				return fmt.Errorf("passwords do not match")
			}
			pw = string(b)
		}
		if len(pw) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		fmt.Println(hash)
		return nil
	case "totp":
		fs := newFlagSet("auth totp")
		account := fs.String("account", "admin", "account name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		secret, url, err := auth.GenerateTOTP(*account)
		if err != nil {
			return err
		}
		fmt.Printf("secret: %s\nuri:    %s\n", secret, url)
		return nil
	}
	return fmt.Errorf("unknown auth command %q", args[0])
}

func notifyCommand(args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return fmt.Errorf("usage: binnacle notify test [--config PATH] [--channel NAME]")
	}
	fs := newFlagSet("notify test")
	path := fs.String("config", "", "config file")
	channel := fs.String("channel", "", "channel name")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" {
		*path = defaultConfigPath()
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.StateDir, "state.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	host := cfg.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	n := alerts.New(cfg.Alerts, st, host, cfg.BaseURL)
	if len(n.Configured()) == 0 {
		return fmt.Errorf("no notification channels configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.Test(ctx, *channel); err != nil {
		return err
	}
	fmt.Println("sent")
	return nil
}

func actionsCommand(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: binnacle actions list [--config PATH]")
	}
	fs := newFlagSet("actions list")
	path := fs.String("config", "", "config file")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" {
		*path = defaultConfigPath()
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	for _, a := range cfg.Actions {
		fmt.Printf("%-20s %-28s %s\n", a.ID, a.Label, strings.Join(a.Command, " "))
	}
	return nil
}

func demoConfig() *config.Config {
	dir, err := os.MkdirTemp("", "binnacle-demo-*")
	if err != nil {
		log.Fatalf("demo state: %v", err)
	}
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:8099"
	cfg.BaseURL = "http://127.0.0.1:8099"
	cfg.StateDir = dir
	cfg.Auth.Mode = "forward"
	cfg.Updates.Enabled = true
	cfg.Actions = nil
	cfg.Alerts.Enabled = false
	return cfg
}

func seedDemo(ctx context.Context, st *store.Store, sys *system.Collector) {
	now := time.Now().Unix()
	host := sys.Latest().Hostname
	if host == "" {
		host = "demo-host"
	}
	services := []store.Service{
		{Key: "unit:caddy.service", Name: "caddy", Kind: "systemd", Unit: "caddy.service", Ports: []store.Port{{Proto: "tcp", Port: 443}, {Proto: "tcp", Port: 80}}, Exposure: "public", FirstSeen: now - 86400, Label: "Caddy", URL: "https://example.com"},
		{Key: "unit:beszel-hub.service", Name: "beszel-hub", Kind: "systemd", Unit: "beszel-hub.service", Ports: []store.Port{{Proto: "tcp", Port: 8091}}, Exposure: "loopback", FirstSeen: now - 86400, Label: "Beszel"},
		{Key: "unit:authelia.service", Name: "authelia", Kind: "systemd", Unit: "authelia.service", Ports: []store.Port{{Proto: "tcp", Port: 9091}}, Exposure: "loopback", FirstSeen: now - 86400, Label: "Authelia"},
		{Key: "container:comfyui", Name: "comfyui", Kind: "container", Container: "comfyui", Image: "ghcr.io/example/comfyui:latest", Ports: []store.Port{{Proto: "tcp", Port: 8188}}, Exposure: "tailnet", FirstSeen: now - 86400, Label: "ComfyUI"},
		{Key: "container:binnacle", Name: "binnacle", Kind: "container", Container: "binnacle", Image: "ghcr.io/bothought/binnacle:latest", Ports: []store.Port{{Proto: "tcp", Port: 8099}}, Exposure: "loopback", FirstSeen: now - 120},
	}
	_, _ = st.SyncServices(ctx, services)
	_ = st.SetBaseline(ctx, now-3600)
	_ = st.UpdateServiceMeta(ctx, "unit:caddy.service", "Caddy", "Reverse proxy", "https://example.com", "infra", "public", false, false, "demo")
	_ = st.UpdateServiceMeta(ctx, "unit:beszel-hub.service", "Beszel", "Host metrics", "", "infra", "internal", false, false, "demo")
	_ = st.UpdateServiceMeta(ctx, "unit:authelia.service", "Authelia", "Forward authentication", "", "infra", "internal", false, false, "demo")
	_ = st.UpdateServiceMeta(ctx, "container:comfyui", "ComfyUI", "Image generation", "", "media", "internal", true, false, "demo")
	_ = st.UpsertUpdate(ctx, store.Update{Key: "app:uptime-kuma", Name: "Uptime Kuma", Current: "1.23.16", Latest: "1.23.17", Severity: "security", Source: "app", URL: "https://github.com/louislam/uptime-kuma/releases", Notes: "Fixes a security issue. Demo data.", CheckedAt: now})
	_ = st.UpsertUpdate(ctx, store.Update{Key: "container:caddy", Name: "Caddy", Current: "2.11.9", Latest: "2.12.0", Severity: "major", Source: "container", URL: "https://github.com/caddyserver/caddy/releases", Notes: "Major release. Demo data.", CheckedAt: now})
	_ = st.UpsertUpdate(ctx, store.Update{Key: "flatpak:com.example.App", Name: "com.example.App", Current: "1.0", Latest: "1.1", Severity: "minor", Source: "flatpak", URL: "https://flathub.org", Notes: "Demo data.", CheckedAt: now})
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func warnPermissions(path string) {
	st, err := os.Stat(path)
	if err == nil && st.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: %s is readable by other users; it may contain secrets", path)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func exposureString(e string) string {
	switch e {
	case "loopback":
		return "local"
	case "lan":
		return "LAN"
	case "tailnet":
		return "tailnet"
	case "public":
		return "public"
	}
	return e
}

func portString(ports []store.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%d/%s", p.Port, p.Proto))
	}
	return strings.Join(parts, ", ")
}

func humanBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	for _, u := range units {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", v/1024)
}
