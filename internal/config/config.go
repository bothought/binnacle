// Package config loads and validates the Binnacle configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that accepts strings such as "10s" in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a string")
	}
	v, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) Value() time.Duration { return time.Duration(d) }

// Config is the root configuration document.
type Config struct {
	Listen   string `yaml:"listen"`
	BaseURL  string `yaml:"base_url"`
	StateDir string `yaml:"state_dir"`
	Hostname string `yaml:"hostname"`

	Auth         AuthConfig         `yaml:"auth"`
	Collector    CollectorConfig    `yaml:"collector"`
	Integrations IntegrationsConfig `yaml:"integrations"`
	Updates      UpdatesConfig      `yaml:"updates"`
	Actions      []ActionConfig     `yaml:"actions"`
	Alerts       AlertsConfig       `yaml:"alerts"`
}

type AuthConfig struct {
	Mode       string        `yaml:"mode"` // forward or local
	SessionTTL Duration      `yaml:"session_ttl"`
	Forward    ForwardConfig `yaml:"forward"`
	Local      LocalConfig   `yaml:"local"`
}

type ForwardConfig struct {
	TrustedProxies    []string `yaml:"trusted_proxies"`
	UserHeader        string   `yaml:"user_header"`
	EmailHeader       string   `yaml:"email_header"`
	GroupsHeader      string   `yaml:"groups_header"`
	AdminGroups       []string `yaml:"admin_groups"`
	ViewerGroups      []string `yaml:"viewer_groups"`
	ProxySecret       string   `yaml:"proxy_secret"`
	ProxySecretHeader string   `yaml:"proxy_secret_header"`
	LogoutURL         string   `yaml:"logout_url"`
}

type LocalConfig struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	TOTPSecret   string `yaml:"totp_secret"`
}

type CollectorConfig struct {
	Interval        Duration `yaml:"interval"`
	MetricsInterval Duration `yaml:"metrics_interval"`
	IgnorePatterns  []string `yaml:"ignore_patterns"`
	DiskWarnPercent float64  `yaml:"disk_warn_percent"`
}

type IntegrationsConfig struct {
	Beszel     *BeszelConfig       `yaml:"beszel"`
	UptimeKuma *KumaConfig         `yaml:"uptime_kuma"`
	Caddy      *CaddyConfig        `yaml:"caddy"`
	Custom     []CustomIntegration `yaml:"custom"`
}

type BeszelConfig struct {
	URL         string `yaml:"url"`
	Auth        string `yaml:"auth"` // forward, password, none
	Email       string `yaml:"email"`
	Password    string `yaml:"password"`
	RemoteEmail string `yaml:"remote_email"`
}

type KumaConfig struct {
	URL     string            `yaml:"url"`
	Headers map[string]string `yaml:"headers"`
}

type CaddyConfig struct {
	AdminURL string `yaml:"admin_url"`
}

type CustomIntegration struct {
	Name       string            `yaml:"name"`
	URL        string            `yaml:"url"`
	Headers    map[string]string `yaml:"headers"`
	StatusPath string            `yaml:"status_path"`
	TitlePath  string            `yaml:"title_path"`
	DetailPath string            `yaml:"detail_path"`
	LinkPath   string            `yaml:"link_path"`
}

type UpdatesConfig struct {
	Enabled     bool        `yaml:"enabled"`
	Interval    Duration    `yaml:"interval"`
	GitHubToken string      `yaml:"github_token"`
	Containers  bool        `yaml:"containers"`
	Flatpak     bool        `yaml:"flatpak"`
	RPMOstree   bool        `yaml:"rpm_ostree"`
	Apps        []AppConfig `yaml:"apps"`
}

type AppConfig struct {
	Name           string   `yaml:"name"`
	Repo           string   `yaml:"repo"`
	VersionCommand []string `yaml:"version_command"`
	VersionRegex   string   `yaml:"version_regex"`
	MatchUnit      string   `yaml:"match_unit"`
	MatchContainer string   `yaml:"match_container"`
}

type ActionConfig struct {
	ID          string   `yaml:"id"`
	Label       string   `yaml:"label"`
	Description string   `yaml:"description"`
	Category    string   `yaml:"category"`
	Command     []string `yaml:"command"`
	Timeout     Duration `yaml:"timeout"`
	Confirm     bool     `yaml:"confirm"`
	Dangerous   bool     `yaml:"dangerous"`
}

type AlertsConfig struct {
	Enabled    bool                `yaml:"enabled"`
	Email      *EmailConfig        `yaml:"email"`
	Ntfy       *NtfyConfig         `yaml:"ntfy"`
	Webhook    *WebhookConfig      `yaml:"webhook"`
	Rules      map[string][]string `yaml:"rules"`
	QuietHours string              `yaml:"quiet_hours"`
	DigestHour int                 `yaml:"digest_hour"`
	Digest     bool                `yaml:"digest"`
	Cooldown   Duration            `yaml:"cooldown"`
}

type EmailConfig struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:"to"`
	TLS      string   `yaml:"tls"` // starttls, tls, none
}

type NtfyConfig struct {
	URL   string `yaml:"url"`
	Topic string `yaml:"topic"`
	Token string `yaml:"token"`
}

type WebhookConfig struct {
	URL     string            `yaml:"url"`
	Format  string            `yaml:"format"` // generic, discord, slack
	Headers map[string]string `yaml:"headers"`
}

// Default returns the built-in configuration. It is intentionally opinionated:
// loopback-only, host-native, and safe unless the user explicitly opts out.
func Default() *Config {
	return &Config{
		Listen:   "127.0.0.1:8099",
		StateDir: "~/.local/state/binnacle",
		Auth: AuthConfig{
			Mode:       "local",
			SessionTTL: Duration(12 * time.Hour),
			Forward: ForwardConfig{
				TrustedProxies:    []string{"127.0.0.1", "::1"},
				UserHeader:        "Remote-User",
				EmailHeader:       "Remote-Email",
				GroupsHeader:      "Remote-Groups",
				ProxySecretHeader: "X-Binnacle-Proxy-Secret",
			},
		},
		Collector: CollectorConfig{
			Interval:        Duration(10 * time.Second),
			MetricsInterval: Duration(5 * time.Second),
			IgnorePatterns:  DefaultIgnorePatterns,
			DiskWarnPercent: 90,
		},
		Updates: UpdatesConfig{
			Enabled:    true,
			Interval:   Duration(6 * time.Hour),
			Containers: true,
			Flatpak:    true,
			RPMOstree:  true,
		},
		Alerts: AlertsConfig{
			Enabled:    true,
			Digest:     true,
			DigestHour: 9,
			Cooldown:   Duration(6 * time.Hour),
		},
	}
}

// DefaultIgnorePatterns suppresses the usual desktop noise. They are still
// stored in the inventory and visible under "system"; they simply do not
// produce new-service alerts or clutter the default view.
var DefaultIgnorePatterns = []string{
	"*steam*", "*kdeconnect*", "*avahi*", "*cups*", "systemd-resolve*",
	"*rpcbind*", "*mdns*", "*pipewire*", "*wireplumber*", "*gvfs*",
	"*dconf*", "*at-spi*", "dbus-*", "xdg-*", "*kwallet*", "*kactivity*",
	"*geoclue*", "*xwayland*", "*krdp*", "*sunshine*", "*wayvnc*",
}

// Load reads, expands, decodes and validates a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadBytes(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// LoadBytes decodes configuration from bytes. Unknown keys are rejected.
func LoadBytes(b []byte) (*Config, error) {
	expanded, err := ExpandEnv(string(b))
	if err != nil {
		return nil, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader([]byte(expanded)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandEnv replaces ${VAR} with the environment value. A missing variable is
// an error rather than silently becoming an empty secret. YAML comments are
// left alone, so examples can mention ${VARS} without requiring them.
func ExpandEnv(s string) (string, error) {
	var missing []string
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		code, comment := splitYAMLComment(line)
		code = envPattern.ReplaceAllStringFunc(code, func(m string) string {
			name := m[2 : len(m)-1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
				return m
			}
			return v
		})
		lines[i] = code + comment
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("environment variable(s) not set: %s", strings.Join(missing, ", "))
	}
	return strings.Join(lines, "\n"), nil
}

// splitYAMLComment separates an unquoted # comment from the value portion.
func splitYAMLComment(line string) (code, comment string) {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && (i == 0 || line[i-1] != '\\') {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
				return line[:i], line[i:]
			}
		}
	}
	return line, ""
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.BaseURL != "" {
		u, err := url.Parse(c.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("base_url must be an absolute http(s) URL")
		}
		c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	}
	if c.StateDir == "" {
		return errors.New("state_dir is required")
	}
	c.StateDir = expandHome(c.StateDir)
	if c.Collector.Interval.Value() < time.Second {
		return errors.New("collector.interval must be at least 1s")
	}
	if c.Collector.MetricsInterval.Value() < time.Second {
		return errors.New("collector.metrics_interval must be at least 1s")
	}
	if c.Collector.DiskWarnPercent <= 0 || c.Collector.DiskWarnPercent > 100 {
		return errors.New("collector.disk_warn_percent must be between 1 and 100")
	}
	if len(c.Collector.IgnorePatterns) == 0 {
		c.Collector.IgnorePatterns = DefaultIgnorePatterns
	}
	switch c.Auth.Mode {
	case "forward":
		if len(c.Auth.Forward.TrustedProxies) == 0 {
			return errors.New("auth.forward.trusted_proxies must not be empty")
		}
		for _, p := range c.Auth.Forward.TrustedProxies {
			if net.ParseIP(p) == nil {
				if _, _, err := net.ParseCIDR(p); err != nil {
					return fmt.Errorf("auth.forward.trusted_proxies: invalid IP or CIDR %q", p)
				}
			}
		}
		if c.Auth.Forward.UserHeader == "" {
			c.Auth.Forward.UserHeader = "Remote-User"
		}
		if c.Auth.Forward.GroupsHeader == "" {
			c.Auth.Forward.GroupsHeader = "Remote-Groups"
		}
		if c.Auth.Forward.ProxySecretHeader == "" {
			c.Auth.Forward.ProxySecretHeader = "X-Binnacle-Proxy-Secret"
		}
		if c.Auth.Forward.LogoutURL != "" {
			if err := validateHTTPURL(c.Auth.Forward.LogoutURL); err != nil {
				return fmt.Errorf("auth.forward.logout_url: %w", err)
			}
		}
	case "local":
		if c.Auth.Local.Username == "" {
			return errors.New("auth.local.username is required")
		}
		if !strings.HasPrefix(c.Auth.Local.PasswordHash, "$argon2id$") {
			return errors.New("auth.local.password_hash must be an argon2id hash (run: binnacle auth hash)")
		}
	default:
		return fmt.Errorf("auth.mode must be forward or local, got %q", c.Auth.Mode)
	}
	if c.Auth.SessionTTL.Value() < time.Minute {
		return errors.New("auth.session_ttl must be at least 1m")
	}

	seen := map[string]bool{}
	for i := range c.Actions {
		a := &c.Actions[i]
		if a.ID == "" {
			return fmt.Errorf("actions[%d].id is required", i)
		}
		if seen[a.ID] {
			return fmt.Errorf("duplicate action id %q", a.ID)
		}
		seen[a.ID] = true
		if a.Label == "" {
			a.Label = a.ID
		}
		if len(a.Command) == 0 {
			return fmt.Errorf("action %q: command is required", a.ID)
		}
		if _, err := exec.LookPath(a.Command[0]); err != nil {
			return fmt.Errorf("action %q: command %q not found", a.ID, a.Command[0])
		}
		if a.Timeout.Value() <= 0 {
			a.Timeout = Duration(60 * time.Second)
		}
		if a.Timeout.Value() > 30*time.Minute {
			return fmt.Errorf("action %q: timeout is capped at 30m", a.ID)
		}
	}
	if c.Updates.Interval.Value() < time.Minute {
		return errors.New("updates.interval must be at least 1m")
	}
	for i := range c.Updates.Apps {
		a := &c.Updates.Apps[i]
		if a.Name == "" {
			return fmt.Errorf("updates.apps[%d].name is required", i)
		}
		if a.Repo == "" && len(a.VersionCommand) == 0 {
			return fmt.Errorf("updates.apps[%d] needs repo or version_command", i)
		}
		if a.VersionRegex != "" {
			if _, err := regexp.Compile(a.VersionRegex); err != nil {
				return fmt.Errorf("updates.apps[%d].version_regex: %w", i, err)
			}
		}
		if len(a.VersionCommand) > 0 {
			if _, err := exec.LookPath(a.VersionCommand[0]); err != nil {
				return fmt.Errorf("updates.apps[%d]: command %q not found", i, a.VersionCommand[0])
			}
		}
	}
	if err := validateIntegration("beszel", c.Integrations.Beszel); err != nil {
		return err
	}
	if c.Integrations.Beszel != nil {
		if c.Integrations.Beszel.Auth == "" {
			c.Integrations.Beszel.Auth = "none"
		}
		switch c.Integrations.Beszel.Auth {
		case "none", "forward", "password":
		default:
			return errors.New("integrations.beszel.auth must be none, forward or password")
		}
	}
	if err := validateIntegration("uptime_kuma", c.Integrations.UptimeKuma); err != nil {
		return err
	}
	if c.Integrations.Caddy != nil {
		if c.Integrations.Caddy.AdminURL == "" {
			c.Integrations.Caddy.AdminURL = "http://127.0.0.1:2019"
		}
		if err := validateHTTPURL(c.Integrations.Caddy.AdminURL); err != nil {
			return fmt.Errorf("integrations.caddy.admin_url: %w", err)
		}
	}
	for i := range c.Integrations.Custom {
		x := &c.Integrations.Custom[i]
		if x.Name == "" || x.URL == "" {
			return fmt.Errorf("integrations.custom[%d]: name and url are required", i)
		}
		if err := validateHTTPURL(x.URL); err != nil {
			return fmt.Errorf("integrations.custom[%d].url: %w", i, err)
		}
	}
	if err := c.Alerts.Validate(); err != nil {
		return err
	}
	return nil
}

func validateIntegration(name string, v any) error {
	switch x := v.(type) {
	case *BeszelConfig:
		if x == nil {
			return nil
		}
		if err := validateHTTPURL(x.URL); err != nil {
			return fmt.Errorf("integrations.%s.url: %w", name, err)
		}
	case *KumaConfig:
		if x == nil {
			return nil
		}
		if err := validateHTTPURL(x.URL); err != nil {
			return fmt.Errorf("integrations.%s.url: %w", name, err)
		}
	}
	return nil
}

func (a *AlertsConfig) Validate() error {
	if a.Cooldown.Value() <= 0 {
		a.Cooldown = Duration(6 * time.Hour)
	}
	if a.DigestHour < 0 || a.DigestHour > 23 {
		return errors.New("alerts.digest_hour must be 0-23")
	}
	if a.QuietHours != "" {
		if _, _, err := ParseQuietHours(a.QuietHours); err != nil {
			return err
		}
	}
	if a.Email != nil {
		if a.Email.Host == "" || a.Email.From == "" || len(a.Email.To) == 0 {
			return errors.New("alerts.email requires host, from and to")
		}
		if a.Email.Port == 0 {
			a.Email.Port = 587
		}
		if a.Email.TLS == "" {
			a.Email.TLS = "starttls"
		}
		switch a.Email.TLS {
		case "starttls", "tls", "none":
		default:
			return errors.New("alerts.email.tls must be starttls, tls or none")
		}
	}
	if a.Ntfy != nil {
		if a.Ntfy.URL == "" || a.Ntfy.Topic == "" {
			return errors.New("alerts.ntfy requires url and topic")
		}
		if err := validateHTTPURL(a.Ntfy.URL); err != nil {
			return fmt.Errorf("alerts.ntfy.url: %w", err)
		}
	}
	if a.Webhook != nil {
		if a.Webhook.URL == "" {
			return errors.New("alerts.webhook.url is required")
		}
		if err := validateHTTPURL(a.Webhook.URL); err != nil {
			return fmt.Errorf("alerts.webhook.url: %w", err)
		}
		if a.Webhook.Format == "" {
			a.Webhook.Format = "generic"
		}
		switch a.Webhook.Format {
		case "generic", "discord", "slack":
		default:
			return errors.New("alerts.webhook.format must be generic, discord or slack")
		}
	}
	for event, channels := range a.Rules {
		for _, ch := range channels {
			switch ch {
			case "email", "ntfy", "webhook":
			default:
				return fmt.Errorf("alerts.rules.%s: unknown channel %q", event, ch)
			}
		}
	}
	return nil
}

// ParseQuietHours parses "23:00-08:00". It supports windows crossing midnight.
func ParseQuietHours(s string) (start, end int, err error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("quiet_hours must look like 23:00-08:00")
	}
	parse := func(v string) (int, error) {
		t, err := time.Parse("15:04", strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("quiet_hours: %w", err)
		}
		return t.Hour()*60 + t.Minute(), nil
	}
	start, err = parse(parts[0])
	if err != nil {
		return 0, 0, err
	}
	end, err = parse(parts[1])
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

func validateHTTPURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must be an http(s) URL")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
