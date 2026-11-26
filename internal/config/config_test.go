package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadForwardDefaults(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
listen: 127.0.0.1:8099
state_dir: /tmp/binnacle-test
auth:
  mode: forward
  forward:
    trusted_proxies: ["127.0.0.1", "10.0.0.0/8"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Collector.Interval.Value().Seconds() != 10 {
		t.Errorf("interval = %s", cfg.Collector.Interval)
	}
	if cfg.Auth.Forward.UserHeader != "Remote-User" {
		t.Errorf("user header = %q", cfg.Auth.Forward.UserHeader)
	}
	if len(cfg.Collector.IgnorePatterns) == 0 {
		t.Error("expected default ignore patterns")
	}
	if !cfg.Updates.Enabled {
		t.Error("updates should default to enabled")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := LoadBytes([]byte(`
listen: 127.0.0.1:8099
state_dir: /tmp/x
nonsense: true
auth:
  mode: forward
`))
	if err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("TEST_DOMAIN", "admin.example.com")
	cfg, err := LoadBytes([]byte(`
listen: 127.0.0.1:8099
base_url: https://${TEST_DOMAIN}
state_dir: /tmp/x
auth:
  mode: forward
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://admin.example.com" {
		t.Errorf("base_url = %q", cfg.BaseURL)
	}

	t.Setenv("EMPTY_OK", "")
	_, err = LoadBytes([]byte(`
listen: 127.0.0.1:8099
state_dir: /tmp/x
base_url: https://${MISSING_VAR}
auth:
  mode: forward
`))
	if err == nil || !strings.Contains(err.Error(), "MISSING_VAR") {
		t.Fatalf("expected missing env error, got %v", err)
	}
}

func TestLocalAuthRequiresHash(t *testing.T) {
	_, err := LoadBytes([]byte(`
listen: 127.0.0.1:8099
state_dir: /tmp/x
auth:
  mode: local
  local:
    username: admin
`))
	if err == nil || !strings.Contains(err.Error(), "password_hash") {
		t.Fatalf("expected hash error, got %v", err)
	}
}

func TestQuietHours(t *testing.T) {
	start, end, err := ParseQuietHours("23:00-08:00")
	if err != nil {
		t.Fatal(err)
	}
	if start != 23*60 || end != 8*60 {
		t.Fatalf("start=%d end=%d", start, end)
	}
	if _, _, err := ParseQuietHours("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestActionCommandMustExist(t *testing.T) {
	_, err := LoadBytes([]byte(`
listen: 127.0.0.1:8099
state_dir: /tmp/x
auth:
  mode: forward
actions:
  - id: nope
    label: Nope
    command: [/definitely/not/a/command]
`))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected command error, got %v", err)
	}
}

func TestExpandHome(t *testing.T) {
	home, _ := os.UserHomeDir()
	if got := expandHome("~/state"); got != home+"/state" {
		t.Fatalf("got %q", got)
	}
}

func TestExpandEnvIgnoresComments(t *testing.T) {
	t.Setenv("TEST_HOST", "example.com")
	out, err := ExpandEnv("# ${DOES_NOT_EXIST}\nhost: ${TEST_HOST} # ${ALSO_MISSING}\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "host: example.com") || !strings.Contains(out, "${ALSO_MISSING}") {
		t.Fatalf("unexpected expansion: %q", out)
	}
	if !strings.Contains(out, "${DOES_NOT_EXIST}") {
		t.Fatalf("comment was expanded: %q", out)
	}
}
