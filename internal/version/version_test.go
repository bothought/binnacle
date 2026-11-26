package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.4", -1},
		{"v2.0.0", "1.9.9", 1},
		{"2026.914.233613", "2026.1000.1", -1},
		{"2.0.1", "2.0.1", 0},
		{"2.0.1", "2.0.1-rc1", 1},
		{"1.0", "1.0.0", 0},
		{"", "", 0},
	}
	for _, tt := range tests {
		if got := Compare(tt.a, tt.b); got != tt.want {
			t.Errorf("Compare(%q,%q)=%d want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSeverity(t *testing.T) {
	tests := []struct{ current, latest, want string }{
		{"1.9.9", "2.0.0", "major"},
		{"2.0.0", "2.1.0", "minor"},
		{"2.0.1", "2.0.2", "patch"},
		{"2.0.2", "2.0.2", "none"},
		{"", "2.0.0", "unknown"},
	}
	for _, tt := range tests {
		if got := Severity(tt.current, tt.latest); got != tt.want {
			t.Errorf("Severity(%q,%q)=%q want %q", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestLooksSecurity(t *testing.T) {
	cases := map[string]bool{
		"Fixes CVE-2026-12345":      true,
		"GHSA-abcd-efgh-ijkl fixed": true,
		"Regular release notes":     false,
		"Security hardening":        true,
	}
	for notes, want := range cases {
		if got := LooksSecurity(notes); got != want {
			t.Errorf("LooksSecurity(%q)=%v want %v", notes, got, want)
		}
	}
}

func TestExtract(t *testing.T) {
	if got := Extract("caddy version v2.11.9 built"); got != "2.11.9" {
		t.Fatalf("got %q", got)
	}
	if got := Extract("no version here"); got != "" {
		t.Fatalf("got %q", got)
	}
}
