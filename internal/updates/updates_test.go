package updates

import (
	"testing"

	"github.com/bothought/binnacle/internal/config"
)

func TestCatalogMatching(t *testing.T) {
	m := New(config.UpdatesConfig{}, nil, nil)
	cases := map[string]string{
		"docker.io/library/caddy:2.11.9":            "Caddy",
		"ghcr.io/authelia/authelia:4.39.28":         "Authelia",
		"docker.io/cloudflare/cloudflared:latest":   "Cloudflared",
		"ghcr.io/immich-app/immich-server:v1.100.0": "Immich",
		"registry.example.com/team/unknown:1.0":     "",
	}
	for image, want := range cases {
		got := ""
		if e := m.matchCatalog(image); e != nil {
			got = e.Name
		}
		if got != want {
			t.Errorf("matchCatalog(%q)=%q want %q", image, got, want)
		}
	}
}

func TestVersionFromTag(t *testing.T) {
	cases := map[string]string{
		"2.11.9":          "2.11.9",
		"v4.39.28":        "4.39.28",
		"2.11.9-alpine":   "2.11.9",
		"latest":          "",
		"stable":          "",
		"2026.914.233613": "2026.914.233613",
		"sha-abcdef":      "",
	}
	for tag, want := range cases {
		if got := versionFromTag(tag); got != want {
			t.Errorf("versionFromTag(%q)=%q want %q", tag, got, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	if got := parseVersion("Beszel v0.21.2 (abcdef)", ""); got != "0.21.2" {
		t.Fatalf("got %q", got)
	}
	if got := parseVersion("version=3.4.5", `version=([0-9.]+)`); got != "3.4.5" {
		t.Fatalf("regex got %q", got)
	}
}

func TestDigestAndImageHelpers(t *testing.T) {
	if !containsDigest([]string{"repo@sha256:abc"}, "sha256:abc") {
		t.Error("digest should match")
	}
	if containsDigest([]string{"repo@sha256:abc"}, "sha256:def") {
		t.Error("digest should not match")
	}
	if got := tagOf("docker.io/library/caddy:2.11.9"); got != "2.11.9" {
		t.Errorf("tagOf = %q", got)
	}
	if got := tagOf("docker.io:5000/caddy"); got != "" {
		t.Errorf("tagOf registry = %q", got)
	}
	if got := normalizeImage("docker.io/library/caddy:2.11.9"); got != "caddy" {
		t.Errorf("normalizeImage = %q", got)
	}
}
