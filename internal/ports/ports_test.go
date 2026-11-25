package ports

import (
	"testing"

	"github.com/bothought/binnacle/internal/hostruntime"
)

func TestParseSS(t *testing.T) {
	out := `tcp   LISTEN 0      4096    127.0.0.1:9091      0.0.0.0:*    users:(("authelia",pid=123,fd=8))
tcp   LISTEN 0      128          [::]:80           [::]:*    users:(("caddy",pid=42,fd=3))
udp   UNCONN 0      0            0.0.0.0:5353        0.0.0.0:*
tcp   ESTAB  0      0        192.168.1.2:54321    1.1.1.1:443
`
	socks := ParseSS(out)
	if len(socks) != 3 {
		t.Fatalf("got %d sockets: %+v", len(socks), socks)
	}
	if socks[0].Proto != "tcp" || socks[0].Port != 9091 || socks[0].PID != 123 || socks[0].Process != "authelia" {
		t.Errorf("first socket = %+v", socks[0])
	}
	if socks[1].Bind != "::" || socks[1].Port != 80 {
		t.Errorf("ipv6 socket = %+v", socks[1])
	}
	if socks[2].Proto != "udp" || socks[2].Port != 5353 {
		t.Errorf("udp socket = %+v", socks[2])
	}
}

func TestSplitAddr(t *testing.T) {
	cases := []struct{ in, host, port string }{
		{"127.0.0.1:8091", "127.0.0.1", "8091"},
		{"[::]:443", "::", "443"},
		{"[fe80::1%wlan0]:5353", "fe80::1", "5353"},
		{"*:8080", "0.0.0.0", "8080"},
	}
	for _, c := range cases {
		h, p, ok := splitAddr(c.in)
		if !ok || h != c.host || p != c.port {
			t.Errorf("splitAddr(%q)=%q,%q,%v", c.in, h, p, ok)
		}
	}
}

func TestBuildServicesGroupsContainerAndIgnoresEphemeral(t *testing.T) {
	socks := []Socket{
		{Proto: "tcp", Port: 8091, Bind: "127.0.0.1"},
		{Proto: "tcp", Port: 40000, Bind: "0.0.0.0"},
	}
	containers := []hostruntime.Container{{
		Name: "systemd-beszel", Image: "ghcr.io/henrygd/beszel:latest", Unit: "systemd-beszel.service",
		Ports: []hostruntime.PortMapping{{HostPort: 8091, Proto: "tcp"}},
	}}
	got := buildServices(socks, containers, []string{"steam*"})
	var beszel, ephemeral bool
	for _, sv := range got {
		switch sv.Key {
		case "container:systemd-beszel":
			beszel = true
			if sv.Name != "beszel" || sv.Exposure != "loopback" || sv.Ignored {
				t.Errorf("unexpected beszel service: %+v", sv)
			}
		case "port:tcp:40000":
			ephemeral = true
			if !sv.Ignored {
				t.Errorf("ephemeral socket should be ignored: %+v", sv)
			}
		}
	}
	if !beszel || !ephemeral {
		t.Fatalf("missing services: %+v", got)
	}
}

func TestExposure(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":   "loopback",
		"::1":         "loopback",
		"0.0.0.0":     "lan",
		"192.168.1.2": "lan",
		"100.64.1.2":  "tailnet",
		"8.8.8.8":     "public",
	}
	for bind, want := range cases {
		if got := exposureOf(bind); got != want {
			t.Errorf("exposureOf(%q)=%q want %q", bind, got, want)
		}
	}
}

func TestMatchesAny(t *testing.T) {
	if !matchesAny([]string{"*steam*"}, "app-steam@autostart.service") {
		t.Error("expected steam match")
	}
	if matchesAny([]string{"steam*"}, "app-steam@autostart.service") {
		t.Error("prefix pattern should not match")
	}
	if !matchesAny([]string{"caddy"}, "custom-caddy") {
		t.Error("plain substring should match")
	}
}
