package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/bothought/binnacle/internal/config"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("valid password rejected")
	}
	if VerifyPassword(hash, "wrong") {
		t.Fatal("invalid password accepted")
	}
	if VerifyPassword("garbage", "wrong") {
		t.Fatal("garbage hash accepted")
	}
}

func TestForwardUser(t *testing.T) {
	cfg := config.AuthConfig{
		Mode: "forward",
		Forward: config.ForwardConfig{
			TrustedProxies: []string{"127.0.0.1"},
			UserHeader:     "Remote-User",
			EmailHeader:    "Remote-Email",
			GroupsHeader:   "Remote-Groups",
			AdminGroups:    []string{"admins"},
			ViewerGroups:   []string{"viewers"},
		},
	}
	m := New(cfg, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Remote-User", "alice")
	req.Header.Set("Remote-Email", "alice@example.com")
	req.Header.Set("Remote-Groups", "users, admins")
	u, err := m.ForwardUser(req)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "alice" || u.Role != "admin" || u.Email != "alice@example.com" {
		t.Fatalf("unexpected user: %+v", u)
	}

	req.Header.Set("Remote-Groups", "viewers")
	u, err = m.ForwardUser(req)
	if err != nil || u.Role != "viewer" {
		t.Fatalf("viewer: %+v %v", u, err)
	}

	req.Header.Set("Remote-Groups", "other")
	if _, err := m.ForwardUser(req); err != ErrForbidden {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestForwardUserRejectsUntrustedProxy(t *testing.T) {
	m := New(config.AuthConfig{
		Mode:    "forward",
		Forward: config.ForwardConfig{TrustedProxies: []string{"127.0.0.1"}},
	}, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("Remote-User", "alice")
	if _, err := m.ForwardUser(req); err != ErrUnauthorized {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}

func TestForwardProxySecret(t *testing.T) {
	m := New(config.AuthConfig{
		Mode: "forward",
		Forward: config.ForwardConfig{
			TrustedProxies:    []string{"127.0.0.1"},
			ProxySecret:       "s3cret",
			ProxySecretHeader: "X-Binnacle-Proxy-Secret",
			UserHeader:        "Remote-User",
		},
	}, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Remote-User", "alice")
	if _, err := m.ForwardUser(req); err != ErrUnauthorized {
		t.Fatalf("missing secret: %v", err)
	}
	req.Header.Set("X-Binnacle-Proxy-Secret", "s3cret")
	if _, err := m.ForwardUser(req); err != nil {
		t.Fatalf("valid secret: %v", err)
	}
}

func TestTrustedProxyCIDR(t *testing.T) {
	if !trustedProxy("10.1.2.3:99", []string{"10.0.0.0/8"}) {
		t.Fatal("CIDR should match")
	}
	if trustedProxy("192.168.1.1:99", []string{"10.0.0.0/8"}) {
		t.Fatal("CIDR should not match")
	}
}

func TestGenerateTOTP(t *testing.T) {
	secret, uri, err := GenerateTOTP("admin")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || uri == "" {
		t.Fatal("empty totp values")
	}
}
