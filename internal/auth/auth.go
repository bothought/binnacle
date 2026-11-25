// Package auth handles forward-auth identities, local login, sessions and CSRF.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/store"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

const CookieName = "binnacle_session"

var ErrUnauthorized = errors.New("unauthorized")
var ErrForbidden = errors.New("forbidden")

type User struct {
	Name  string
	Email string
	Role  string // admin or viewer
}

func (u User) IsAdmin() bool { return u.Role == "admin" }

type Manager struct {
	cfg   config.AuthConfig
	store *store.Store
	mu    sync.Mutex
	login map[string]*attempts
}

type attempts struct {
	count   int
	until   time.Time
	updated time.Time
}

func New(cfg config.AuthConfig, st *store.Store) *Manager {
	return &Manager{cfg: cfg, store: st, login: map[string]*attempts{}}
}

func (m *Manager) Mode() string { return m.cfg.Mode }

// ForwardUser validates a request from a trusted reverse proxy.
func (m *Manager) ForwardUser(r *http.Request) (User, error) {
	if !trustedProxy(r.RemoteAddr, m.cfg.Forward.TrustedProxies) {
		return User{}, ErrUnauthorized
	}
	if m.cfg.Forward.ProxySecret != "" {
		got := r.Header.Get(m.cfg.Forward.ProxySecretHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(m.cfg.Forward.ProxySecret)) != 1 {
			return User{}, ErrUnauthorized
		}
	}
	name := strings.TrimSpace(r.Header.Get(m.cfg.Forward.UserHeader))
	if name == "" {
		return User{}, ErrUnauthorized
	}
	email := strings.TrimSpace(r.Header.Get(m.cfg.Forward.EmailHeader))
	groups := splitGroups(r.Header.Get(m.cfg.Forward.GroupsHeader))
	role, err := m.roleForGroups(groups)
	if err != nil {
		return User{}, err
	}
	return User{Name: name, Email: email, Role: role}, nil
}

func (m *Manager) roleForGroups(groups []string) (string, error) {
	if len(m.cfg.Forward.AdminGroups) == 0 && len(m.cfg.Forward.ViewerGroups) == 0 {
		return "admin", nil
	}
	for _, g := range groups {
		for _, a := range m.cfg.Forward.AdminGroups {
			if strings.EqualFold(g, a) {
				return "admin", nil
			}
		}
	}
	for _, g := range groups {
		for _, v := range m.cfg.Forward.ViewerGroups {
			if strings.EqualFold(g, v) {
				return "viewer", nil
			}
		}
	}
	return "", ErrForbidden
}

// Login verifies a local username, password and optional TOTP code.
func (m *Manager) Login(username, password, code string) error {
	if username != m.cfg.Local.Username {
		return ErrUnauthorized
	}
	if !VerifyPassword(m.cfg.Local.PasswordHash, password) {
		return ErrUnauthorized
	}
	if m.cfg.Local.TOTPSecret != "" {
		ok, err := totp.ValidateCustom(code, m.cfg.Local.TOTPSecret, time.Now().UTC(), totp.ValidateOpts{
			Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil || !ok {
			return ErrUnauthorized
		}
	}
	return nil
}

func (m *Manager) AllowLogin(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	a := m.login[ip]
	if a == nil {
		return true
	}
	return time.Now().After(a.until)
}

func (m *Manager) RecordLoginFailure(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	a := m.login[ip]
	if a == nil {
		a = &attempts{}
		m.login[ip] = a
	}
	a.count++
	a.updated = now
	if a.count >= 5 {
		a.until = now.Add(15 * time.Minute)
		a.count = 0
	}
}

func (m *Manager) ClearLoginFailures(ip string) {
	m.mu.Lock()
	delete(m.login, ip)
	m.mu.Unlock()
}

func (m *Manager) cleanupLocked() {
	if len(m.login) < 256 {
		return
	}
	cutoff := time.Now().Add(-time.Hour)
	for k, v := range m.login {
		if v.updated.Before(cutoff) {
			delete(m.login, k)
		}
	}
}

// NewSession creates a session and sets the session cookie.
func (m *Manager) NewSession(ctx context.Context, w http.ResponseWriter, r *http.Request, u User) (store.Session, error) {
	id, err := randomToken(32)
	if err != nil {
		return store.Session{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return store.Session{}, err
	}
	now := time.Now()
	s := store.Session{
		ID:        id,
		User:      u.Name,
		Email:     u.Email,
		Role:      u.Role,
		CSRF:      csrf,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(m.cfg.SessionTTL.Value()).Unix(),
		IP:        clientIP(r),
	}
	if err := m.store.CreateSession(ctx, s); err != nil {
		return store.Session{}, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   IsSecure(r),
		Expires:  time.Unix(s.ExpiresAt, 0),
	})
	return s, nil
}

func (m *Manager) CurrentSession(r *http.Request) (store.Session, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return store.Session{}, false
	}
	s, err := m.store.GetSession(r.Context(), c.Value)
	if err != nil {
		return store.Session{}, false
	}
	return s, true
}

func (m *Manager) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		_ = m.store.DeleteSession(ctx, c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: IsSecure(r),
	})
}

func (m *Manager) CSRFValid(s store.Session, token string) bool {
	if token == "" || s.CSRF == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.CSRF), []byte(token)) == 1
}

func (m *Manager) LogoutURL() string {
	if m.cfg.Mode == "forward" {
		return m.cfg.Forward.LogoutURL
	}
	return "/logout"
}

func (m *Manager) SessionTTL() time.Duration { return m.cfg.SessionTTL.Value() }

// IsSecure reports whether cookies should carry the Secure flag.
func IsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func ClientIP(r *http.Request) string { return clientIP(r) }

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(first) != nil {
				return first
			}
		}
	}
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func trustedProxy(remoteAddr string, allowed []string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, a := range allowed {
		if strings.Contains(a, "/") {
			_, cidr, err := net.ParseCIDR(a)
			if err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if x := net.ParseIP(a); x != nil && x.Equal(ip) {
			return true
		}
	}
	return false
}

func splitGroups(s string) []string {
	if s == "" {
		return nil
	}
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
	out := make([]string, 0, len(f))
	for _, g := range f {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const argonTime = 3
const argonMemory = 64 * 1024
const argonThreads = 2
const argonKeyLen = 32

// HashPassword returns an argon2id PHC string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an argon2id PHC string.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory uint32
	var iter uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iter, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iter, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// GenerateTOTP creates a new TOTP secret for the given account.
func GenerateTOTP(account string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Binnacle", AccountName: account})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}
