// Package web renders the server-rendered admin UI.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bothought/binnacle/internal/actions"
	"github.com/bothought/binnacle/internal/alerts"
	"github.com/bothought/binnacle/internal/auth"
	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/hostruntime"
	"github.com/bothought/binnacle/internal/integrations"
	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/system"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Deps struct {
	Config       *config.Config
	ConfigPath   string
	Store        *store.Store
	Auth         *auth.Manager
	System       *system.Collector
	Integrations *integrations.Manager
	Actions      *actions.Manager
	Notifier     *alerts.Notifier
	Runtime      *hostruntime.Runtime
	Version      string
	Demo         bool
}

type Server struct {
	deps        Deps
	mux         *http.ServeMux
	pages       map[string]*template.Template
	login       *template.Template
	errorPage   *template.Template
	static      http.Handler
	demoSession store.Session
	logger      *log.Logger
}

type ctxKey int

const sessionKey ctxKey = 1

func New(d Deps) (*Server, error) {
	s := &Server{
		deps:   d,
		mux:    http.NewServeMux(),
		pages:  map[string]*template.Template{},
		logger: log.New(os.Stderr, "binnacle: ", log.LstdFlags),
	}
	funcs := template.FuncMap{
		"bytes":     humanBytes,
		"rate":      humanRate,
		"pct":       func(f float64) string { return fmt.Sprintf("%.0f%%", f) },
		"uptime":    uptimeText,
		"ago":       agoText,
		"datetime":  datetimeText,
		"ports":     portText,
		"exposure":  exposureText,
		"vis":       visibilityText,
		"severity":  severityText,
		"status":    statusText,
		"statuscls": statusClass,
		"add":       func(a, b int) int { return a + b },
		"spark":     sparkline,
		"short":     shortText,
		"hasPrefix": strings.HasPrefix,
		"lower":     strings.ToLower,
		"timeout":   func(d config.Duration) string { return d.String() },
		"unix":      func(t time.Time) int64 { return t.Unix() },
		"command":   func(c []string) string { return strings.Join(c, " ") },
		"notempty":  func(s string) bool { return strings.TrimSpace(s) != "" },
		"rule":      func(m map[string][]string, key string) []string { return m[key] },
	}
	pages := map[string]string{
		"dashboard":      "dashboard.html",
		"services":       "services.html",
		"updates":        "updates.html",
		"actions":        "actions.html",
		"action_confirm": "action_confirm.html",
		"run":            "run.html",
		"settings":       "settings.html",
	}
	for name, file := range pages {
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, "templates/base.html", "templates/partials.html", "templates/"+file)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		s.pages[name] = t
	}
	t, err := template.New("login").Funcs(funcs).ParseFS(assets, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse login: %w", err)
	}
	s.login = t
	t, err = template.New("error").Funcs(funcs).ParseFS(assets, "templates/error.html")
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}
	s.errorPage = t
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.FileServer(http.FS(staticFS))

	csrf, _ := randomToken(32)
	host := d.Config.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	s.demoSession = store.Session{User: "demo", Role: "admin", CSRF: csrf, Email: "demo@localhost"}

	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.dashboard)
	s.mux.HandleFunc("GET /partials/dashboard", s.dashboardPartial)
	s.mux.HandleFunc("GET /services", s.servicesPage)
	s.mux.HandleFunc("POST /services/update", s.servicesUpdate)
	s.mux.HandleFunc("POST /services/ack", s.servicesAck)
	s.mux.HandleFunc("POST /services/ack-all", s.servicesAckAll)
	s.mux.HandleFunc("GET /updates", s.updatesPage)
	s.mux.HandleFunc("POST /updates/ack", s.updatesAck)
	s.mux.HandleFunc("GET /actions", s.actionsPage)
	s.mux.HandleFunc("GET /actions/{id}/run", s.actionConfirm)
	s.mux.HandleFunc("POST /actions/run", s.actionRun)
	s.mux.HandleFunc("GET /runs/{id}", s.runPage)
	s.mux.HandleFunc("GET /runs/{id}/events", s.runEvents)
	s.mux.HandleFunc("GET /settings", s.settingsPage)
	s.mux.HandleFunc("POST /settings/notify-test", s.notifyTest)
	s.mux.HandleFunc("GET /healthz", s.healthz)
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginPost)
	s.mux.HandleFunc("GET /logout", s.logout)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", s.static))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	p := r.URL.Path
	if p == "/healthz" || strings.HasPrefix(p, "/static/") || p == "/login" || p == "/logout" {
		s.mux.ServeHTTP(w, r)
		return
	}
	sess, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ctx := context.WithValue(r.Context(), sessionKey, sess)
	r = r.WithContext(ctx)
	if r.Method == http.MethodPost {
		if sess.Role != "admin" {
			s.renderError(w, r, http.StatusForbidden, "This account is read-only.")
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Invalid form submission.")
			return
		}
		if !s.deps.Auth.CSRFValid(sess, r.PostForm.Get("csrf")) {
			s.renderError(w, r, http.StatusForbidden, "The form expired or the CSRF token is invalid. Reload and try again.")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	if s.deps.Demo {
		return s.demoSession, true
	}
	if s.deps.Config.Auth.Mode == "forward" {
		u, err := s.deps.Auth.ForwardUser(r)
		if err != nil {
			msg := "Authentication is handled by the reverse proxy."
			if errors.Is(err, auth.ErrForbidden) {
				msg = "Your account is not allowed to access this panel."
			}
			s.renderErrorStatus(w, r, http.StatusUnauthorized, msg)
			return store.Session{}, false
		}
		if sess, ok := s.deps.Auth.CurrentSession(r); ok {
			if sess.User == u.Name && sess.Role == u.Role && sess.Email == u.Email {
				return sess, true
			}
			_ = s.deps.Store.DeleteSession(r.Context(), sess.ID)
		}
		sess, err := s.deps.Auth.NewSession(r.Context(), w, r, u)
		if err != nil {
			s.renderErrorStatus(w, r, http.StatusInternalServerError, "Could not create a session.")
			return store.Session{}, false
		}
		return sess, true
	}
	sess, ok := s.deps.Auth.CurrentSession(r)
	if !ok {
		next := r.URL.RequestURI()
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
		return store.Session{}, false
	}
	return sess, true
}

func sessionOf(r *http.Request) store.Session {
	if v, ok := r.Context().Value(sessionKey).(store.Session); ok {
		return v
	}
	return store.Session{}
}

type baseData struct {
	Title    string
	Nav      string
	Hostname string
	User     string
	Role     string
	CSRF     string
	IsAdmin  bool
	Version  string
	Demo     bool
	Now      time.Time
	Notice   string
	Error    string
}

func (s *Server) base(r *http.Request, title, nav string) baseData {
	sess := sessionOf(r)
	host := s.deps.Config.Hostname
	if host == "" {
		host = s.deps.System.Latest().Hostname
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	return baseData{
		Title: title, Nav: nav, Hostname: host, User: sess.User, Role: sess.Role,
		CSRF: sess.CSRF, IsAdmin: sess.Role == "admin", Version: s.deps.Version,
		Demo: s.deps.Demo, Now: time.Now(),
		Notice: r.URL.Query().Get("ok"), Error: r.URL.Query().Get("error"),
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, status int, data any) {
	t := s.pages[page]
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.logger.Printf("render %s: %v", page, err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) renderPartial(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	t := s.pages[page]
	if t == nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		s.logger.Printf("render partial %s: %v", name, err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderErrorStatus(w, r, status, msg)
}

func (s *Server) renderErrorStatus(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = s.errorPage.ExecuteTemplate(w, "layout", map[string]any{
		"Status": status, "Message": msg, "Hostname": s.deps.Config.Hostname, "Version": s.deps.Version,
	})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.deps.Version})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.deps.Demo {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.deps.Config.Auth.Mode != "local" {
		s.renderErrorStatus(w, r, http.StatusUnauthorized, "Authentication is handled by the reverse proxy.")
		return
	}
	if _, ok := s.deps.Auth.CurrentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	csrf := loginCSRF(w, r)
	data := map[string]any{
		"CSRF": csrf, "Error": "", "Username": "", "TOTP": s.deps.Config.Auth.Local.TOTPSecret != "",
		"Next": safeNext(r.URL.Query().Get("next")),
	}
	s.renderLogin(w, http.StatusOK, data)
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if s.deps.Demo {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if s.deps.Config.Auth.Mode != "local" {
		s.renderErrorStatus(w, r, http.StatusUnauthorized, "Authentication is handled by the reverse proxy.")
		return
	}
	_ = r.ParseForm()
	cookie, err := r.Cookie("binnacle_login_csrf")
	if err != nil || cookie.Value == "" || cookie.Value != r.PostForm.Get("csrf") {
		s.renderLogin(w, http.StatusForbidden, map[string]any{
			"CSRF": loginCSRF(w, r), "Error": "The form expired. Reload and try again.",
			"Username": r.PostForm.Get("username"), "TOTP": s.deps.Config.Auth.Local.TOTPSecret != "",
			"Next": safeNext(r.PostForm.Get("next")),
		})
		return
	}
	ip := auth.ClientIP(r)
	if !s.deps.Auth.AllowLogin(ip) {
		s.renderLogin(w, http.StatusTooManyRequests, map[string]any{
			"CSRF": loginCSRF(w, r), "Error": "Too many attempts. Try again in 15 minutes.",
			"Username": r.PostForm.Get("username"), "TOTP": s.deps.Config.Auth.Local.TOTPSecret != "",
			"Next": safeNext(r.PostForm.Get("next")),
		})
		return
	}
	if err := s.deps.Auth.Login(r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("totp")); err != nil {
		s.deps.Auth.RecordLoginFailure(ip)
		s.renderLogin(w, http.StatusUnauthorized, map[string]any{
			"CSRF": loginCSRF(w, r), "Error": "Invalid username, password or code.",
			"Username": r.PostForm.Get("username"), "TOTP": s.deps.Config.Auth.Local.TOTPSecret != "",
			"Next": safeNext(r.PostForm.Get("next")),
		})
		return
	}
	s.deps.Auth.ClearLoginFailures(ip)
	u := auth.User{Name: s.deps.Config.Auth.Local.Username, Role: "admin"}
	if _, err := s.deps.Auth.NewSession(r.Context(), w, r, u); err != nil {
		s.renderErrorStatus(w, r, http.StatusInternalServerError, "Could not create a session.")
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.login.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Printf("render login: %v", err)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.deps.Auth.Logout(r.Context(), w, r)
	if s.deps.Config.Auth.Mode == "forward" && s.deps.Config.Auth.Forward.LogoutURL != "" {
		http.Redirect(w, r, s.deps.Config.Auth.Forward.LogoutURL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("binnacle_login_csrf"); err == nil && c.Value != "" {
		return c.Value
	}
	tok, _ := randomToken(32)
	http.SetCookie(w, &http.Cookie{
		Name: "binnacle_login_csrf", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: auth.IsSecure(r), MaxAge: 900,
	})
	return tok
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func safeNext(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/\\") {
		return ""
	}
	return v
}
