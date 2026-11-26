// Package alerts routes state-change events to configured notification channels.
package alerts

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/store"
)

type Event struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	URL         string `json:"url,omitempty"`
	Urgent      bool   `json:"urgent,omitempty"`
	Fingerprint string `json:"-"`
}

type payload struct {
	Event
	Host string `json:"host"`
}

type Notifier struct {
	cfg     config.AlertsConfig
	store   *store.Store
	client  *http.Client
	host    string
	baseURL string
}

func New(cfg config.AlertsConfig, st *store.Store, host, baseURL string) *Notifier {
	return &Notifier{
		cfg: cfg, store: st, host: host, baseURL: baseURL,
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (n *Notifier) Enabled() bool {
	return n.cfg.Enabled && len(n.Configured()) > 0
}

func (n *Notifier) Configured() []string {
	var out []string
	if n.cfg.Email != nil {
		out = append(out, "email")
	}
	if n.cfg.Ntfy != nil {
		out = append(out, "ntfy")
	}
	if n.cfg.Webhook != nil {
		out = append(out, "webhook")
	}
	return out
}

// Notify queues an event for every configured channel in its routing rule.
func (n *Notifier) Notify(ctx context.Context, ev Event) {
	if !n.Enabled() {
		return
	}
	if !ev.Urgent && n.inQuietHours(time.Now()) {
		return
	}
	channels := n.cfg.Rules[ev.Type]
	if len(channels) == 0 {
		channels = n.Configured()
	}
	if len(channels) == 0 {
		return
	}
	if ev.URL == "" {
		ev.URL = n.baseURL
	}
	p := payload{Event: ev, Host: n.host}
	body, _ := json.Marshal(p)
	for _, ch := range channels {
		if !n.hasChannel(ch) {
			continue
		}
		fp := ev.Type + ":" + ev.Fingerprint + ":" + ch
		if ev.Fingerprint != "" && n.recentlySent(ctx, fp, time.Duration(n.cfg.Cooldown)) {
			continue
		}
		if err := n.store.EnqueueNotification(ctx, ch, ev.Type, string(body)); err != nil {
			continue
		}
		if ev.Fingerprint != "" {
			_ = n.store.SetSetting(ctx, "alert:"+fp, fmt.Sprint(time.Now().Unix()))
		}
	}
}

// NotifyChannels queues an event on explicit channels. Used for the daily
// digest, where routing is not a state-change rule.
func (n *Notifier) NotifyChannels(ctx context.Context, ev Event, channels []string) {
	if !n.Enabled() {
		return
	}
	if ev.URL == "" {
		ev.URL = n.baseURL
	}
	p := payload{Event: ev, Host: n.host}
	body, _ := json.Marshal(p)
	for _, ch := range channels {
		if !n.hasChannel(ch) {
			continue
		}
		_ = n.store.EnqueueNotification(ctx, ch, ev.Type, string(body))
	}
}

func (n *Notifier) Worker(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.flush(ctx)
		}
	}
}

func (n *Notifier) flush(ctx context.Context) {
	due, err := n.store.DueNotifications(ctx, 20)
	if err != nil {
		return
	}
	for _, item := range due {
		var p payload
		if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
			_ = n.store.MarkNotificationFailed(ctx, item.ID, "invalid payload")
			continue
		}
		c, cancel := context.WithTimeout(ctx, 25*time.Second)
		err := n.send(c, item.Channel, p)
		cancel()
		if err != nil {
			_ = n.store.MarkNotificationFailed(ctx, item.ID, err.Error())
			continue
		}
		_ = n.store.MarkNotificationSent(ctx, item.ID)
	}
}

// Test sends a test notification immediately, bypassing the queue.
func (n *Notifier) Test(ctx context.Context, channel string) error {
	p := payload{
		Event: Event{Type: "test", Title: "Test notification", Message: "Binnacle can reach this channel.", URL: n.baseURL},
		Host:  n.host,
	}
	var errs []string
	for _, ch := range n.Configured() {
		if channel != "" && channel != ch {
			continue
		}
		if err := n.send(ctx, ch, p); err != nil {
			errs = append(errs, ch+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if channel != "" && !n.hasChannel(channel) {
		return fmt.Errorf("channel %q is not configured", channel)
	}
	return nil
}

func (n *Notifier) send(ctx context.Context, channel string, p payload) error {
	switch channel {
	case "email":
		return n.sendEmail(p)
	case "ntfy":
		return n.sendNtfy(ctx, p)
	case "webhook":
		return n.sendWebhook(ctx, p)
	}
	return fmt.Errorf("unknown channel %q", channel)
}

func (n *Notifier) sendEmail(p payload) error {
	c := n.cfg.Email
	if c == nil {
		return fmt.Errorf("email not configured")
	}
	subject := fmt.Sprintf("[binnacle] %s", p.Title)
	body := fmt.Sprintf("%s\n\nHost: %s\nEvent: %s\n", p.Message, p.Host, p.Type)
	if p.URL != "" {
		body += "Open: " + p.URL + "\n"
	}
	msg := buildEmail(c.From, c.To, subject, body)
	addr := net.JoinHostPort(c.Host, fmt.Sprint(c.Port))
	if c.TLS == "tls" {
		return sendSMTPTLS(addr, c, msg)
	}
	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()
	if c.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("server does not advertise STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
				return err
			}
		}
	}
	if err := client.Mail(c.From); err != nil {
		return err
	}
	for _, to := range c.To {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func sendSMTPTLS(addr string, c *config.EmailConfig, msg []byte) error {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	if c.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(c.From); err != nil {
		return err
	}
	for _, to := range c.To {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildEmail(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return b.Bytes()
}

func (n *Notifier) sendNtfy(ctx context.Context, p payload) error {
	c := n.cfg.Ntfy
	if c == nil {
		return fmt.Errorf("ntfy not configured")
	}
	u := strings.TrimRight(c.URL, "/") + "/" + c.Topic
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(p.Message+"\n\n"+p.URL))
	if err != nil {
		return err
	}
	title := p.Title
	if p.Host != "" {
		title = "[" + p.Host + "] " + title
	}
	req.Header.Set("Title", title)
	req.Header.Set("Tags", "computer")
	if p.Urgent {
		req.Header.Set("Priority", "high")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy HTTP %d", resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, p payload) error {
	c := n.cfg.Webhook
	if c == nil {
		return fmt.Errorf("webhook not configured")
	}
	text := p.Title + "\n" + p.Message
	if p.URL != "" {
		text += "\n" + p.URL
	}
	var body any
	switch c.Format {
	case "discord":
		body = map[string]any{"content": text}
	case "slack":
		body = map[string]any{"text": text}
	default:
		body = map[string]any{
			"title": p.Title, "message": p.Message, "url": p.URL,
			"event": p.Type, "host": p.Host, "urgent": p.Urgent,
		}
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

// Handles reports whether an event type can produce at least one notification.
func (n *Notifier) Handles(event string) bool {
	if !n.Enabled() {
		return false
	}
	channels := n.cfg.Rules[event]
	if len(channels) == 0 {
		return len(n.Configured()) > 0
	}
	for _, ch := range channels {
		if n.hasChannel(ch) {
			return true
		}
	}
	return false
}

func (n *Notifier) hasChannel(ch string) bool {
	switch ch {
	case "email":
		return n.cfg.Email != nil
	case "ntfy":
		return n.cfg.Ntfy != nil
	case "webhook":
		return n.cfg.Webhook != nil
	}
	return false
}

func (n *Notifier) recentlySent(ctx context.Context, key string, cooldown time.Duration) bool {
	if cooldown <= 0 {
		return false
	}
	v, ok, err := n.store.GetSetting(ctx, "alert:"+key)
	if err != nil || !ok {
		return false
	}
	var unix int64
	if _, err := fmt.Sscan(v, &unix); err != nil {
		return false
	}
	return time.Since(time.Unix(unix, 0)) < cooldown
}

func (n *Notifier) inQuietHours(now time.Time) bool {
	if n.cfg.QuietHours == "" {
		return false
	}
	start, end, err := config.ParseQuietHours(n.cfg.QuietHours)
	if err != nil {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if start == end {
		return false
	}
	if start < end {
		return cur >= start && cur < end
	}
	return cur >= start || cur < end
}
