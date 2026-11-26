// Package store persists mutable state in a single SQLite database.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	// The database contains session IDs and action output.
	_ = os.Chmod(path, 0o600)
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
	key TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	unit TEXT NOT NULL DEFAULT '',
	container TEXT NOT NULL DEFAULT '',
	image TEXT NOT NULL DEFAULT '',
	ports TEXT NOT NULL DEFAULT '[]',
	exposure TEXT NOT NULL DEFAULT 'loopback',
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	active INTEGER NOT NULL DEFAULT 1,
	ignored INTEGER NOT NULL DEFAULT 0,
	label TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	url TEXT NOT NULL DEFAULT '',
	grp TEXT NOT NULL DEFAULT '',
	favorite INTEGER NOT NULL DEFAULT 0,
	visibility TEXT NOT NULL DEFAULT 'auto',
	muted INTEGER NOT NULL DEFAULT 0,
	acked INTEGER NOT NULL DEFAULT 0,
	updated_by TEXT NOT NULL DEFAULT '',
	updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_services_last_seen ON services(last_seen);
CREATE TABLE IF NOT EXISTS service_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_key TEXT NOT NULL,
	type TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	actor TEXT NOT NULL DEFAULT '',
	at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_service_events_at ON service_events(at);
CREATE TABLE IF NOT EXISTS updates (
	key TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	current TEXT NOT NULL DEFAULT '',
	latest TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT 'unknown',
	source TEXT NOT NULL,
	url TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '',
	checked_at INTEGER NOT NULL,
	acknowledged INTEGER NOT NULL DEFAULT 0,
	notified_version TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_updates_checked ON updates(checked_at);
CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY,
	action_id TEXT NOT NULL,
	action_label TEXT NOT NULL,
	command TEXT NOT NULL,
	user TEXT NOT NULL,
	ip TEXT NOT NULL,
	started_at INTEGER NOT NULL,
	ended_at INTEGER NOT NULL DEFAULT 0,
	exit_code INTEGER NOT NULL DEFAULT -1,
	output TEXT NOT NULL DEFAULT '',
	error TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at DESC);
CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	role TEXT NOT NULL,
	csrf TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS notifications (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	channel TEXT NOT NULL,
	event TEXT NOT NULL,
	payload TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	attempts INTEGER NOT NULL DEFAULT 0,
	next_try INTEGER NOT NULL,
	sent_at INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_notifications_due ON notifications(sent_at, next_try);
CREATE TABLE IF NOT EXISTS metric_samples (
	ts INTEGER PRIMARY KEY,
	cpu REAL NOT NULL,
	mem REAL NOT NULL,
	disk REAL NOT NULL,
	load1 REAL NOT NULL,
	net_rx REAL NOT NULL,
	net_tx REAL NOT NULL
);
`)
	return err
}

func (s *Store) GetSetting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Port is a listening socket belonging to a service.
type Port struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Bind  string `json:"bind"`
}

// Service is a logical owner of one or more listening sockets.
type Service struct {
	Key         string
	Name        string
	Kind        string
	Unit        string
	Container   string
	Image       string
	Ports       []Port
	Exposure    string
	FirstSeen   int64
	LastSeen    int64
	Active      bool
	Ignored     bool
	Label       string
	Description string
	URL         string
	Group       string
	Favorite    bool
	Visibility  string
	Muted       bool
	Acked       bool
	UpdatedBy   string
	UpdatedAt   int64
}

func (s Service) DisplayName() string {
	if s.Label != "" {
		return s.Label
	}
	return s.Name
}

// EffectiveVisibility resolves "auto" using exposure.
func (s Service) EffectiveVisibility() string {
	if s.Visibility == "" || s.Visibility == "auto" {
		if s.Exposure == "public" {
			return "public"
		}
		return "internal"
	}
	return s.Visibility
}

func (s Service) IsNew(baselineAt int64) bool {
	return !s.Acked && baselineAt > 0 && s.FirstSeen > baselineAt
}

func (s Service) ExposureRank() int {
	switch s.Exposure {
	case "public":
		return 4
	case "tailnet":
		return 3
	case "lan":
		return 2
	case "loopback":
		return 1
	}
	return 0
}

func (s *Store) BaselineAt(ctx context.Context) (int64, error) {
	v, ok, err := s.GetSetting(ctx, "baseline_at")
	if err != nil || !ok {
		return 0, err
	}
	var n int64
	_, err = fmt.Sscan(v, &n)
	return n, err
}

func (s *Store) SetBaseline(ctx context.Context, at int64) error {
	return s.SetSetting(ctx, "baseline_at", fmt.Sprint(at))
}

type SyncResult struct {
	Created         []Service
	Lost            []Service
	Returned        []Service
	ExposureChanged []Service
}

// SyncServices marks the full scan as the current state and returns changes.
func (s *Store) SyncServices(ctx context.Context, services []Service) (SyncResult, error) {
	var res SyncResult
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `SELECT key,name,kind,unit,container,image,ports,exposure,first_seen,last_seen,active,ignored,label,description,url,grp,favorite,visibility,muted,acked,updated_by,updated_at FROM services`)
	if err != nil {
		return res, err
	}
	prev := map[string]Service{}
	for rows.Next() {
		sv, err := scanService(rows)
		if err != nil {
			rows.Close()
			return res, err
		}
		prev[sv.Key] = sv
	}
	if err := rows.Close(); err != nil {
		return res, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE services SET active = 0`); err != nil {
		return res, err
	}
	now := time.Now().Unix()
	seen := map[string]bool{}
	for i := range services {
		sv := &services[i]
		seen[sv.Key] = true
		if sv.FirstSeen == 0 {
			sv.FirstSeen = now
		}
		if sv.LastSeen == 0 {
			sv.LastSeen = now
		}
		if sv.Visibility == "" {
			sv.Visibility = "auto"
		}
		if sv.Exposure == "" {
			sv.Exposure = "loopback"
		}
		ports, _ := json.Marshal(sv.Ports)
		_, err := tx.ExecContext(ctx, `INSERT INTO services(key,name,kind,unit,container,image,ports,exposure,first_seen,last_seen,active,ignored)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(key) DO UPDATE SET
				name=excluded.name, kind=excluded.kind, unit=excluded.unit,
				container=excluded.container, image=excluded.image, ports=excluded.ports,
				exposure=excluded.exposure, last_seen=excluded.last_seen,
				active=excluded.active, ignored=excluded.ignored`,
			sv.Key, sv.Name, sv.Kind, sv.Unit, sv.Container, sv.Image, string(ports), sv.Exposure, sv.FirstSeen, sv.LastSeen, 1, boolInt(sv.Ignored))
		if err != nil {
			return res, err
		}
		if old, ok := prev[sv.Key]; !ok {
			res.Created = append(res.Created, *sv)
		} else {
			if !old.Active {
				res.Returned = append(res.Returned, *sv)
			}
			if sv.ExposureRank() > old.ExposureRank() && old.ExposureRank() > 0 {
				res.ExposureChanged = append(res.ExposureChanged, *sv)
			}
		}
	}
	for key, old := range prev {
		if old.Active && !seen[key] {
			res.Lost = append(res.Lost, old)
		}
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	return res, nil
}

func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,name,kind,unit,container,image,ports,exposure,first_seen,last_seen,active,ignored,label,description,url,grp,favorite,visibility,muted,acked,updated_by,updated_at FROM services`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		sv, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

func (s *Store) UpdateServiceMeta(ctx context.Context, key, label, description, link, group, visibility string, favorite, muted bool, actor string) error {
	switch visibility {
	case "auto", "public", "internal", "hidden":
	default:
		return fmt.Errorf("invalid visibility %q", visibility)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE services SET label=?, description=?, url=?, grp=?, visibility=?, favorite=?, muted=?, updated_by=?, updated_at=? WHERE key=?`,
		label, description, link, group, visibility, boolInt(favorite), boolInt(muted), actor, time.Now().Unix(), key)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return s.AddServiceEvent(ctx, key, "labeled", label, actor)
}

func (s *Store) AckService(ctx context.Context, key, actor string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE services SET acked=1, updated_by=?, updated_at=? WHERE key=?`, actor, time.Now().Unix(), key)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return s.AddServiceEvent(ctx, key, "acknowledged", "", actor)
}

func (s *Store) AckAllNew(ctx context.Context, baselineAt int64, actor string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE services SET acked=1, updated_by=?, updated_at=? WHERE acked=0 AND first_seen > ?`, actor, time.Now().Unix(), baselineAt)
	return err
}

func (s *Store) AddServiceEvent(ctx context.Context, key, typ, detail, actor string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO service_events(service_key,type,detail,actor,at) VALUES(?,?,?,?,?)`, key, typ, detail, actor, time.Now().Unix())
	return err
}

type Update struct {
	Key             string
	Name            string
	Current         string
	Latest          string
	Severity        string
	Source          string
	URL             string
	Notes           string
	CheckedAt       int64
	Acknowledged    bool
	NotifiedVersion string
}

func (u Update) IsUrgent() bool { return u.Severity == "security" }

func (s *Store) UpsertUpdate(ctx context.Context, u Update) error {
	var oldLatest, oldNotified string
	_ = s.db.QueryRowContext(ctx, `SELECT latest, notified_version FROM updates WHERE key=?`, u.Key).Scan(&oldLatest, &oldNotified)
	ack := 0
	if oldLatest == u.Latest {
		_ = s.db.QueryRowContext(ctx, `SELECT acknowledged FROM updates WHERE key=?`, u.Key).Scan(&ack)
	}
	if u.CheckedAt == 0 {
		u.CheckedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO updates(key,name,current,latest,severity,source,url,notes,checked_at,acknowledged,notified_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET name=excluded.name, current=excluded.current, latest=excluded.latest,
			severity=excluded.severity, source=excluded.source, url=excluded.url, notes=excluded.notes,
			checked_at=excluded.checked_at, acknowledged=excluded.acknowledged`,
		u.Key, u.Name, u.Current, u.Latest, u.Severity, u.Source, u.URL, u.Notes, u.CheckedAt, ack, oldNotified)
	return err
}

func (s *Store) ListUpdates(ctx context.Context) ([]Update, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,name,current,latest,severity,source,url,notes,checked_at,acknowledged,notified_version FROM updates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Update
	for rows.Next() {
		var u Update
		var ack int
		if err := rows.Scan(&u.Key, &u.Name, &u.Current, &u.Latest, &u.Severity, &u.Source, &u.URL, &u.Notes, &u.CheckedAt, &ack, &u.NotifiedVersion); err != nil {
			return nil, err
		}
		u.Acknowledged = ack == 1
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank(out[i].Severity) < severityRank(out[j].Severity)
	})
	return out, rows.Err()
}

func severityRank(s string) int {
	switch s {
	case "security":
		return 0
	case "major":
		return 1
	case "minor":
		return 2
	case "patch":
		return 3
	case "image":
		return 4
	case "update":
		return 5
	}
	return 6
}

func (s *Store) AckUpdate(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE updates SET acknowledged=1 WHERE key=?`, key)
	return err
}

func (s *Store) MarkUpdateNotified(ctx context.Context, key, latest string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE updates SET notified_version=? WHERE key=?`, latest, key)
	return err
}

func (s *Store) DeleteStaleUpdates(ctx context.Context, source string, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM updates WHERE source=? AND checked_at < ?`, source, before)
	return err
}

// PruneUpdates removes rows for a source that were not seen during a complete
// check. It is only called after a source finishes without errors.
func (s *Store) PruneUpdates(ctx context.Context, source string, keep map[string]bool, before int64) error {
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM updates WHERE source=? AND checked_at <= ?`, source, before)
	if err != nil {
		return err
	}
	var stale []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		if !keep[k] {
			stale = append(stale, k)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range stale {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM updates WHERE key=? AND source=?`, k, source); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UnnotifiedUrgent(ctx context.Context) ([]Update, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,name,current,latest,severity,source,url,notes,checked_at,acknowledged,notified_version FROM updates WHERE severity='security' AND notified_version <> latest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Update
	for rows.Next() {
		var u Update
		var ack int
		if err := rows.Scan(&u.Key, &u.Name, &u.Current, &u.Latest, &u.Severity, &u.Source, &u.URL, &u.Notes, &u.CheckedAt, &ack, &u.NotifiedVersion); err != nil {
			return nil, err
		}
		u.Acknowledged = ack == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

type Run struct {
	ID        string
	ActionID  string
	Label     string
	Command   string
	User      string
	IP        string
	StartedAt int64
	EndedAt   int64
	ExitCode  int
	Output    string
	Error     string
	Status    string
}

func (s *Store) CreateRun(ctx context.Context, r Run) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs(id,action_id,action_label,command,user,ip,started_at,status) VALUES(?,?,?,?,?,?,?,?)`,
		r.ID, r.ActionID, r.Label, r.Command, r.User, r.IP, r.StartedAt, "running")
	return err
}

func (s *Store) FinishRun(ctx context.Context, id string, exitCode int, output, errMsg string) error {
	status := "success"
	if exitCode != 0 || errMsg != "" {
		status = "failed"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET ended_at=?, exit_code=?, output=?, error=?, status=? WHERE id=?`,
		time.Now().Unix(), exitCode, output, errMsg, status, id)
	return err
}

func (s *Store) GetRun(ctx context.Context, id string) (Run, error) {
	var r Run
	err := s.db.QueryRowContext(ctx, `SELECT id,action_id,action_label,command,user,ip,started_at,ended_at,exit_code,output,error,status FROM runs WHERE id=?`, id).
		Scan(&r.ID, &r.ActionID, &r.Label, &r.Command, &r.User, &r.IP, &r.StartedAt, &r.EndedAt, &r.ExitCode, &r.Output, &r.Error, &r.Status)
	return r, err
}

func (s *Store) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,action_id,action_label,command,user,ip,started_at,ended_at,exit_code,output,error,status FROM runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.ActionID, &r.Label, &r.Command, &r.User, &r.IP, &r.StartedAt, &r.EndedAt, &r.ExitCode, &r.Output, &r.Error, &r.Status); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type Session struct {
	ID        string
	User      string
	Email     string
	Role      string
	CSRF      string
	CreatedAt int64
	ExpiresAt int64
	IP        string
}

func (s *Store) CreateSession(ctx context.Context, x Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(id,user,email,role,csrf,created_at,expires_at,ip) VALUES(?,?,?,?,?,?,?,?)`,
		x.ID, x.User, x.Email, x.Role, x.CSRF, x.CreatedAt, x.ExpiresAt, x.IP)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var x Session
	err := s.db.QueryRowContext(ctx, `SELECT id,user,email,role,csrf,created_at,expires_at,ip FROM sessions WHERE id=? AND expires_at > ?`, id, time.Now().Unix()).
		Scan(&x.ID, &x.User, &x.Email, &x.Role, &x.CSRF, &x.CreatedAt, &x.ExpiresAt, &x.IP)
	return x, err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

func (s *Store) PruneRuns(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM runs WHERE started_at < ?`, before)
	return err
}

func (s *Store) PruneNotifications(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE sent_at > 0 AND sent_at < ?`, before)
	return err
}

func (s *Store) PruneServiceEvents(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_events WHERE at < ?`, before)
	return err
}

type Notification struct {
	ID        int64
	Channel   string
	Event     string
	Payload   string
	CreatedAt int64
	Attempts  int
	NextTry   int64
	SentAt    int64
	LastError string
}

func (s *Store) EnqueueNotification(ctx context.Context, channel, event, payload string) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO notifications(channel,event,payload,created_at,next_try) VALUES(?,?,?,?,?)`, channel, event, payload, now, now)
	return err
}

func (s *Store) DueNotifications(ctx context.Context, limit int) ([]Notification, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,channel,event,payload,created_at,attempts,next_try,sent_at,last_error FROM notifications WHERE sent_at=0 AND next_try<=? ORDER BY id LIMIT ?`, time.Now().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.Channel, &n.Event, &n.Payload, &n.CreatedAt, &n.Attempts, &n.NextTry, &n.SentAt, &n.LastError); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) MarkNotificationSent(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notifications SET sent_at=?, attempts=attempts+1, last_error='' WHERE id=?`, time.Now().Unix(), id)
	return err
}

func (s *Store) MarkNotificationFailed(ctx context.Context, id int64, errMsg string) error {
	var attempts int
	_ = s.db.QueryRowContext(ctx, `SELECT attempts FROM notifications WHERE id=?`, id).Scan(&attempts)
	backoff := []int64{60, 300, 1800, 7200, 21600}
	idx := attempts
	if idx >= len(backoff) {
		idx = len(backoff) - 1
	}
	next := time.Now().Unix() + backoff[idx]
	_, err := s.db.ExecContext(ctx, `UPDATE notifications SET attempts=attempts+1, next_try=?, last_error=? WHERE id=?`, next, truncate(errMsg, 500), id)
	return err
}

type MetricSample struct {
	TS    int64
	CPU   float64
	Mem   float64
	Disk  float64
	Load1 float64
	NetRx float64
	NetTx float64
}

func (s *Store) InsertMetricSample(ctx context.Context, m MetricSample) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO metric_samples(ts,cpu,mem,disk,load1,net_rx,net_tx) VALUES(?,?,?,?,?,?,?)`,
		m.TS, m.CPU, m.Mem, m.Disk, m.Load1, m.NetRx, m.NetTx)
	return err
}

func (s *Store) PruneMetrics(ctx context.Context, before int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM metric_samples WHERE ts < ?`, before)
	return err
}

func (s *Store) RecentMetrics(ctx context.Context, since int64) ([]MetricSample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts,cpu,mem,disk,load1,net_rx,net_tx FROM metric_samples WHERE ts >= ? ORDER BY ts`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricSample
	for rows.Next() {
		var m MetricSample
		if err := rows.Scan(&m.TS, &m.CPU, &m.Mem, &m.Disk, &m.Load1, &m.NetRx, &m.NetTx); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanService(sc scanner) (Service, error) {
	var sv Service
	var ports string
	var active, ignored, favorite, muted, acked int
	err := sc.Scan(&sv.Key, &sv.Name, &sv.Kind, &sv.Unit, &sv.Container, &sv.Image, &ports, &sv.Exposure,
		&sv.FirstSeen, &sv.LastSeen, &active, &ignored, &sv.Label, &sv.Description, &sv.URL, &sv.Group,
		&favorite, &sv.Visibility, &muted, &acked, &sv.UpdatedBy, &sv.UpdatedAt)
	if err != nil {
		return sv, err
	}
	_ = json.Unmarshal([]byte(ports), &sv.Ports)
	sv.Active = active == 1
	sv.Ignored = ignored == 1
	sv.Favorite = favorite == 1
	sv.Muted = muted == 1
	sv.Acked = acked == 1
	return sv, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
