package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func svc(key, name string, port int, exposure string) Service {
	return Service{Key: key, Name: name, Kind: "unit", Unit: name + ".service", Exposure: exposure,
		Ports: []Port{{Proto: "tcp", Port: port}}, Visibility: "auto"}
}

func TestSyncServicesLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	r, err := s.SyncServices(ctx, []Service{
		svc("unit:a", "a", 1000, "loopback"),
		svc("unit:b", "b", 2000, "lan"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Created) != 2 {
		t.Fatalf("created = %d", len(r.Created))
	}

	r, err = s.SyncServices(ctx, []Service{svc("unit:a", "a", 1000, "lan")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lost) != 1 || r.Lost[0].Key != "unit:b" {
		t.Fatalf("lost = %+v", r.Lost)
	}
	if len(r.ExposureChanged) != 1 || r.ExposureChanged[0].Exposure != "lan" {
		t.Fatalf("exposure = %+v", r.ExposureChanged)
	}

	r, err = s.SyncServices(ctx, []Service{svc("unit:a", "a", 1000, "lan"), svc("unit:b", "b", 2000, "lan")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Returned) != 1 || r.Returned[0].Key != "unit:b" {
		t.Fatalf("returned = %+v", r.Returned)
	}
}

func TestServiceMetadataAndBaseline(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.SyncServices(ctx, []Service{svc("unit:a", "a", 1000, "loopback")}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateServiceMeta(ctx, "unit:a", "Nice A", "desc", "https://a", "infra", "hidden", true, true, "alice"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListServices(ctx)
	if err != nil || len(list) != 1 {
		t.Fatal(err)
	}
	got := list[0]
	if got.Label != "Nice A" || got.Visibility != "hidden" || !got.Favorite || !got.Muted || got.UpdatedBy != "alice" {
		t.Fatalf("metadata = %+v", got)
	}
	if err := s.SetBaseline(ctx, 123); err != nil {
		t.Fatal(err)
	}
	at, err := s.BaselineAt(ctx)
	if err != nil || at != 123 {
		t.Fatalf("baseline = %d %v", at, err)
	}
	if err := s.AckService(ctx, "unit:a", "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestUpdatesAckLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	u := Update{Key: "app:x", Name: "X", Current: "1.0", Latest: "2.0", Severity: "security", Source: "app", CheckedAt: time.Now().Unix()}
	if err := s.UpsertUpdate(ctx, u); err != nil {
		t.Fatal(err)
	}
	urgent, err := s.UnnotifiedUrgent(ctx)
	if err != nil || len(urgent) != 1 {
		t.Fatalf("urgent = %+v %v", urgent, err)
	}
	if err := s.AckUpdate(ctx, u.Key); err != nil {
		t.Fatal(err)
	}
	u.Latest = "2.0"
	if err := s.UpsertUpdate(ctx, u); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListUpdates(ctx)
	if len(list) != 1 || !list[0].Acknowledged {
		t.Fatalf("ack should persist for same version: %+v", list)
	}
	u.Latest = "3.0"
	if err := s.UpsertUpdate(ctx, u); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListUpdates(ctx)
	if len(list) != 1 || list[0].Acknowledged {
		t.Fatalf("ack should reset for new version: %+v", list)
	}
	if err := s.MarkUpdateNotified(ctx, u.Key, "3.0"); err != nil {
		t.Fatal(err)
	}
	if urgent, _ = s.UnnotifiedUrgent(ctx); len(urgent) != 0 {
		t.Fatalf("urgent after notify = %+v", urgent)
	}
}

func TestPruneUpdates(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().Unix()
	for _, k := range []string{"a", "b"} {
		_ = s.UpsertUpdate(ctx, Update{Key: k, Name: k, Latest: "1", Severity: "patch", Source: "flatpak", CheckedAt: now})
	}
	if err := s.PruneUpdates(ctx, "flatpak", map[string]bool{"a": true}, now); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListUpdates(ctx)
	if len(list) != 1 || list[0].Key != "a" {
		t.Fatalf("after prune: %+v", list)
	}
}

func TestSessionsAndNotifications(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	sess := Session{ID: "s1", User: "alice", Role: "admin", CSRF: "c", CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), IP: "127.0.0.1"}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "s1")
	if err != nil || got.User != "alice" {
		t.Fatalf("session: %+v %v", got, err)
	}
	if err := s.DeleteSession(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "s1"); err == nil {
		t.Fatal("deleted session still present")
	}

	if err := s.EnqueueNotification(ctx, "webhook", "new_service", `{}`); err != nil {
		t.Fatal(err)
	}
	due, err := s.DueNotifications(ctx, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due: %+v %v", due, err)
	}
	if err := s.MarkNotificationFailed(ctx, due[0].ID, "nope"); err != nil {
		t.Fatal(err)
	}
	due, _ = s.DueNotifications(ctx, 10)
	if len(due) != 0 {
		t.Fatalf("failed notification should back off: %+v", due)
	}
}

func TestMetrics(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().Unix()
	if err := s.InsertMetricSample(ctx, MetricSample{TS: now, CPU: 12, Mem: 40}); err != nil {
		t.Fatal(err)
	}
	got, err := s.RecentMetrics(ctx, now-10)
	if err != nil || len(got) != 1 || got[0].CPU != 12 {
		t.Fatalf("metrics: %+v %v", got, err)
	}
	if err := s.PruneMetrics(ctx, now+1); err != nil {
		t.Fatal(err)
	}
	got, _ = s.RecentMetrics(ctx, 0)
	if len(got) != 0 {
		t.Fatalf("metrics not pruned: %+v", got)
	}
}
