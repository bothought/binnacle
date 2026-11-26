package actions

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func waitRun(t *testing.T, st *store.Store, id string) store.Run {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, err := st.GetRun(context.Background(), id)
		if err == nil && r.Status != "running" {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("run did not finish")
	return store.Run{}
}

func TestRunSuccessAndFailure(t *testing.T) {
	st := testStore(t)
	failed := make(chan store.Run, 1)
	m := New([]config.ActionConfig{
		{ID: "ok", Label: "OK", Command: []string{"sh", "-c", "printf hello"}, Timeout: config.Duration(5 * time.Second)},
		{ID: "bad", Label: "Bad", Command: []string{"sh", "-c", "printf oops; exit 7"}, Timeout: config.Duration(5 * time.Second)},
	}, st, func(r store.Run) { failed <- r })

	id, err := m.Run(context.Background(), config.ActionConfig{ID: "ok", Label: "OK", Command: []string{"sh", "-c", "printf hello"}, Timeout: config.Duration(5 * time.Second)}, "alice", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r := waitRun(t, st, id)
	if r.Status != "success" || r.ExitCode != 0 || r.Output != "hello" {
		t.Fatalf("success run: %+v", r)
	}

	id, err = m.Run(context.Background(), config.ActionConfig{ID: "bad", Label: "Bad", Command: []string{"sh", "-c", "printf oops; exit 7"}, Timeout: config.Duration(5 * time.Second)}, "alice", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	r = waitRun(t, st, id)
	if r.Status != "failed" || r.ExitCode != 7 || r.Output != "oops" {
		t.Fatalf("failure run: %+v", r)
	}
	select {
	case got := <-failed:
		if got.ActionID != "bad" {
			t.Fatalf("failed callback: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for failure callback")
	}
}

func TestSubscribeLiveOutput(t *testing.T) {
	st := testStore(t)
	m := New(nil, st, nil)
	a := config.ActionConfig{ID: "slow", Label: "Slow", Command: []string{"sh", "-c", "sleep 0.4; printf ok"}, Timeout: config.Duration(5 * time.Second)}
	id, err := m.Run(context.Background(), a, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	initial, ch, done, ok := m.Subscribe(id)
	if !ok {
		t.Fatal("subscribe failed")
	}
	if done {
		if initial != "ok" {
			t.Fatalf("finished early with %q", initial)
		}
		return
	}
	select {
	case chunk, open := <-ch:
		if !open || chunk != "ok" {
			t.Fatalf("chunk=%q open=%v", chunk, open)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for chunk")
	}
}
