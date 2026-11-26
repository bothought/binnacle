// Package actions runs the explicitly configured host commands.
package actions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/store"
)

var ErrBusy = errors.New("another action is already running")
var ErrNotFound = errors.New("action not found")

type Manager struct {
	actions   map[string]config.ActionConfig
	order     []config.ActionConfig
	store     *store.Store
	mu        sync.Mutex
	active    map[string]*activeRun
	actionRun map[string]string
	total     int
	maxTotal  int
	onFinish  func(store.Run)
	maxOutput int
	retention time.Duration
}

type activeRun struct {
	mu      sync.Mutex
	output  []byte
	subs    map[chan string]bool
	done    bool
	exit    int
	err     string
	started time.Time
	max     int
}

func New(cfg []config.ActionConfig, st *store.Store, onFinish func(store.Run)) *Manager {
	m := &Manager{
		actions: map[string]config.ActionConfig{}, store: st, onFinish: onFinish,
		active: map[string]*activeRun{}, actionRun: map[string]string{},
		maxTotal: 2, maxOutput: 256 << 10, retention: 10 * time.Minute,
	}
	for _, a := range cfg {
		m.actions[a.ID] = a
		m.order = append(m.order, a)
	}
	go m.reaper()
	return m
}

func (m *Manager) List() []config.ActionConfig {
	out := make([]config.ActionConfig, len(m.order))
	copy(out, m.order)
	return out
}

func (m *Manager) Get(id string) (config.ActionConfig, bool) {
	a, ok := m.actions[id]
	return a, ok
}

func (m *Manager) Running() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id := range m.actionRun {
		out[id] = true
	}
	return out
}

// Run starts an action asynchronously and returns its run ID.
func (m *Manager) Run(ctx context.Context, action config.ActionConfig, user, ip string) (string, error) {
	m.mu.Lock()
	if m.total >= m.maxTotal {
		m.mu.Unlock()
		return "", ErrBusy
	}
	if _, ok := m.actionRun[action.ID]; ok {
		m.mu.Unlock()
		return "", fmt.Errorf("%w: %s", ErrBusy, action.Label)
	}
	id, err := newID()
	if err != nil {
		m.mu.Unlock()
		return "", err
	}
	ar := &activeRun{subs: map[chan string]bool{}, started: time.Now(), max: m.maxOutput}
	m.total++
	m.actionRun[action.ID] = id
	m.active[id] = ar
	m.mu.Unlock()

	cmdLine := strings.Join(action.Command, " ")
	run := store.Run{
		ID: id, ActionID: action.ID, Label: action.Label, Command: cmdLine,
		User: user, IP: ip, StartedAt: time.Now().Unix(), Status: "running", ExitCode: -1,
	}
	if err := m.store.CreateRun(ctx, run); err != nil {
		m.mu.Lock()
		delete(m.active, id)
		delete(m.actionRun, action.ID)
		m.total--
		m.mu.Unlock()
		return "", err
	}

	go m.execute(action, run, ar)
	return id, nil
}

func (m *Manager) execute(action config.ActionConfig, run store.Run, ar *activeRun) {
	defer func() {
		if r := recover(); r != nil {
			m.finish(run.ID, action.ID, ar, -1, fmt.Sprintf("panic: %v", r), run)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), action.Timeout.Value())
	defer cancel()
	cmd := exec.CommandContext(ctx, action.Command[0], action.Command[1:]...)
	cmd.Env = safeEnv()
	cmd.Dir = homeDir()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 3 * time.Second
	w := &runWriter{ar: ar}
	cmd.Stdout = w
	cmd.Stderr = w
	err := cmd.Run()
	exit := 0
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			exit = exitErr.ExitCode()
		} else {
			exit = -1
		}
		if ctx.Err() == context.DeadlineExceeded {
			errMsg = "timed out after " + action.Timeout.String()
			exit = -1
		}
	}
	m.finish(run.ID, action.ID, ar, exit, errMsg, run)
}

func (m *Manager) finish(runID, actionID string, ar *activeRun, exit int, errMsg string, run store.Run) {
	ar.mu.Lock()
	if ar.done {
		ar.mu.Unlock()
		return
	}
	ar.done = true
	ar.exit = exit
	ar.err = errMsg
	output := string(ar.output)
	subs := make([]chan string, 0, len(ar.subs))
	for ch := range ar.subs {
		subs = append(subs, ch)
	}
	ar.subs = map[chan string]bool{}
	ar.mu.Unlock()

	final := fmt.Sprintf("\n[exit %d]\n", exit)
	for _, ch := range subs {
		select {
		case ch <- final:
		default:
		}
		close(ch)
	}

	_ = m.store.FinishRun(context.Background(), runID, exit, output, errMsg)
	if exit != 0 || errMsg != "" {
		if m.onFinish != nil {
			run.EndedAt = time.Now().Unix()
			run.ExitCode = exit
			run.Output = output
			run.Error = errMsg
			run.Status = "failed"
			m.onFinish(run)
		}
	}

	m.mu.Lock()
	delete(m.actionRun, actionID)
	m.total--
	m.mu.Unlock()
}

func (m *Manager) reaper() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		for id, ar := range m.active {
			ar.mu.Lock()
			done := ar.done
			started := ar.started
			ar.mu.Unlock()
			if done && time.Since(started) > m.retention {
				delete(m.active, id)
			}
		}
		m.mu.Unlock()
	}
}

// Subscribe returns buffered output and a live channel. If the run is already
// finished, done is true and channel is nil.
func (m *Manager) Subscribe(runID string) (initial string, ch <-chan string, done bool, ok bool) {
	m.mu.Lock()
	ar, ok := m.active[runID]
	m.mu.Unlock()
	if !ok {
		return "", nil, true, false
	}
	ar.mu.Lock()
	defer ar.mu.Unlock()
	if ar.done {
		return string(ar.output), nil, true, true
	}
	c := make(chan string, 64)
	ar.subs[c] = true
	return string(ar.output), c, false, true
}

func (m *Manager) Unsubscribe(runID string, ch <-chan string) {
	m.mu.Lock()
	ar := m.active[runID]
	m.mu.Unlock()
	if ar == nil || ch == nil {
		return
	}
	ar.mu.Lock()
	defer ar.mu.Unlock()
	for c := range ar.subs {
		if c == ch {
			delete(ar.subs, c)
			close(c)
			return
		}
	}
}

type runWriter struct {
	ar *activeRun
}

func (w *runWriter) Write(p []byte) (int, error) {
	w.ar.mu.Lock()
	defer w.ar.mu.Unlock()
	w.ar.output = append(w.ar.output, p...)
	if len(w.ar.output) > w.ar.max {
		w.ar.output = w.ar.output[len(w.ar.output)-w.ar.max:]
	}
	s := string(p)
	for ch := range w.ar.subs {
		select {
		case ch <- s:
		default:
		}
	}
	return len(p), nil
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func safeEnv() []string {
	allowed := []string{"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TMPDIR", "SSH_AUTH_SOCK", "TZ"}
	var out []string
	for _, k := range allowed {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	out = append(out, "TERM=dumb")
	return out
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/"
}
