package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bothought/binnacle/internal/auth"
)

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "dashboard", http.StatusOK, s.dashboardModel(r))
}

func (s *Server) dashboardPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, r, "dashboard", "dashboard_content", s.dashboardModel(r))
}

func (s *Server) servicesPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "services", http.StatusOK, s.servicesModel(r))
}

func (s *Server) servicesUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	key := strings.TrimSpace(r.PostForm.Get("key"))
	if key == "" {
		s.renderError(w, r, http.StatusBadRequest, "Missing service key.")
		return
	}
	label := clip(strings.TrimSpace(r.PostForm.Get("label")), 80)
	description := clip(strings.TrimSpace(r.PostForm.Get("description")), 500)
	link := clip(strings.TrimSpace(r.PostForm.Get("url")), 300)
	group := clip(strings.TrimSpace(r.PostForm.Get("group")), 60)
	visibility := r.PostForm.Get("visibility")
	if visibility == "" {
		visibility = "auto"
	}
	switch visibility {
	case "auto", "public", "internal", "hidden":
	default:
		s.renderError(w, r, http.StatusBadRequest, "Invalid visibility.")
		return
	}
	if link != "" {
		u, err := url.Parse(link)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			s.renderError(w, r, http.StatusBadRequest, "The URL must start with http:// or https://.")
			return
		}
	}
	sess := sessionOf(r)
	if err := s.deps.Store.UpdateServiceMeta(r.Context(), key, label, description, link, group, visibility,
		r.PostForm.Get("favorite") == "on", r.PostForm.Get("muted") == "on", sess.User); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not save the service.")
		return
	}
	http.Redirect(w, r, "/services?ok=Service+saved", http.StatusSeeOther)
}

func (s *Server) servicesAck(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	key := r.PostForm.Get("key")
	if key == "" {
		s.renderError(w, r, http.StatusBadRequest, "Missing service key.")
		return
	}
	if err := s.deps.Store.AckService(r.Context(), key, sessionOf(r).User); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not acknowledge the service.")
		return
	}
	http.Redirect(w, r, "/services?ok=Acknowledged", http.StatusSeeOther)
}

func (s *Server) servicesAckAll(w http.ResponseWriter, r *http.Request) {
	baseline, _ := s.deps.Store.BaselineAt(r.Context())
	if err := s.deps.Store.AckAllNew(r.Context(), baseline, sessionOf(r).User); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not acknowledge services.")
		return
	}
	http.Redirect(w, r, "/services?ok=All+new+services+acknowledged", http.StatusSeeOther)
}

func (s *Server) updatesPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "updates", http.StatusOK, s.updatesModel(r))
}

func (s *Server) updatesAck(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	if key := r.PostForm.Get("key"); key != "" {
		if err := s.deps.Store.AckUpdate(r.Context(), key); err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "Could not acknowledge the update.")
			return
		}
	}
	http.Redirect(w, r, "/updates?ok=Update+acknowledged", http.StatusSeeOther)
}

func (s *Server) actionsPage(w http.ResponseWriter, r *http.Request) {
	runs, _ := s.deps.Store.ListRuns(r.Context(), 30)
	s.render(w, r, "actions", http.StatusOK, actionsData{
		baseData: s.base(r, "Actions", "actions"),
		Actions:  s.buildActions(r.Context()),
		Runs:     runs,
	})
}

func (s *Server) actionConfirm(w http.ResponseWriter, r *http.Request) {
	if sessionOf(r).Role != "admin" {
		s.renderError(w, r, http.StatusForbidden, "This account is read-only.")
		return
	}
	id := r.PathValue("id")
	action, ok := s.deps.Actions.Get(id)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Action not found.")
		return
	}
	s.render(w, r, "action_confirm", http.StatusOK, confirmData{
		baseData: s.base(r, action.Label, "actions"),
		Action:   action,
		Running:  s.deps.Actions.Running()[id],
	})
}

func (s *Server) actionRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	id := r.PostForm.Get("id")
	action, ok := s.deps.Actions.Get(id)
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "Action not found.")
		return
	}
	sess := sessionOf(r)
	run := confirmData{baseData: s.base(r, action.Label, "actions"), Action: action, Running: s.deps.Actions.Running()[id]}
	if action.Dangerous {
		if strings.TrimSpace(r.PostForm.Get("confirm_text")) != action.Label {
			run.Error = "Type the action name exactly to confirm."
			s.render(w, r, "action_confirm", http.StatusBadRequest, run)
			return
		}
	} else if action.Confirm && r.PostForm.Get("confirm") != "yes" {
		run.Error = "Please tick the confirmation box."
		s.render(w, r, "action_confirm", http.StatusBadRequest, run)
		return
	}
	runID, err := s.deps.Actions.Run(context.Background(), action, sess.User, auth.ClientIP(r))
	if err != nil {
		run.Error = err.Error()
		s.render(w, r, "action_confirm", http.StatusConflict, run)
		return
	}
	http.Redirect(w, r, "/runs/"+runID, http.StatusSeeOther)
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.deps.Store.GetRun(r.Context(), id)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "Run not found.")
		return
	}
	data := runData{baseData: s.base(r, "Run "+shortText(id, 6), "actions"), Run: run}
	if run.Status != "running" {
		data.Output = run.Output
	}
	data.Active = run.Status == "running"
	s.render(w, r, "run", http.StatusOK, data)
}

type sseMessage struct {
	Chunk string `json:"chunk,omitempty"`
	Done  bool   `json:"done,omitempty"`
}

func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, err := s.deps.Store.GetRun(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	writeSSE := func(m sseMessage) bool {
		b, _ := json.Marshal(m)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	initial, ch, done, active := s.deps.Actions.Subscribe(id)
	if active {
		if initial != "" && !writeSSE(sseMessage{Chunk: initial}) {
			s.deps.Actions.Unsubscribe(id, ch)
			return
		}
		if done {
			writeSSE(sseMessage{Done: true})
			return
		}
		defer s.deps.Actions.Unsubscribe(id, ch)
		keep := time.NewTicker(15 * time.Second)
		defer keep.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case chunk, ok := <-ch:
				if !ok {
					writeSSE(sseMessage{Done: true})
					return
				}
				if !writeSSE(sseMessage{Chunk: chunk}) {
					return
				}
			case <-keep.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
	// No live process (finished or server restarted): replay the stored output.
	if run.Output != "" {
		if !writeSSE(sseMessage{Chunk: run.Output}) {
			return
		}
	}
	writeSSE(sseMessage{Done: true})
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "settings", http.StatusOK, s.settingsModel(r))
}

func (s *Server) notifyTest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "Invalid form.")
		return
	}
	channel := r.PostForm.Get("channel")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.deps.Notifier.Test(ctx, channel); err != nil {
		http.Redirect(w, r, "/settings?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?ok=Test+notification+sent", http.StatusSeeOther)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
