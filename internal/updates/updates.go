// Package updates detects installed software and checks upstream releases.
package updates

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bothought/binnacle/internal/config"
	"github.com/bothought/binnacle/internal/hostruntime"
	"github.com/bothought/binnacle/internal/store"
	"github.com/bothought/binnacle/internal/version"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"gopkg.in/yaml.v3"
)

//go:embed catalog.yaml
var catalogYAML []byte

type catalogEntry struct {
	Name      string `yaml:"name"`
	Repo      string `yaml:"repo"`
	Container string `yaml:"container"`
}

type Manager struct {
	cfg      config.UpdatesConfig
	store    *store.Store
	runtime  *hostruntime.Runtime
	client   *http.Client
	catalog  []catalogEntry
	mu       sync.Mutex
	releases map[string]githubRelease
}

type Result struct {
	CheckedAt int64
	Errors    []string
	Count     int
}

type githubRelease struct {
	Tag  string
	URL  string
	Body string
	ETag string
	OK   bool
}

func New(cfg config.UpdatesConfig, st *store.Store, rt *hostruntime.Runtime) *Manager {
	m := &Manager{
		cfg: cfg, store: st, runtime: rt,
		client:   &http.Client{Timeout: 20 * time.Second},
		releases: map[string]githubRelease{},
	}
	_ = yaml.Unmarshal(catalogYAML, &m.catalog)
	return m
}

func (m *Manager) Check(ctx context.Context) Result {
	start := time.Now().Unix()
	res := Result{CheckedAt: start}
	if !m.cfg.Enabled {
		return res
	}

	if m.cfg.Containers {
		errs := m.checkContainers(ctx, start)
		res.Errors = append(res.Errors, errs...)
	}
	if len(m.cfg.Apps) > 0 {
		errs := m.checkApps(ctx, start)
		res.Errors = append(res.Errors, errs...)
	}
	if m.cfg.Flatpak {
		errs := m.checkFlatpak(ctx, start)
		res.Errors = append(res.Errors, errs...)
	}
	if m.cfg.RPMOstree {
		errs := m.checkOstree(ctx, start)
		res.Errors = append(res.Errors, errs...)
	}
	all, _ := m.store.ListUpdates(ctx)
	res.Count = len(all)
	return res
}

func (m *Manager) checkContainers(ctx context.Context, start int64) []string {
	var errs []string
	containers := m.runtime.Containers(ctx)
	keep := map[string]bool{}
	seenImage := map[string]imageState{}
	for _, ct := range containers {
		key := "container:" + ct.Name
		keep[key] = true
		entry := m.matchCatalog(ct.Image)
		display := ct.Name
		if entry != nil {
			display = entry.Name
		}
		image := ct.Image
		state, ok := seenImage[image]
		if !ok {
			state = imageState{local: localDigests(ctx, m.runtime.Kind(), image)}
			seenImage[image] = state
		}
		remoteDigest, digestErr := remoteDigest(ctx, image)
		if digestErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", image, digestErr))
		}
		hasImageUpdate := digestErr == nil && remoteDigest != "" && !containsDigest(state.local, remoteDigest)

		var latest *githubRelease
		var current string
		if entry != nil && entry.Repo != "" {
			current = versionFromTag(tagOf(image))
			if current != "" {
				rel, err := m.latestRelease(ctx, entry.Repo)
				if err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", entry.Repo, err))
				} else {
					latest = &rel
				}
			}
		}
		if latest != nil && latest.Tag != "" && current != "" && version.Compare(current, latest.Tag) < 0 {
			sev := version.Severity(current, latest.Tag)
			if version.LooksSecurity(latest.Body) {
				sev = "security"
			}
			notes := truncate(latest.Body, 4000)
			if hasImageUpdate {
				notes += "\n\nThe container image on the host also differs from the registry. Restart the container after pulling."
			}
			_ = m.store.UpsertUpdate(ctx, store.Update{
				Key: key, Name: display, Current: current, Latest: version.Normalize(latest.Tag),
				Severity: sev, Source: "container", URL: latest.URL, Notes: notes, CheckedAt: start,
			})
			continue
		}
		if hasImageUpdate {
			short := strings.TrimPrefix(remoteDigest, "sha256:")
			if len(short) > 12 {
				short = short[:12]
			}
			_ = m.store.UpsertUpdate(ctx, store.Update{
				Key: key, Name: display, Current: tagOf(image), Latest: "sha256:" + short,
				Severity: "image", Source: "container",
				Notes:     fmt.Sprintf("The remote digest for %s differs from the local image. Pull and restart the container.", tagOf(image)),
				CheckedAt: start,
			})
		}
	}
	if len(errs) == 0 {
		_ = m.store.PruneUpdates(ctx, "container", keep, start)
	}
	return errs
}

func (m *Manager) checkApps(ctx context.Context, start int64) []string {
	var errs []string
	services, _ := m.store.ListServices(ctx)
	containers := m.runtime.Containers(ctx)
	keep := map[string]bool{}
	for _, app := range m.cfg.Apps {
		key := "app:" + slug(app.Name)
		keep[key] = true
		current := ""
		matched := app.MatchUnit == "" && app.MatchContainer == ""
		if app.MatchUnit != "" {
			for _, s := range services {
				if strings.EqualFold(s.Unit, app.MatchUnit) || strings.EqualFold(s.Name, app.MatchUnit) {
					matched = true
					break
				}
			}
		}
		if app.MatchContainer != "" {
			for _, c := range containers {
				if strings.Contains(strings.ToLower(c.Image), strings.ToLower(app.MatchContainer)) {
					matched = true
					if current == "" {
						current = versionFromTag(tagOf(c.Image))
					}
				}
			}
		}
		if !matched {
			continue
		}
		if len(app.VersionCommand) > 0 {
			out, err := runOutput(ctx, 8*time.Second, app.VersionCommand[0], app.VersionCommand[1:]...)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", app.Name, err))
			} else {
				current = parseVersion(out, app.VersionRegex)
			}
		}
		if app.Repo == "" {
			continue
		}
		rel, err := m.latestRelease(ctx, app.Repo)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", app.Name, err))
			continue
		}
		if rel.Tag == "" {
			continue
		}
		latest := version.Normalize(rel.Tag)
		if current != "" && version.Compare(current, latest) >= 0 {
			continue
		}
		sev := "unknown"
		if current != "" {
			sev = version.Severity(current, latest)
		}
		if version.LooksSecurity(rel.Body) {
			sev = "security"
		}
		_ = m.store.UpsertUpdate(ctx, store.Update{
			Key: key, Name: app.Name, Current: current, Latest: latest,
			Severity: sev, Source: "app", URL: rel.URL, Notes: truncate(rel.Body, 4000), CheckedAt: start,
		})
	}
	if len(errs) == 0 {
		_ = m.store.PruneUpdates(ctx, "app", keep, start)
	}
	return errs
}

func (m *Manager) checkFlatpak(ctx context.Context, start int64) []string {
	var errs []string
	installed := map[string]string{}
	out, err := runOutput(ctx, 15*time.Second, "flatpak", "list", "--app", "--columns=application,version")
	if err != nil {
		errs = append(errs, "flatpak list: "+err.Error())
	} else {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				installed[f[0]] = f[1]
			}
		}
	}
	out, err = runOutput(ctx, 45*time.Second, "flatpak", "remote-ls", "--updates", "--columns=application,version,branch")
	if err != nil {
		errs = append(errs, "flatpak updates: "+err.Error())
		return errs
	}
	keep := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		app := f[0]
		latest := ""
		if len(f) > 1 {
			latest = f[1]
		}
		key := "flatpak:" + app
		keep[key] = true
		current := installed[app]
		sev := "update"
		if current != "" && latest != "" {
			sev = version.Severity(current, latest)
			if sev == "none" {
				continue
			}
		}
		_ = m.store.UpsertUpdate(ctx, store.Update{
			Key: key, Name: app, Current: current, Latest: latest,
			Severity: sev, Source: "flatpak",
			URL:   "https://flathub.org/apps/" + app,
			Notes: "Flatpak update available.", CheckedAt: start,
		})
	}
	if len(errs) == 0 {
		_ = m.store.PruneUpdates(ctx, "flatpak", keep, start)
	}
	return errs
}

type ostreeStatus struct {
	Deployments []struct {
		Booted                  bool              `json:"booted"`
		Staged                  bool              `json:"staged"`
		Version                 string            `json:"version"`
		ContainerImageReference string            `json:"container-image-reference"`
		BaseCommitMeta          map[string]string `json:"base-commit-meta"`
	} `json:"deployments"`
}

func (m *Manager) checkOstree(ctx context.Context, start int64) []string {
	if _, err := exec.LookPath("rpm-ostree"); err != nil {
		return nil
	}
	out, err := runOutput(ctx, 10*time.Second, "rpm-ostree", "status", "--json")
	if err != nil {
		return []string{"rpm-ostree: " + err.Error()}
	}
	var st ostreeStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return []string{"rpm-ostree: invalid JSON"}
	}
	var booted, staged, imageRef, localDigest string
	for _, d := range st.Deployments {
		if d.Booted {
			booted = d.Version
			imageRef = d.ContainerImageReference
			localDigest = d.BaseCommitMeta["ostree.manifest-digest"]
		}
		if d.Staged {
			staged = d.Version
		}
	}
	keep := map[string]bool{}
	var errs []string
	if staged != "" && staged != booted {
		key := "os:staged"
		keep[key] = true
		_ = m.store.UpsertUpdate(ctx, store.Update{
			Key: key, Name: "Operating system", Current: booted, Latest: staged,
			Severity: "update", Source: "ostree",
			Notes: "A new OS deployment is staged. Reboot to apply it.", CheckedAt: start,
		})
	}
	if imageRef != "" && localDigest != "" {
		ref := imageRef
		if i := strings.Index(ref, "docker://"); i >= 0 {
			ref = ref[i+len("docker://"):]
		}
		remote, err := remoteDigest(ctx, ref)
		if err != nil {
			errs = append(errs, "os image: "+err.Error())
		} else if remote != "" && remote != localDigest {
			key := "os:image"
			keep[key] = true
			_ = m.store.UpsertUpdate(ctx, store.Update{
				Key: key, Name: "Operating system image", Current: booted, Latest: "upstream update",
				Severity: "update", Source: "ostree",
				URL:   "https://github.com/ublue-os/bazzite/releases",
				Notes: "The upstream OS image has a new digest. Run `rpm-ostree upgrade` and reboot when convenient. (Image: " + ref + ")", CheckedAt: start,
			})
		}
	}
	if len(errs) == 0 {
		_ = m.store.PruneUpdates(ctx, "ostree", keep, start)
	}
	return errs
}

func (m *Manager) latestRelease(ctx context.Context, repo string) (githubRelease, error) {
	m.mu.Lock()
	cached, ok := m.releases[repo]
	m.mu.Unlock()
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "binnacle")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if m.cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.cfg.GitHubToken)
	}
	if ok && cached.ETag != "" {
		req.Header.Set("If-None-Match", cached.ETag)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified && ok {
		return cached, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return githubRelease{}, fmt.Errorf("GitHub rate limit (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("GitHub HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Tag        string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Body       string `json:"body"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); err != nil {
		return githubRelease{}, err
	}
	if payload.Draft || payload.Prerelease {
		return githubRelease{}, nil
	}
	rel := githubRelease{Tag: payload.Tag, URL: payload.HTMLURL, Body: payload.Body, ETag: resp.Header.Get("ETag"), OK: true}
	m.mu.Lock()
	m.releases[repo] = rel
	m.mu.Unlock()
	return rel, nil
}

func (m *Manager) matchCatalog(image string) *catalogEntry {
	norm := normalizeImage(image)
	base := path.Base(norm)
	for i := range m.catalog {
		c := m.catalog[i].Container
		if c == "" {
			continue
		}
		if norm == c || base == c || strings.HasSuffix(norm, "/"+c) {
			return &m.catalog[i]
		}
	}
	return nil
}

type imageState struct {
	local []string
}

func localDigests(ctx context.Context, kind, image string) []string {
	if kind == "" {
		kind = "podman"
	}
	bin := kind
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, bin, "image", "inspect", image, "--format", "{{json .RepoDigests}}").Output()
	if err != nil {
		return nil
	}
	var digests []string
	_ = json.Unmarshal(out, &digests)
	return digests
}

func remoteDigest(ctx context.Context, image string) (string, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", err
	}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	desc, err := remote.Head(ref, remote.WithContext(c), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithUserAgent("binnacle"))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

func containsDigest(local []string, remote string) bool {
	for _, d := range local {
		if strings.HasSuffix(d, "@"+remote) {
			return true
		}
	}
	return false
}

func tagOf(image string) string {
	s := image
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		return s[i+1:]
	}
	return ""
}

func normalizeImage(image string) string {
	s := image
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "docker.io/library/")
	s = strings.TrimPrefix(s, "docker.io/")
	s = strings.TrimPrefix(s, "index.docker.io/")
	return s
}

var versionTagRE = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})`)

func versionFromTag(tag string) string {
	if tag == "" {
		return ""
	}
	low := strings.ToLower(tag)
	for _, bad := range []string{"latest", "stable", "main", "master", "edge", "nightly", "dev", "develop", "testing"} {
		if low == bad {
			return ""
		}
	}
	m := versionTagRE.FindStringSubmatch(tag)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

var defaultVersionRE = regexp.MustCompile(`(?i)\bv?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)`)

func parseVersion(output, pattern string) string {
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err == nil {
			if m := re.FindStringSubmatch(output); len(m) > 1 {
				return m[1]
			}
		}
	}
	if m := defaultVersionRE.FindStringSubmatch(output); len(m) > 1 {
		return m[1]
	}
	return version.Extract(output)
}

func runOutput(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "app"
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
