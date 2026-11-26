# AGENTS.md

Binnacle is a single-binary Go admin panel for a Linux host. The web UI is
server-rendered; there is no Node/npm build and no separate frontend checkout.
Read `README.md` for scope and `docs/security.md` before touching auth, actions
or host data.

## Commands

- `make demo` — run the UI at `http://127.0.0.1:8099` with auth bypassed, a
  temporary DB and sample services/updates. Actions are disabled; host metrics
  and failed units are still real.
- `make test`, `make race`, `make vet`, `make fmt`.
- CI runs exactly: `gofmt -l .`, `go vet ./...`, `go test -race ./...`,
  `go build -trimpath ./...`; `govulncheck ./...` is a separate required job.
- Focused tests: `go test ./internal/web -run TestPagesRender` catches
  template parse/execute errors; `go test ./internal/ports -run TestParseSS`.
- After changing config fields: `make check` validates `config.example.yaml`.
- Binary build: `go build -trimpath -o binnacle ./cmd/binnacle`.

## Workspace rules

- This is a code-only workspace. Do not install Binnacle, write
  `~/.config/binnacle`, create systemd units, or modify host services. For
  manual checks use `--demo` or a throwaway config with `state_dir` under
  `/tmp` and a loopback port.
- Work on a branch, push it, and open a PR. Do not merge or push a `v*` tag
  unless explicitly instructed; tags trigger the GoReleaser workflow.
- Keep `go 1.26.11` in `go.mod` or newer patched. CI's govulncheck job fails on
  older standard-library patch levels.

## Wiring

- `cmd/binnacle/main.go` owns the CLI and all background loops. `internal/web`
  renders pages and handles requests; do not put collection/update logic in
  handlers.
- Templates and static files live in `internal/web/{templates,static}` and are
  embedded with `go:embed`. Adding a page needs both a template file and a new
  entry in the `pages` map in `internal/web/server.go`. HTMX is vendored; do not
  add a frontend build step.
- `serve` binds the HTTP listener before starting `portsLoop`. Keep that order:
  otherwise Binnacle discovers its own port after baseline and reports itself as
  a new service.
- Alert delivery is queued in SQLite (`notifications`) and drained by a
  background worker. Enqueue through `alerts.Notifier`; don't send synchronously
  from a web handler.

## Repo-specific traps

- The first port scan sets `baseline_at`. `NEW` means
  `first_seen > baseline_at && !acked`, so UI/new-service tests need a fresh
  state DB or a deliberately written baseline. Lost/returned services are not
  new again.
- SQLite schema lives in `Store.migrate` as `CREATE TABLE IF NOT EXISTS` with no
  migration version table. For schema changes, add an additive `ALTER` path for
  existing databases, not just an edited `CREATE`.
- Config parsing is strict (`KnownFields`); unknown keys fail. `${ENV}` expansion
  skips YAML comments but errors on missing referenced vars. New settings need
  validation, `config.example.yaml`, docs and tests.
- The release catalog is embedded from `internal/updates/catalog.yaml`; it is
  never fetched. Network-backed update checks must degrade to an error state and
  must not be required by tests.
- Inventory uses live host data (`ss`, cgroups, systemd, Podman/Docker CLI).
  Non-root attribution for other users' sockets is incomplete; don't assume
  every port has a process name.
- Tests use temp SQLite and `httptest`; do not add tests that require real
  Podman, Caddy, Beszel, Uptime Kuma, GitHub or registry access.

## Security invariants

- Actions are fixed argv arrays declared in server-side YAML only. No browser
  arguments, no shell interpolation, no web-editable commands.
- Every authenticated mutating POST requires an admin session plus CSRF.
  `/login` is the only unauthenticated POST and uses double-submit CSRF. Viewer
  is enforced server-side, not only by hiding controls.
- Keep the CSP strict: no inline scripts/styles, no external fonts/CDNs. Put
  JS/CSS in the embedded static directory.
- Forward auth trusts identity headers only from `trusted_proxies` and supports a
  shared proxy secret; do not weaken those checks.
