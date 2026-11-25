# binnacle

A small, opinionated server admin panel. One Go binary, one SQLite file, no
Node build, no telemetry.

Binnacle answers four questions on one screen:

- Is anything wrong?
- What changed?
- What is installed and listening?
- What can I do about it?

It is deliberately **not** another monitoring platform. Keep Beszel, Uptime
Kuma, or Prometheus for history and synthetic checks; Binnacle summarizes them
and focuses on host inventory, updates, and explicit maintenance actions.

```
┌ binnacle ───────────────────── server · healthy ┐
│ Overview   Services   Updates   Actions         │
│                                                 │
│ CPU 14%   RAM 9.1/31G   Disk 62%   Up 3d 4h     │
│                                                 │
│ ATTENTION                                       │
│ ● 2 new services      8099 binnacle · 11434 …   │
│ ● 1 urgent update     Immich 2.1.0 (security)   │
│ ● 1 failed unit       uupd.service              │
│                                                 │
│ EXTERNAL                                        │
│ Beszel 3 systems · 1 warning   Kuma 12/12 up    │
│                                                 │
│ SERVICES 12 shown · 9 hidden        [search]    │
│ ● 443   caddy.service       public   Caddy      │
│ ● 8091  beszel-hub.service  internal Beszel     │
│ ● 8099  binnacle.service    internal NEW        │
│                                                 │
│ ACTIONS  [Restart Caddy] [Update containers]    │
└─────────────────────────────────────────────────┘
```

## Features

- **System overview** — CPU, memory, load, disks, network rate, temperatures,
  failed systemd units, and staged OS deployments. Sparklines, not a metrics
  database.
- **Service inventory** — listening sockets grouped by systemd unit, container
  or process. Label them, add URLs, hide internal services, mark favorites, and
  acknowledge new ones. A baseline is established on the first scan, so a busy
  host does not alert on everything at install time.
- **Update checks** — container image digests, GitHub releases for cataloged
  images, custom native apps, Flatpak updates, and bootc/rpm-ostree deployments.
  Security-looking releases are flagged from their notes.
- **Actions** — YAML-defined commands become buttons. Typed confirmation for
  dangerous commands, live SSE output, exit codes, per-user audit history, time
  limits and a hard cap on concurrent runs. Commands are never editable from the
  web UI.
- **External summaries** — optional Beszel, Uptime Kuma, Caddy and generic JSON
  integrations shown as compact status cards.
- **Alerts** — email, ntfy and generic webhooks (Discord/Slack formats included),
  with per-event routing, deduplication, quiet hours and a daily digest.
- **Auth** — Authelia/forward-auth in front, or a local argon2id account with
  optional TOTP. Session cookies, CSRF protection, CSP, read-only viewer role.
- **Open source ready** — MIT, vendored frontend assets, no build step, CI,
  release archives, a demo mode, and a catalog that ships inside the binary.

## Quick start

Requirements: Linux, systemd, Go 1.26+ to build. Podman or Docker is optional.

```sh
git clone https://github.com/bothought/binnacle
cd binnacle
go build -o binnacle ./cmd/binnacle

mkdir -p ~/.config/binnacle
cp config.example.yaml ~/.config/binnacle/config.yaml
# edit listen/auth/base_url

# local auth instead of forward auth:
./binnacle auth hash
# paste the hash into config.yaml (auth.mode: local)

./binnacle check --config ~/.config/binnacle/config.yaml
./binnacle serve --config ~/.config/binnacle/config.yaml
```

Open `http://127.0.0.1:8099`.

Try it without touching your host state:

```sh
./binnacle serve --demo
```

Demo mode is forced to loopback, bypasses auth, uses a temporary database and
sample services/updates, and disables actions.

## Deployment

Run Binnacle as a **user** systemd service on the host. Do not run it as root
unless you need system-wide socket attribution; rootless Podman and user
services are fully supported.

```sh
install -Dm755 binnacle ~/.local/bin/binnacle
install -Dm644 packaging/systemd/binnacle.service ~/.config/systemd/user/binnacle.service
systemctl --user daemon-reload
systemctl --user enable --now binnacle
loginctl enable-linger "$USER"   # once, so it survives logout/reboot
```

Then put it behind Caddy + Authelia, or another authenticated reverse proxy.
The panel binds to `127.0.0.1` by default.

See [docs/deployment.md](docs/deployment.md) for the Caddy/Authelia example and
[docs/security.md](docs/security.md) before exposing it.

## Configuration

See [config.example.yaml](config.example.yaml) and
[docs/configuration.md](docs/configuration.md).

- `auth.mode`: `forward` (Authelia) or `local`.
- Every integration is optional; an unreachable one is shown as down, not a
  crash.
- `updates.apps` covers native software with a read-only version command.
- `actions` are argv arrays, not shell strings. No arguments are accepted from
  the browser in this version.

See [docs/actions.md](docs/actions.md) for the action cookbook.

## Alerts

Email uses SMTP directly (STARTTLS by default, implicit TLS optional). ntfy and
webhooks need only a URL. A test message can be sent from Settings or:

```sh
./binnacle notify test --config ~/.config/binnacle/config.yaml
```

Alerts are state changes, not periodic spam: new service, exposed service,
service disappeared/returned, failed unit, security update, disk threshold,
action failure. Non-urgent updates are summarized in the daily digest.

## Why these choices

- **Host-native, not container-first.** Containers hide `/proc`, systemd and
  socket attribution. Binnacle runs where the host is visible.
- **Server-rendered HTML.** HTMX and hand-written CSS. No Node toolchain, no
  external CDN, no client-side state.
- **Config file is truth.** The UI edits labels and visibility state; commands
  and secrets stay in YAML owned by the service user.
- **No automatic updates.** The panel tells you; you decide.
- **No plugin runtime.** Integrations are compiled in. A generic JSON card is
  the escape hatch.
- **No built-in terminal, file manager, or log explorer.** Those are separate
  tools.

## Project layout

```
cmd/binnacle          CLI entry point
internal/config       strict YAML + env expansion + validation
internal/auth         forward-auth, argon2id, TOTP, sessions, CSRF
internal/system       host metrics, disks, failed units, ostree
internal/ports        ss parser + service attribution
internal/hostruntime  Podman/Docker container discovery
internal/updates      catalog, GitHub, registries, Flatpak, rpm-ostree
internal/integrations Beszel, Uptime Kuma, Caddy, generic JSON
internal/actions      configured command runner + SSE + audit
internal/alerts       SMTP, ntfy, webhook queue + digest
internal/store        SQLite schema and state
internal/web          handlers, templates, embedded static assets
```

## Status

Initial implementation, intentionally narrow. Contributions are welcome,
especially catalog entries and deployment notes; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Binnacle executes configured commands. Treat access to the panel as equivalent
to shell access for the service user. Read [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
