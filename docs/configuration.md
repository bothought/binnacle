# Configuration

The config file is strict YAML: unknown keys are rejected. `${ENV_VAR}` is
expanded in values, never in comments. Missing referenced variables are a
startup error. Paths support `~`.

The process needs a restart after config changes. State (labels, sessions,
audit, update cache) lives in SQLite; commands and secrets do not.

## Top level

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8099` | HTTP listen address. Keep it loopback. |
| `base_url` | empty | Absolute URL used in links inside alerts. |
| `state_dir` | `~/.local/state/binnacle` | SQLite and runtime state. |
| `hostname` | detected | Display name; also used in notification payloads. |

## auth

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `local` | `forward` or `local`. |
| `session_ttl` | `12h` | Session lifetime. |
| `local.username` | | Local account name. |
| `local.password_hash` | | argon2id PHC string from `binnacle auth hash`. |
| `local.totp_secret` | empty | Optional TOTP secret from `binnacle auth totp`. |

Forward-auth:

| Key | Default | Meaning |
| --- | --- | --- |
| `forward.trusted_proxies` | loopback | IPs/CIDRs allowed to assert identity. |
| `forward.user_header` | `Remote-User` | Identity header. |
| `forward.email_header` | `Remote-Email` | Email header; optional. |
| `forward.groups_header` | `Remote-Groups` | Group header. |
| `forward.admin_groups` | empty | Groups with write access. Empty means any authenticated user is admin. |
| `forward.viewer_groups` | empty | Read-only groups. |
| `forward.proxy_secret` | empty | Shared secret required from the proxy. Strongly recommended. |
| `forward.proxy_secret_header` | `X-Binnacle-Proxy-Secret` | Header carrying the secret. |
| `forward.logout_url` | empty | Where `/logout` redirects (typically Authelia). |

If any group list is configured, a user who matches neither list is denied.

## collector

| Key | Default | Meaning |
| --- | --- | --- |
| `interval` | `10s` | Port scan interval (minimum 1s). |
| `metrics_interval` | `5s` | Host metrics sample interval. |
| `disk_warn_percent` | `90` | Disk alert threshold. |
| `ignore_patterns` | built-in | Case-insensitive glob/substring matches against name, unit, container, image. |

Sockets with no attributable process owner that only use ports >= 32768 are
marked system/hidden by default. They remain in the inventory.

## integrations

Every block is optional. Unreachable integrations render as down with the last
error; they never stop the page.

```yaml
integrations:
  beszel:
    url: http://127.0.0.1:8091
    auth: forward            # forward, password or none
    remote_email: ${BESZEL_EMAIL}
    email: admin@example.com
    password: ${BESZEL_PASSWORD}

  uptime_kuma:
    url: https://kuma.example.com
    headers: {}

  caddy:
    admin_url: http://127.0.0.1:2019

  custom:
    - name: Gatus
      url: https://status.example.com/api/v1/endpoints/statuses
      status_path: "0.success"
      title_path: "0.name"
      detail_path: "0.results.0.status"
      link_path: ""
```

### Beszel

Uses the PocketBase API. If the hub is configured with
`TRUSTED_AUTH_HEADER=Remote-Email`, `auth: forward` plus `remote_email` reuses the
panel's authenticated identity. Otherwise use a dedicated account with
`auth: password`.

### Uptime Kuma

Enable **Prometheus** in Kuma settings and point `url` at the instance (Binnacle
appends `/metrics`) or directly at the metrics URL. Counts are parsed from
`monitor_status`.

### Caddy

The Caddy admin API is read-only here. It maps upstream dial addresses to public
hostnames and marks services as publicly exposed. Bind the admin API to
loopback.

### Custom JSON

`status_path`, `title_path`, `detail_path` and `link_path` are GJSON paths.
Status values map as: `ok/up/healthy/pass/green`, `warn/warning/degraded/yellow`,
`down/error/fail/failed/red/critical`. Anything else is unknown.

## updates

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Run update checks. |
| `interval` | `6h` | Check interval. |
| `github_token` | empty | Optional GitHub token, raises rate limits. |
| `containers` | `true` | Compare local image digests with registries. |
| `flatpak` | `true` | `flatpak remote-ls --updates`. |
| `rpm_ostree` | `true` | Staged deployments and image-based OS digest. |
| `apps` | empty | Native apps checked through GitHub releases. |

Native app entry:

```yaml
updates:
  apps:
    - name: Beszel
      repo: henrygd/beszel
      match_unit: beszel-hub.service
      match_container: beszel
      version_command: ["/home/me/srv/beszel/bin/beszel", "--version"]
      version_regex: "v?([0-9.]+)"
```

`version_command` is local, trusted code that Binnacle executes read-only on a
schedule. It is not downloaded and not editable from the web UI. `match_unit`
and `match_container` make the entry conditional on the software being present.
If no match is configured, the command is run unconditionally.

### Urgency

`security` is set when release notes contain a CVE/GHSA identifier or security
wording. Otherwise the jump is classified as `major`, `minor` or `patch` by a
tolerant comparator that handles semver and CalVer. `image` means "registry
digest differs". This is a heuristic: the UI links the release and never claims
complete CVE coverage. Only `security` triggers an immediate alert; everything
else waits for the digest or stays on the page.

## actions

```yaml
actions:
  - id: restart-caddy
    label: Restart Caddy
    description: Restart the user-level Caddy service.
    category: services
    command: [systemctl, --user, restart, caddy]
    timeout: 30s
    confirm: false
    dangerous: false
```

`id` is stable and used in the audit log. `command` is an argv array, not a shell
string. The executable is resolved when the config is validated. `timeout` is
capped at 30 minutes. `confirm` shows a checkbox; `dangerous` requires typing
the label exactly. See [actions.md](actions.md).

## alerts

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Master switch. |
| `quiet_hours` | empty | `23:00-08:00`, local time; urgent events bypass. |
| `digest` | `true` | Daily summary of open updates. |
| `digest_hour` | `9` | Local hour. |
| `cooldown` | `6h` | Duplicate suppression per event fingerprint/channel. |

Channels:

```yaml
alerts:
  email:
    host: smtp.example.com
    port: 587
    username: ${SMTP_USER}
    password: ${SMTP_PASSWORD}
    from: binnacle@example.com
    to: [you@example.com]
    tls: starttls        # starttls, tls (implicit, usually 465), none

  ntfy:
    url: https://ntfy.sh
    topic: ${NTFY_TOPIC}
    token: ${NTFY_TOKEN}

  webhook:
    url: ${WEBHOOK_URL}
    format: generic      # generic, discord, slack
    headers: {}
```

Rules select channels per event:

```yaml
alerts:
  rules:
    new_service: [email, ntfy]
    service_down: [email]
    service_up: [email]
    exposure: [email, ntfy]
    urgent_update: [email, ntfy]
    unit_failed: [email]
    disk: [email]
    action_failed: [email]
    digest: [email]
```

Rules naming a channel that is not configured are skipped. If `rules` is
omitted, every configured channel receives every event. Notifications are
persisted in an outbox and retried with backoff. Email can be tested with
`binnacle notify test`. The daily digest is skipped when there is nothing open.

## State and permissions

Binnacle warns if the config file is group/world-readable. Use `chmod 600` when
it contains SMTP or API credentials. The default state directory is `0700`; the
SQLite database contains session IDs and audit output, so protect backups.
