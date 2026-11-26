# Security

Binnacle is an administrative tool. **Access to the panel is equivalent to
shell access as the Binnacle service user.** Treat it accordingly.

## Threat model

The primary risks are:

1. Unauthorized access to the panel leading to action execution.
2. A compromised reverse proxy or forged identity headers.
3. A malicious or overly broad action definition.
4. Leakage of secrets in the config file or notification channels.
5. Supply-chain issues in Go dependencies or the release artifact.

## Authentication and authorization

Two modes exist:

- **forward**: identity is asserted by a trusted reverse proxy (Authelia is the
  intended setup). Only `auth.forward.trusted_proxies` may assert headers.
  Configure `proxy_secret` and have the proxy inject it; this prevents direct
  loopback requests from forging `Remote-*` headers.
- **local**: one argon2id password, optional TOTP, login rate limiting and
  server-side sessions.

Roles come from `Remote-Groups` in forward mode: `admin_groups` can mutate, and
`viewer_groups` are read-only. If group lists are configured, unmatched users
are denied. The UI hides write controls for viewers and the server rejects POSTs.

The panel binds `127.0.0.1` by default. Do not expose it directly to a network.
Terminate TLS at the reverse proxy.

## Web protections

- CSRF token bound to the session on every state-changing POST.
- Session cookie is HttpOnly, SameSite=Lax, and Secure when TLS is detected.
- Content Security Policy: self-hosted scripts/styles only, no inline or
  third-party resources, no framing.
- Login rate limit, session expiry, and audit identity on actions.
- HTML templates escape output; no user HTML is rendered as trusted.
- No telemetry, external fonts or CDN requests.

## Actions are remote code execution by design

Mitigations:

- Commands exist only in the root/user-owned YAML file, never in the database or
  browser.
- No shell interpolation; argv arrays; no browser-supplied arguments.
- Commands are resolved and validated at startup.
- Timeout kills the process group; output is capped.
- One run per action and a global concurrency cap.
- Dangerous actions require typing the label.
- Every run is audited with user, IP, command, output and exit status.

The action runner inherits the service user's permissions. A root Binnacle means
root actions. Prefer a user service and escalate specific commands through a
narrow sudoers rule. Keep the config file mode `0600` because it can contain
SMTP/API credentials.

## Host data

Binnacle reads:

- `/proc`, `/etc/os-release`, gopsutil metrics
- `ss` output and cgroup names
- Podman/Docker metadata over the local CLI/socket
- `systemctl` failed units
- `flatpak` and `rpm-ostree` status
- Caddy's localhost admin API (optional)

It does not read container filesystems or arbitrary user files. Action output
and service labels are stored in SQLite.

## Notifications

Email uses SMTP directly; ntfy and webhooks use HTTPS URLs. Secrets are expanded
from environment variables and never stored in SQLite. Notification payloads may
include service names, ports, versions and release links. Do not put secrets in
service labels.

## Updates

Binnacle never updates software. It compares versions/digests and links to the
release. `version_command` entries are local trusted code executed as the
service user. The built-in catalog is compiled into the binary and is not fetched
from the network.

## Hardening checklist

- Run as a dedicated user, not root.
- Bind to loopback and use Authelia/forward-auth.
- Set `proxy_secret` and inject it only from the proxy.
- Set `admin_groups` and `viewer_groups`.
- Keep config mode `0600`, state directory `0700`.
- Keep `NoNewPrivileges=yes` unless a reviewed sudoers rule requires otherwise.
- Review every action and every custom `version_command`.
- Back up SQLite with the same care as shell history.
- Subscribe to release notifications for dependencies.

## Reporting

Please do not open a public issue for a vulnerability. Use GitHub's private
security advisory feature for `bothought/binnacle`, or contact the maintainer
directly. Include reproduction steps and the affected version.
