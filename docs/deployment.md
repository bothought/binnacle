# Deployment

Binnacle is designed to run as an unprivileged user service on the host. This
gives it access to the same rootless containers and user units it manages, and
keeps the action runner out of root.

## 1. Binary and config

```sh
go build -trimpath -o binnacle ./cmd/binnacle
install -Dm755 binnacle ~/.local/bin/binnacle

mkdir -p ~/.config/binnacle ~/.local/state/binnacle
install -Dm600 config.example.yaml ~/.config/binnacle/config.yaml
$EDITOR ~/.config/binnacle/config.yaml
```

Set at least:

```yaml
listen: 127.0.0.1:8099
base_url: https://admin.example.com
auth:
  mode: forward
  forward:
    trusted_proxies: [127.0.0.1]
    admin_groups: [admins]
```

## 2. systemd user service

```sh
install -Dm644 packaging/systemd/binnacle.service ~/.config/systemd/user/binnacle.service
systemctl --user daemon-reload
systemctl --user enable --now binnacle
journalctl --user -u binnacle -f
```

To keep the service running after logout (and across reboots), enable lingering
for the service user once:

```sh
loginctl enable-linger "$USER"
```

The supplied unit hardens the service (`ProtectSystem=strict`,
`NoNewPrivileges`). The home directory stays writable because container and
Flatpak update actions need it. If an action needs `sudo`, `NoNewPrivileges=yes`
must be removed and a narrow sudoers rule added.

Verify from the host:

```sh
curl -fsS http://127.0.0.1:8099/healthz
```

## 3. Caddy + Authelia

Authelia is the intended forward-auth provider. The important parts are:

- Binnacle trusts identity headers only from `trusted_proxies`.
- Caddy injects a shared secret header that the client cannot forge.
- Authelia forwards `Remote-User`, `Remote-Email` and `Remote-Groups`.
- The `admins` group grants write access; `viewers` is read-only.

Caddyfile (host-network Caddy; adjust the upstream if not):

```caddyfile
admin.example.com {
    forward_auth 127.0.0.1:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Email Remote-Groups
    }

    reverse_proxy 127.0.0.1:8099 {
        header_up X-Binnacle-Proxy-Secret {env.BINNACLE_PROXY_SECRET}
    }
}
```

Start Caddy with `BINNACLE_PROXY_SECRET` set to the same value as
`auth.forward.proxy_secret` in Binnacle:

```yaml
auth:
  forward:
    proxy_secret: ${BINNACLE_PROXY_SECRET}
    proxy_secret_header: X-Binnacle-Proxy-Secret
```

Authelia access control:

```yaml
access_control:
  rules:
    - domain: admin.example.com
      policy: two_factor
      subject:
        - "group:admins"
        - "group:viewers"
```

If Binnacle runs in a container instead of on the host, remember that Caddy must
be able to reach it and that container namespaces hide host sockets. Native
systemd deployment is recommended.

### Cloudflare Tunnel

If Caddy is the Cloudflare Tunnel origin (as in a typical
`cloudflared → Caddy → services` setup), add the new hostname to the tunnel
configuration the same way the other services are added. Binnacle itself does
not need to know about Cloudflare.

## 4. Rootless Podman and systemd attribution

Binnacle reads the user's Podman socket automatically when available. It shows
quadlet units, container images, published ports and auto-update labels.

Sockets owned by other users (for example `sshd` or a rootful service) may not
have a process name because reading `/proc/<pid>/fd` is restricted. They are
still listed, keyed by protocol and port, and can be labeled or hidden. Running
Binnacle as root would improve attribution, but it also gives the action runner
root access. That trade is not recommended.

## 5. First scan

The first service scan establishes a baseline. Existing ports are marked
"unreviewed", not "new", and do not generate alerts. Label them and hide desktop
noise from the Services page; subsequent appearances are treated as new.

If you change socket attribution substantially or want to accept the current
state as known, see the Services page's acknowledgement controls (new items) or
reset the database state in `~/.local/state/binnacle/state.db` after stopping
the service.

## 6. Backup

Everything mutable lives in one SQLite database:

```
~/.local/state/binnacle/state.db
```

The config file is the source of truth for commands, integrations and secrets;
back it up separately. Copying the database while the service is stopped is the
simplest consistent backup. Labels and audit history are in SQLite.

## 7. Updates

Binnacle never updates itself. Build a new binary, install it, and restart:

```sh
systemctl --user restart binnacle
```

Release archives and checksums are published by GoReleaser.
