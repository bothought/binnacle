# Actions

Actions are declared in the server-side config file. They become buttons, but
the browser can never create, edit or parameterize a command. Every action is a
fixed argv array.

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

- `command` is executed directly. No shell is involved unless you explicitly
  call one.
- `timeout` defaults to 60s and is capped at 30m. The process group is killed on
  timeout.
- `confirm: true` adds a checkbox.
- `dangerous: true` requires typing the label exactly. Use it for anything that
  restarts networking, deletes data, or reboots.
- At most two actions run at once, and only one instance of the same action.
- Output is streamed live, capped at 256 KiB, and retained in the audit
  history for 90 days.
- The action runs as the Binnacle service user, with your home directory as cwd
  and a scrubbed environment (`PATH`, `HOME`, `XDG_RUNTIME_DIR`, D-Bus, locale).
- Failure generates an `action_failed` alert, with a link to the run.

## Cookbook

Restart a user service:

```yaml
  - id: restart-caddy
    label: Restart Caddy
    command: [systemctl, --user, restart, caddy]
```

Pull and restart containers labeled for auto-update:

```yaml
  - id: update-containers
    label: Update containers
    command: [podman, auto-update]
    timeout: 5m
    confirm: true
    dangerous: true
```

Update Flatpaks:

```yaml
  - id: update-flatpaks
    label: Update Flatpaks
    command: [flatpak, update, -y]
    timeout: 15m
    confirm: true
```

Rebuild the bootc/rpm-ostree OS (download only, then reboot separately):

```yaml
  - id: stage-os-update
    label: Stage OS update
    command: [rpm-ostree, upgrade]
    timeout: 30m
    confirm: true
    dangerous: true
```

Truncate the user journal:

```yaml
  - id: vacuum-journal
    label: Vacuum journal
    command: [journalctl, --user, --vacuum-time=14d]
    timeout: 2m
    confirm: true
```

Run a local backup script:

```yaml
  - id: backup
    label: Back up home
    command: ["/home/me/bin/backup.sh"]
    timeout: 30m
    confirm: true
```

## System-level commands

The supplied systemd unit sets `NoNewPrivileges=yes`, so `sudo` will not work.
If you need a root command, you have two options:

1. Run Binnacle as root (not recommended; actions then run as root).
2. Remove `NoNewPrivileges=yes` and add a narrowly scoped sudoers file:

```
# /etc/sudoers.d/binnacle
youruser ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx.service
```

Then invoke it without a shell:

```yaml
  - id: restart-nginx
    label: Restart nginx
    command: [sudo, -n, systemctl, restart, nginx.service]
    confirm: true
```

Never use a wildcard argument in sudoers for a command reachable from a web UI.

## Shell scripts

If you genuinely need shell features, call the shell explicitly and keep the
script owned by the service user:

```yaml
  - id: shell-example
    label: Run shell task
    command: [/bin/bash, -lc, "/home/me/bin/task.sh"]
    timeout: 10m
    confirm: true
```

The script is not uploadable through Binnacle. Keep it versioned outside the
panel and review it like any other privileged automation.

## Audit

Every run records:

- action ID and label
- exact argv
- user and source IP
- start/end time and exit code
- stdout/stderr (bounded, possibly truncated in the middle)

The Actions page shows recent runs; the run page streams live output over SSE.
