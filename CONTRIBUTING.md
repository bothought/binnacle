# Contributing

Binnacle is intentionally small and opinionated. Bug fixes, deployment notes,
catalog entries and focused improvements are welcome. Large features should be
discussed in an issue first, especially anything that adds a dependency, a
config surface, or another way to execute code.

## Development

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
gofmt -w .
```

Run with sample data:

```sh
go run ./cmd/binnacle serve --demo
```

Run against a real config:

```sh
go run ./cmd/binnacle check --config /path/to/config.yaml
go run ./cmd/binnacle serve --config /path/to/config.yaml
```

## Code layout

- `cmd/binnacle` — CLI only.
- `internal/config` — strict parsing and validation; add a test for every rule.
- `internal/ports` — socket parsing and attribution; pure functions where
  possible.
- `internal/updates` — release detection; network failures must degrade to
  "unknown", never crash the page.
- `internal/web` — handlers and embedded templates/static assets.
- `internal/store` — schema and SQLite state.

## Catalog entries

The built-in catalog lives in `internal/updates/catalog.yaml` and maps container
images to GitHub repositories. Add an entry only when the image repository and
upstream release repository are clearly the same project. The catalog is
compiled in and never downloaded; do not add commands or URLs that execute.

Native apps belong in the user's `updates.apps` config, not the catalog.

## Templates and assets

- Server-rendered HTML with `html/template`; keep the CSP strict.
- No inline scripts or styles. Put JS in `internal/web/static/app.js`.
- No external CDN, fonts, or analytics.
- HTMX is vendored in `internal/web/static/htmx.min.js`.
- Keep the UI dense, monochrome, responsive, and accessible without color alone.

## Security expectations

- Never add a path that executes a browser-provided string.
- New mutating endpoints need CSRF protection and the admin role check.
- New config secrets should support `${ENV_VAR}` expansion.
- New integrations must have a timeout and a visible error state.
- Add a `SECURITY.md` note if a change alters the threat model.

## Privacy and sensitive data

This repository is public. Never commit real usernames, hostnames, email
addresses, IP addresses, paths, credentials, tokens or state databases, including
in examples, tests, docs, commit messages and screenshots.

- Use placeholders: `example.com`, `/home/me`, `admin`, `youruser`, `192.0.2.10`.
- Keep secrets in environment variables referenced as `${VAR}`; never inline
  them in config examples.
- Review `git diff --cached` before committing. `config.yaml`, `.env`, `*.db`
  and similar files are ignored, but ignored files can still be staged with
  `git add -f`.
- If something sensitive is committed, treat it as compromised: rotate the
  credential and remove it from history. Deleting it in a later commit is not
  enough because the old commit remains public.
- CI runs gitleaks and GitHub secret scanning/push protection is enabled for the
  repository.

## Pull requests

- Keep the diff focused.
- Include tests for parsing, comparison, auth, or store changes.
- Update `config.example.yaml` and docs for new settings.
- CI must pass (`gofmt`, `go vet`, `go test -race`, build, gitleaks).
- Do not commit state databases, secrets, or generated binaries.

## License

By contributing, you agree that your contribution is licensed under the MIT
License.
