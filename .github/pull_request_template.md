## Summary

## Checks

- [ ] Tests pass (`make test`; `make race` for concurrency/auth changes)
- [ ] `make check` passes when config fields or the example config changed
- [ ] No real usernames, hostnames, email addresses, private IPs, absolute home
      paths, credentials, tokens, or state databases are included
- [ ] New mutating endpoints enforce admin + CSRF and preserve the read-only
      viewer role
