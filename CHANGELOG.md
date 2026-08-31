# Changelog

Notable changes to the KrakenKey CLI. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed
- Config file with permissions broader than `0600` (readable or writable by group/other) now causes `krakenkey` to refuse to load it and exit with a configuration error, instead of printing a warning and continuing. Not enforced on Windows. Fix with `chmod 600 ~/.config/krakenkey/config.yaml`. (#22)

---

## [v0.2.0] — 2026-05-14

### Added
- `cert issue` / `cert submit`: `--chain-out` flag (default `./<domain>.chain.pem`) — writes the intermediate CA chain to disk alongside the leaf certificate.
- `cert issue` / `cert submit`: `--fullchain-out` flag (default `./<domain>.fullchain.pem`) — writes leaf + intermediates.
- `cert download`: `--format` flag with values `cert` (leaf only, default), `chain` (intermediates only), and `fullchain` (leaf + intermediates).
- `cert show` now displays per-entry details for each intermediate in the chain (subject, issuer, fingerprint, expiry).
- **Certificate chain** section in README explaining the three output files and when to use each.
- Updated CI/CD examples in README to include `--fullchain-out`.
- `endpoint region add` / `region remove` commands now note the Starter tier requirement in README.

### Depends on
- KrakenKey/app v0.4.0 or later (for `GET /certs/tls/:id/chain` backend endpoint)

---

## [v0.1.0] — 2026-03-27

### Added
- Initial release: `auth`, `domain`, `cert`, `endpoint`, and `account` command groups.
- ECDSA P-256 / P-384 and RSA 2048 / 4096 CSR generation using Go `crypto` stdlib. Private keys are never sent to the API.
- Configuration stored in `~/.config/krakenkey/config.yaml` (respects `XDG_CONFIG_HOME`), created with `0600` permissions.
- Text (default, colored with spinners) and JSON (`--output json`) output modes.
- Exit codes 0–5 for success, general error, auth error, not-found, rate limit, and config error.
- Multi-architecture Docker image (`ghcr.io/krakenkey/cli`) for amd64 and arm64.
- `endpoint` command with subcommands for CRUD, probe assignment, hosted region management, and on-demand TLS scan.
- Migrated from Go stdlib `flag` to `pflag` for POSIX-style double-dash flags.
- 38 unit tests covering certificate issue, submit, download, and auth flows.
