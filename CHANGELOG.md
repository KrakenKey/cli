# Changelog

Notable changes to the KrakenKey CLI. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Documentation
- README: new "Do not rely on AIA chain repair" subsection under Certificate chain. It lists which clients download a missing intermediate from the leaf's AIA `caIssuers` URL and which never do, explains why the full chain is the file to deploy, and shows how to check a server or chain file with `openssl`. CA/Browser Forum ballot SC104 (passed 2026-09-03) makes the AIA extension optional in TLS subscriber certificates, so leaf-only deployments will get less reliable over time. No CLI change.

---

## [v0.7.0] — 2026-10-04

### Added
- `cert renew --if-due` renews only when the certificate is inside the plan's renewal window. Otherwise it prints `Certificate <id> is not due for renewal (expires <date>, renewal window <n> days)` and exits 0 without polling, so it is safe to run from cron or a systemd timer. With `--output json` it prints the API response (`skipped`, `reason`, `expiresAt`, `renewalWindowDays`). Requires an API that supports `?ifDue=true` (KrakenKey/app#126); older APIs ignore it and renew, and the CLI says so. (#45)

### Fixed
- `cert renew --wait` now saves the renewed certificate, chain and full chain once the renewal finishes, the same way `cert issue --wait` does. It previously waited and then wrote nothing, so the files on disk kept the old certificate. `cert renew` gains `--out`, `--chain-out` and `--fullchain-out` (defaults `./<cn>.crt`, `./<cn>.chain.crt`, `./<cn>.fullchain.crt`). With `--output json`, `renew --wait` now prints the renewed certificate object instead of the initial `{"id","status"}` response. (#43)
- `cert issue --wait`, `cert submit --wait` and `cert renew --wait` no longer skip the full chain silently when it cannot be fetched. If you passed `--fullchain-out` (or `--chain-out` and the API returned no intermediate chain), the command now exits 1 with an error that says the leaf certificate was saved and gives the `krakenkey cert download <id> --format fullchain --out <path>` command to fetch the chain later. Without an explicit chain flag it prints a warning on stderr and still exits 0. (#44)

---

## [v0.6.1] — 2026-10-03

### Changed
- `auth --help`, the README and the message after `auth login --web` no longer suggest `auth keys delete` for revoking a key. The API refuses `auth keys create` and `auth keys delete` from an API key (KrakenKey/app#115), so the help now says they need a dashboard session and points to `auth login --web` and the dashboard instead.

---

## [v0.6.0] — 2026-10-03

### Added
- `krakenkey auth login --web` signs in through the dashboard instead of a pasted key. It prints a link and a short code (and opens the browser unless `--no-browser`); approving in the dashboard creates an API key named `CLI login: <hostname>`, which the CLI saves. Requires an API with device login (KrakenKey/app#117). (#38)

### Changed
- Requests made without an API key no longer send an empty `Authorization: Bearer` header. (#38)

---

## [v0.5.0] — 2026-10-03

### Added
- `krakenkey domain check <name>...` checks the DNS records for the names on a certificate: one `_acme-challenge` CNAME per name and, with a working API key, the ownership TXT. Reports `ok`, `missing`, `wrong` or `conflict` per record, exits 1 until all are in place, and `--wait` re-checks until they are. `--resolver` queries a specific DNS server. (#34)
- `KK_ACME_ZONE` overrides the challenge delegation zone (default `acme.krakenkey.io`). (#34)
- `cert show` prints the failure reason for failed certificates, and `cert issue`, `submit`, `renew` and `retry` with `--wait` include it in their error, e.g. a missing `_acme-challenge` CNAME. Requires an API that returns `failureReason`; older APIs keep the previous messages. (#36)

### Changed
- `domain add` now prints the `_acme-challenge` CNAME alongside the TXT record, and its JSON output gains a `dnsRecords` array. Issuance has required the CNAME since the API started checking delegation before each order. (#34)

### Fixed
- Text output no longer prints the raw JSON response above the human-readable output. JSON is written only with `--output json` / `KK_OUTPUT=json`. (#35)

---

## [v0.4.0] — 2026-09-04

### Changed
- Config file with permissions broader than `0600` (readable or writable by group/other) now causes `krakenkey` to refuse to load it and exit with a configuration error, instead of printing a warning and continuing. Not enforced on Windows. Fix with `chmod 600 ~/.config/krakenkey/config.yaml`. (#22)
- Docker images migrated to GitHub Container Registry (`ghcr.io/krakenkey/cli`). The `docker.io/krakenkey/cli` image is no longer updated. Pull with `docker pull ghcr.io/krakenkey/cli:latest`. (#14)
- Multi-platform images now use the GoReleaser `dockers_v2` format — a single OCI image index serves both `amd64` and `arm64` architectures. Per-architecture tags (e.g., `v0.2.0-amd64`) are no longer published. (#14)
- Version tags published on each release: `vMAJOR.MINOR.PATCH`, `vMAJOR.MINOR`, `vMAJOR`, and `latest`. (#14)

### Build
- golangci-lint pinned to v2.13.2 in CI (was floating `@latest`); `actions/checkout` and `actions/setup-go` bumped to v7. (#29)

---

## [v0.3.0] — 2026-05-19

### Added
- **Certificate chain** documentation: cert chain flags and certificate chain section in README. (#11)
- This CHANGELOG. (#12)

### Build
- GitHub Actions bumped: `docker/setup-qemu-action` v3→v4, `docker/setup-buildx-action` v3→v4, `docker/login-action` v3→v4, `goreleaser/goreleaser-action` v6→v7. (#13)

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
