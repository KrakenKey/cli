# krakenkey-cli

[![CI](https://github.com/KrakenKey/cli/actions/workflows/ci.yaml/badge.svg)](https://github.com/KrakenKey/cli/actions/workflows/ci.yaml)
[![Latest Release](https://img.shields.io/github/v/release/KrakenKey/cli)](https://github.com/KrakenKey/cli/releases/latest)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Command-line interface for [KrakenKey](https://krakenkey.io) — TLS certificate lifecycle management from your terminal.

The CLI generates CSRs locally using Go's crypto stdlib (private keys never leave your machine), submits them to the KrakenKey API, polls for issuance, and downloads issued certificates. It covers the same API surface as the web dashboard, designed for terminal workflows and CI/CD pipelines.

## Installation

**Homebrew** (macOS and Linux):

```bash
brew install krakenkey/tap/krakenkey
```

Update with `brew upgrade krakenkey`. The cask comes from [KrakenKey/homebrew-tap](https://github.com/KrakenKey/homebrew-tap) and is updated by each release.

**Binary download** (Linux, macOS, Windows):

Download the latest release from [github.com/KrakenKey/cli/releases](https://github.com/KrakenKey/cli/releases). Archive names include the version, so set it first:

```bash
# Linux amd64 example
VERSION=0.7.1
curl -Lo krakenkey.tar.gz "https://github.com/KrakenKey/cli/releases/download/v${VERSION}/krakenkey_${VERSION}_linux_amd64.tar.gz"
tar -xzf krakenkey.tar.gz
sudo mv krakenkey /usr/local/bin/
```

**Debian/Ubuntu or RHEL/Fedora package** (amd64 and arm64):

Each release also includes `.deb` and `.rpm` packages that install the binary to `/usr/bin/krakenkey`. Download the one for your architecture from the [releases page](https://github.com/KrakenKey/cli/releases/latest), then:

```bash
# Debian, Ubuntu
sudo apt install ./krakenkey_*_linux_amd64.deb

# RHEL, Fedora, Amazon Linux
sudo dnf install ./krakenkey_*_linux_amd64.rpm
```

Replace `amd64` with `arm64` on ARM machines. `checksums.txt` in the release covers the packages too. Remove with `sudo apt remove krakenkey` or `sudo dnf remove krakenkey`.

**go install**:

```bash
go install github.com/krakenkey/cli/cmd/krakenkey@latest
```

**Docker**:

```bash
docker pull ghcr.io/krakenkey/cli:latest
```

## Quick start

```bash
# 1. Sign in: approve the login in your browser (or paste a key with `auth login`)
krakenkey auth login --web

# 2. Register your domain, add the DNS records it prints, then verify
krakenkey domain add example.com
krakenkey domain check example.com --wait
krakenkey domain verify <id>

# 3. Issue a certificate
krakenkey cert issue --domain example.com
```

## Command reference

### `krakenkey auth`

```
krakenkey auth login [--api-key <key>]        Save API key (prompts interactively if omitted)
krakenkey auth login --web [--no-browser]     Approve a login in the dashboard; creates and saves a new API key
krakenkey auth logout                         Remove stored API key
krakenkey auth status                         Show auth status and resource counts
krakenkey auth keys list                      List API keys
krakenkey auth keys create --name <name>      Create a new API key (dashboard session only)
krakenkey auth keys delete <id>               Delete an API key (dashboard session only)
```

`auth login --web` prints a link to `app.krakenkey.io/device` and a short code, opens the link in your browser (unless `--no-browser`), and waits up to 10 minutes. Sign in, check the code matches, and click **Approve**: the dashboard creates an API key named `CLI login: <hostname>` and the CLI saves it to the config file. Instructions go to stderr, so `--output json` stdout carries only `{"keyId", "keyName"}`. Revoke it under **API Keys** in the dashboard.

Creating and deleting keys needs a dashboard session. The CLI always calls the API with an API key, so the API refuses `auth keys create` and `auth keys delete` with a 403. This stops a leaked key from minting a replacement for itself. Use `auth login --web` to get a new key and the dashboard to delete one.

`auth keys create` flags:

| Flag | Description |
|---|---|
| `--name` | Name for the API key (required) |
| `--expires-at` | Expiry date in ISO 8601 format (optional) |

#### Limited keys

A key created in the dashboard can be limited to scopes (for example read-only or certificate renewal), to specific domains or certificates, and to source IP addresses. The limits are fixed when the key is created. `auth keys list` shows them in the **Access** column:

| Access | Meaning |
|---|---|
| `full` | No limits. Every key created before limits existed, and keys from `auth login --web` |
| `read-only`, `cert-renewal`, `probe` | One of the dashboard presets |
| `custom: <scopes>` | Any other set of scopes |
| `(2 domains; 1 cert; IPs ...)` | Domain, certificate or IP limits, after the scopes |

A command outside the key's limits fails with the API's message, for example `This API key needs the certs:revoke scope for this request.` (403), and a certificate or domain outside them is reported as not found. For a renewal job, a `cert-renewal` key limited to the certificate's domain is enough for `cert show`, `cert renew --wait` and `cert download`. With `--output json`, `auth keys list` includes `scopes`, `allowedDomainIds`, `allowedCertIds` and `allowedIps` (`null` when not limited). See the [API reference](https://github.com/KrakenKey/app/blob/main/backend/docs/API_REFERENCE.md#api-key-scopes-and-restrictions) for which commands need which scope.

### `krakenkey domain`

```
krakenkey domain add <hostname>    Register a domain and print the TXT and challenge CNAME records
krakenkey domain list              List all domains
krakenkey domain show <id>         Show domain details and verification record
krakenkey domain check <name>...   Check DNS records for the names on a certificate
krakenkey domain verify <id>       Trigger DNS TXT verification
krakenkey domain delete <id>       Delete a domain
```

Each name on a certificate needs a CNAME from `_acme-challenge.<name>` to `<name with dots as dashes>.acme.krakenkey.io` (a `*.` prefix shares its parent's record). KrakenKey checks these before every order. `domain check` takes the certificate names, resolves each challenge CNAME and, with a working API key, the ownership TXT of the registered domain that covers them. It reports each record as `ok`, `missing`, `wrong` (points elsewhere) or `conflict` (TXT records sit where the CNAME should go), and exits 1 until everything is in place.

`domain check` flags:

| Flag | Default | Description |
|---|---|---|
| `--resolver` | system resolver | DNS server to query, e.g. `1.1.1.1` |
| `--wait` | `false` | Re-check until every record is in place |
| `--poll-interval` | `30s` | How often to re-check |
| `--poll-timeout` | `15m` | Maximum time to wait |

Set `KK_ACME_ZONE` to override the `acme.krakenkey.io` challenge zone when pointing at a non-production API.

### `krakenkey cert`

```
krakenkey cert issue --domain <domain>              Generate key + CSR locally, submit, and optionally wait
krakenkey cert submit --csr <file>                  Submit an existing CSR PEM file
krakenkey cert list [--status <status>]             List certificates (filter: pending|issuing|issued|failed|renewing|revoking|revoked)
krakenkey cert show <id>                            Show certificate details
krakenkey cert download <id> [--out path]           Download certificate PEM
                              [--format cert|chain|fullchain]
krakenkey cert renew <id> [--if-due] [--wait]       Trigger manual renewal (--if-due: only when due; --wait saves the renewed cert)
krakenkey cert revoke <id> [--reason N]             Revoke a certificate (RFC 5280 reason code 0–10)
krakenkey cert retry <id> [--wait]                  Retry failed issuance (--wait saves the issued cert)
krakenkey cert update <id>                          Update certificate settings
krakenkey cert delete <id>                          Delete a certificate (failed or revoked only)
```

`cert issue` flags:

| Flag | Default | Description |
|---|---|---|
| `--domain` | | Primary domain (CN) — required |
| `--san` | | Additional SAN (repeat for multiple) |
| `--key-type` | `ecdsa-p256` | Key type: `rsa-2048`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384` |
| `--org` | | Organization (O) |
| `--ou` | | Organizational unit (OU) |
| `--locality` | | Locality (L) |
| `--state` | | State or province (ST) |
| `--country` | | Country code (C, e.g. US) |
| `--key-out` | `./<domain>.key` | Private key output path |
| `--csr-out` | `./<domain>.csr` | CSR output path |
| `--out` | `./<domain>.crt` | Leaf certificate output path |
| `--chain-out` | `./<domain>.chain.crt` | Intermediate CA chain output path |
| `--fullchain-out` | `./<domain>.fullchain.crt` | Full chain output path (leaf + intermediates) |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

`cert submit` flags:

| Flag | Default | Description |
|---|---|---|
| `--csr` | | Path to CSR PEM file — required |
| `--out` | `./<cn>.crt` | Leaf certificate output path |
| `--chain-out` | `./<cn>.chain.crt` | Intermediate CA chain output path |
| `--fullchain-out` | `./<cn>.fullchain.crt` | Full chain output path (leaf + intermediates) |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

`cert renew` flags:

| Flag | Default | Description |
|---|---|---|
| `--if-due` | `false` | Only renew if the certificate is inside your plan's renewal window; otherwise print a note and exit 0. Use this for scheduled renewals |
| `--out` | `./<cn>.crt` | Leaf certificate output path |
| `--chain-out` | `./<cn>.chain.crt` | Intermediate CA chain output path |
| `--fullchain-out` | `./<cn>.fullchain.crt` | Full chain output path (leaf + intermediates) |
| `--wait` | `false` | Wait for renewal to complete, then save the renewed certificate |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

Renewal reuses the certificate's original CSR, so the existing private key stays valid. With `--wait`, the renewed certificate, chain and full chain are written to the output paths once the renewal finishes, replacing any files already there. With `--if-due`, a certificate outside the renewal window is left alone and nothing is written. Without `--wait`, nothing is written; use `cert download` once the status is back to `issued`.

`cert retry` flags:

| Flag | Default | Description |
|---|---|---|
| `--out` | `./<cn>.crt` | Leaf certificate output path |
| `--chain-out` | `./<cn>.chain.crt` | Intermediate CA chain output path |
| `--fullchain-out` | `./<cn>.fullchain.crt` | Full chain output path (leaf + intermediates) |
| `--wait` | `false` | Wait for issuance to complete, then save the certificate |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

Retry reuses the certificate's CSR, so the private key you already have stays valid. With `--wait`, the certificate, chain and full chain are written to the output paths once issuance finishes. If the retry fails again, nothing is written and the command exits 1 with the reason. Without `--wait`, nothing is written; use `cert download` once the status is `issued`.

`cert download` flags:

| Flag | Default | Description |
|---|---|---|
| `--out` | `./<cn>.crt` | Output file path |
| `--format` | `cert` | Certificate format: `cert` (leaf only), `chain` (intermediates only), `fullchain` (leaf + intermediates) |

### `krakenkey endpoint`

```
krakenkey endpoint add <host> [flags]               Add a monitored endpoint
krakenkey endpoint list                              List all endpoints
krakenkey endpoint show <id>                         Show endpoint details
krakenkey endpoint scan <id>                         Request an on-demand TLS scan
krakenkey endpoint probes                            List your connected probes
krakenkey endpoint enable <id>                       Re-enable a disabled endpoint
krakenkey endpoint disable <id>                      Disable an endpoint
krakenkey endpoint delete <id>                       Delete an endpoint
krakenkey endpoint probe add <id> <probe-id>         Assign a connected probe
krakenkey endpoint probe remove <id> <probe-id>      Remove a connected probe
krakenkey endpoint region add <id> <region>           Add a hosted probe region (Starter+)
krakenkey endpoint region remove <id> <region>        Remove a hosted probe region
```

`endpoint add` flags:

| Flag | Default | Description |
|---|---|---|
| `--port` | `443` | Port to monitor |
| `--sni` | | SNI override (optional) |
| `--label` | | Human-readable label (optional) |
| `--probe` | | Connected probe ID to assign (repeat for multiple) |

### `krakenkey account`

```
krakenkey account show    Show profile, email, plan, and resource counts
krakenkey account plan    Show subscription details and plan limits
```

### Global flags

```
--api-url string    API base URL (env: KK_API_URL, default: https://api.krakenkey.io)
--api-key string    API key (env: KK_API_KEY)
--output string     Output format: text, json (env: KK_OUTPUT, default: text)
--no-color          Disable colored output
--verbose           Enable verbose logging
--version           Print version and exit
```

## Configuration

The CLI stores configuration in `~/.config/krakenkey/config.yaml` (respects `XDG_CONFIG_HOME`). The file is created on `krakenkey auth login` with `0600` permissions.

```yaml
api_url: "https://api.krakenkey.io"
api_key: "kk_..."
output: "text"
```

**Precedence** (highest to lowest): CLI flags → environment variables → config file → defaults.

| Setting | Flag | Env var |
|---|---|---|
| API URL | `--api-url` | `KK_API_URL` |
| API key | `--api-key` | `KK_API_KEY` |
| Output format | `--output` | `KK_OUTPUT` |

**Permissions**: on non-Windows systems, the CLI refuses to load a config file with permissions broader than `0600` (readable or writable by group/other) and exits with a configuration error (exit code 5) instead of loading it. Fix with:

```bash
chmod 600 ~/.config/krakenkey/config.yaml
```

## Certificate chain

`cert issue`, `cert submit`, `cert renew --wait` and `cert retry --wait` produce three certificate files (`cert issue` also writes the private key and CSR):

| File | Flag | Default | Contents |
|------|------|---------|----------|
| Leaf certificate | `--out` | `./<domain>.crt` | End-entity certificate only |
| Intermediate chain | `--chain-out` | `./<domain>.chain.crt` | Intermediate CA certificates |
| Full chain | `--fullchain-out` | `./<domain>.fullchain.crt` | Leaf + intermediates |

Most web servers (nginx, Caddy, HAProxy) expect the full chain. Use `--fullchain-out` in production deployments.

If you pass `--fullchain-out` or `--chain-out` and that file cannot be written (for example the chain fetch fails), `--wait` exits with status 1 after saving the leaf certificate, and the error shows the `cert download` command to fetch the chain later. Without those flags a missing chain file is only a warning.

`cert download` accepts `--format` with values `cert` (default), `chain`, and `fullchain` to download a specific format for an already-issued certificate:

```bash
# Download full chain for deployment
krakenkey cert download 42 --format fullchain --out ./fullchain.pem

# Download intermediates only
krakenkey cert download 42 --format chain --out ./chain.pem
```

### Do not rely on AIA chain repair

A server that sends only the leaf certificate works in some clients and fails in others. Some clients fill in the missing intermediate by downloading it from the `caIssuers` URL in the leaf's Authority Information Access (AIA) extension. Others never do:

| Behavior | Clients |
|----------|---------|
| Download the intermediate from AIA | Windows CryptoAPI/Schannel, Apple Security.framework (macOS, iOS), Chrome's certificate verifier |
| Never download from AIA | OpenSSL and the tools built on it (`curl`, `wget`, Python, Node.js), Go `crypto/x509`, Java unless `com.sun.security.enableAIAcaIssuers=true`, Firefox (it ships its own list of known intermediates instead) |

So a leaf-only setup can look fine in a desktop browser and still fail for API clients, monitoring and CI jobs with `unable to get local issuer certificate`. Serve the file written by `--fullchain-out` (or `cert download --format fullchain`) and every client gets the intermediates it needs.

This matters more over time. CA/Browser Forum ballot SC104 (passed 2026-09-03) makes the AIA extension optional (SHOULD instead of MUST) in TLS subscriber certificates. Let's Encrypt certificates still carry a `caIssuers` URL today, but a certificate without one gives AIA-fetching clients nothing to download.

To check a live server with a client that does not download from AIA:

```bash
openssl s_client -connect example.com:443 -servername example.com -verify_return_error </dev/null
```

A missing intermediate fails with `verify error:num=20:unable to get local issuer certificate`. To check the files before deploying, using the chain downloaded above:

```bash
openssl verify -untrusted ./chain.pem ./example.com.crt
```

## Output formats

**Text** (default): colored, human-readable output with aligned tables and spinners.

**JSON** (`--output json` or `KK_OUTPUT=json`): machine-readable JSON on stdout. No color, no spinners. Every command outputs a JSON object or array. Errors are `{"error":"..."}` on stderr.

```bash
# CI/CD example — set KK_API_KEY from your secrets manager
export KK_OUTPUT=json

CERT_ID=$(krakenkey cert issue --domain "$DOMAIN" --key-type ecdsa-p256 | jq -r '.id')
```

## CI/CD

**GitHub Actions**:

```yaml
- name: Issue certificate
  uses: docker://ghcr.io/krakenkey/cli:latest
  env:
    KK_API_KEY: ${{ secrets.KK_API_KEY }}
    KK_OUTPUT: json
  with:
    args: cert issue --domain example.com --key-out ./example.com.key --out ./example.com.crt --fullchain-out ./example.com.fullchain.pem
```

**Generic shell**:

```bash
docker run --rm \
  -e KK_API_KEY \
  -e KK_OUTPUT=json \
  -v "$(pwd)/certs:/out" \
  ghcr.io/krakenkey/cli:latest \
  cert issue --domain example.com \
    --key-out /out/example.com.key \
    --out /out/example.com.crt \
    --fullchain-out /out/example.com.fullchain.pem
```

## Scheduled renewals

`cert renew` on its own always renews, and every renewal counts against your monthly certificate limit. For cron jobs and systemd timers use `--if-due`: the API renews only when the certificate is inside your plan's renewal window (5 days on Free, 30 days on paid plans). Otherwise nothing happens and the command exits 0 with:

```
• Certificate 42 is not due for renewal (expires 2026-12-01, renewal window 30 days)
```

With `--output json` it prints the API response instead, e.g. `{"id":42,"status":"issued","skipped":true,"reason":"not_due","expiresAt":"...","renewalWindowDays":30}`; a renewal that went ahead has `"skipped": false`. A skipped renewal never polls, even with `--wait`.

`--if-due` needs an API that supports it. An older API ignores the option and renews anyway; the CLI then prints a note saying the API did not report whether the certificate was due.

Pass explicit output paths: with `--wait`, a renewal that goes ahead writes the new certificate files, and the default `./<cn>.crt` paths depend on the working directory, which differs between cron and systemd. A skipped renewal writes nothing.

cron (daily at 03:17, in the crontab of a user who has run `krakenkey auth login`):

```cron
17 3 * * * /usr/local/bin/krakenkey cert renew 42 --if-due --wait --out /etc/ssl/krakenkey/example.crt --fullchain-out /etc/ssl/krakenkey/example.fullchain.crt
```

systemd timer:

```ini
# /etc/systemd/system/krakenkey-renew.service
[Unit]
Description=Renew KrakenKey certificate 42 when due

[Service]
Type=oneshot
EnvironmentFile=/etc/krakenkey/env
ExecStart=/usr/local/bin/krakenkey cert renew 42 --if-due --wait \
  --out /etc/ssl/krakenkey/example.crt \
  --fullchain-out /etc/ssl/krakenkey/example.fullchain.crt
# Optional: reload the server so it picks up a renewed certificate
ExecStartPost=/usr/bin/systemctl reload nginx

# /etc/systemd/system/krakenkey-renew.timer
[Unit]
Description=Daily KrakenKey renewal check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

`/etc/krakenkey/env` holds `KK_API_KEY=kk_...` and should be readable only by root. Enable with `systemctl enable --now krakenkey-renew.timer`.

## CSR generation

The CLI generates CSRs using Go's `crypto` standard library. Supported key types:

| Flag value | Algorithm | Key / curve | Signature |
|---|---|---|---|
| `ecdsa-p256` (default) | ECDSA | P-256 | ECDSA with SHA-256 |
| `ecdsa-p384` | ECDSA | P-384 | ECDSA with SHA-384 |
| `rsa-2048` | RSA | 2048-bit | SHA-256 with RSA |
| `rsa-4096` | RSA | 4096-bit | SHA-256 with RSA |

Private keys are saved locally with `0600` permissions. They are never sent to the API or printed to stdout.

## Troubleshooting

### `ACME challenge delegation missing` / `ACME challenge delegation mismatch`

Before it creates an ACME order, KrakenKey checks the `_acme-challenge` CNAME for every name on the certificate (see [`krakenkey domain`](#krakenkey-domain)). If a record is missing or points somewhere else, the certificate fails before the CA is contacted. `cert issue`, `submit`, `renew` and `retry` with `--wait` exit 1 with the reason, and `cert show <id>` prints it:

```
Error: certificate issuance failed for example.com: ACME challenge delegation missing: no CNAME found at _acme-challenge.example.com. Create a CNAME record from _acme-challenge.example.com to example-com.acme.krakenkey.io, then request the certificate again (if you just created it, allow a few minutes for DNS to update).
```

The mismatch variant names the record's current target and the one expected.

KrakenKey does not retry this failure on its own, because only a DNS change can fix it. To recover:

1. Create or fix the record. `krakenkey domain check <name>...` with the certificate's names shows what each `_acme-challenge` record should be and what is still missing, and `--wait` re-checks until everything is in place.
2. Once `domain check` passes, run `krakenkey cert retry <id> --wait`. The retry reuses the certificate's CSR, so the private key you already have stays valid, and `--wait` saves the certificate, chain and full chain when issuance finishes (pass `--out`, `--chain-out` or `--fullchain-out` to choose where).

A CNAME chain is fine: KrakenKey follows up to five hops from `_acme-challenge.<name>` looking for the expected target. If you have only just created the record, a resolver that looked it up earlier can keep the "no record" answer until your zone's negative-cache TTL runs out, often a few minutes.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General error (API error, validation failure, issuance failed) |
| 2 | Authentication error (no API key, 401) |
| 3 | Not found (404) |
| 4 | Rate limited (429) |
| 5 | Configuration error |

## Building from source

```bash
git clone git@github.com:krakenkey/cli.git
cd cli
go build -o krakenkey ./cmd/krakenkey

# With version injection
go build -ldflags="-X main.version=v0.1.0" -o krakenkey ./cmd/krakenkey
```

## License

[AGPL-3.0](LICENSE)
