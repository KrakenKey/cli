# krakenkey-cli

[![CI](https://github.com/KrakenKey/cli/actions/workflows/ci.yaml/badge.svg)](https://github.com/KrakenKey/cli/actions/workflows/ci.yaml)
[![Latest Release](https://img.shields.io/github/v/release/KrakenKey/cli)](https://github.com/KrakenKey/cli/releases/latest)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Command-line interface for [KrakenKey](https://krakenkey.io) — TLS certificate lifecycle management from your terminal.

The CLI generates CSRs locally using Go's crypto stdlib (private keys never leave your machine), submits them to the KrakenKey API, polls for issuance, and downloads issued certificates. It covers the same API surface as the web dashboard, designed for terminal workflows and CI/CD pipelines.

## Installation

**Binary download** (Linux, macOS, Windows):

Download the latest release from [github.com/KrakenKey/cli/releases](https://github.com/KrakenKey/cli/releases).

```bash
# Linux amd64 example
curl -Lo krakenkey.tar.gz https://github.com/KrakenKey/cli/releases/latest/download/krakenkey_linux_amd64.tar.gz
tar -xzf krakenkey.tar.gz
sudo mv krakenkey /usr/local/bin/
```

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
krakenkey cert renew <id> [--wait]                  Trigger manual renewal (--wait saves the renewed cert)
krakenkey cert revoke <id> [--reason N]             Revoke a certificate (RFC 5280 reason code 0–10)
krakenkey cert retry <id> [--wait]                  Retry failed issuance
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
| `--chain-out` | `./<domain>.chain.pem` | Intermediate CA chain output path |
| `--fullchain-out` | `./<domain>.fullchain.pem` | Full chain output path (leaf + intermediates) |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

`cert submit` flags:

| Flag | Default | Description |
|---|---|---|
| `--csr` | | Path to CSR PEM file — required |
| `--out` | `./<cn>.crt` | Leaf certificate output path |
| `--chain-out` | `./<cn>.chain.pem` | Intermediate CA chain output path |
| `--fullchain-out` | `./<cn>.fullchain.pem` | Full chain output path (leaf + intermediates) |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

`cert renew` flags:

| Flag | Default | Description |
|---|---|---|
| `--out` | `./<cn>.crt` | Leaf certificate output path |
| `--chain-out` | `./<cn>.chain.crt` | Intermediate CA chain output path |
| `--fullchain-out` | `./<cn>.fullchain.crt` | Full chain output path (leaf + intermediates) |
| `--wait` | `false` | Wait for renewal to complete, then save the renewed certificate |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

Renewal reuses the certificate's original CSR, so the existing private key stays valid. With `--wait`, the renewed certificate, chain and full chain are written to the output paths once the renewal finishes, replacing any files already there. Without `--wait`, nothing is written; use `cert download` once the status is back to `issued`.

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

`cert issue`, `cert submit` and `cert renew --wait` produce three certificate files (`cert issue` also writes the private key and CSR):

| File | Flag | Default | Contents |
|------|------|---------|----------|
| Leaf certificate | `--out` | `./<domain>.crt` | End-entity certificate only |
| Intermediate chain | `--chain-out` | `./<domain>.chain.pem` | Intermediate CA certificates |
| Full chain | `--fullchain-out` | `./<domain>.fullchain.pem` | Leaf + intermediates |

Most web servers (nginx, Caddy, HAProxy) expect the full chain. Use `--fullchain-out` in production deployments.

If you pass `--fullchain-out` or `--chain-out` and that file cannot be written (for example the chain fetch fails), `--wait` exits with status 1 after saving the leaf certificate, and the error shows the `cert download` command to fetch the chain later. Without those flags a missing chain file is only a warning.

`cert download` accepts `--format` with values `cert` (default), `chain`, and `fullchain` to download a specific format for an already-issued certificate:

```bash
# Download full chain for deployment
krakenkey cert download 42 --format fullchain --out ./fullchain.pem

# Download intermediates only
krakenkey cert download 42 --format chain --out ./chain.pem
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

## CSR generation

The CLI generates CSRs using Go's `crypto` standard library. Supported key types:

| Flag value | Algorithm | Key / curve | Signature |
|---|---|---|---|
| `ecdsa-p256` (default) | ECDSA | P-256 | ECDSA with SHA-256 |
| `ecdsa-p384` | ECDSA | P-384 | ECDSA with SHA-384 |
| `rsa-2048` | RSA | 2048-bit | SHA-256 with RSA |
| `rsa-4096` | RSA | 4096-bit | SHA-256 with RSA |

Private keys are saved locally with `0600` permissions. They are never sent to the API or printed to stdout.

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
