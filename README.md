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
# 1. Set your API key (create one at app.krakenkey.io/dashboard → API Keys)
krakenkey auth login

# 2. Register and verify your domain
krakenkey domain add example.com
krakenkey domain verify <id>

# 3. Issue a certificate
krakenkey cert issue --domain example.com
```

## Command reference

### `krakenkey auth`

```
krakenkey auth login [--api-key <key>]        Save API key (prompts interactively if omitted)
krakenkey auth logout                         Remove stored API key
krakenkey auth status                         Show auth status and resource counts
krakenkey auth keys list                      List API keys
krakenkey auth keys create --name <name>      Create a new API key
krakenkey auth keys delete <id>               Delete an API key
```

`auth keys create` flags:

| Flag | Description |
|---|---|
| `--name` | Name for the API key (required) |
| `--expires-at` | Expiry date in ISO 8601 format (optional) |

### `krakenkey domain`

```
krakenkey domain add <hostname>    Register a domain and get the DNS TXT verification record
krakenkey domain list              List all domains
krakenkey domain show <id>         Show domain details and verification record
krakenkey domain verify <id>       Trigger DNS TXT verification
krakenkey domain delete <id>       Delete a domain
```

### `krakenkey cert`

```
krakenkey cert issue --domain <domain>     Generate key + CSR locally, submit, and optionally wait
krakenkey cert submit --csr <file>         Submit an existing CSR PEM file
krakenkey cert list [--status <status>]    List certificates (filter: pending|issuing|issued|failed|renewing|revoking|revoked)
krakenkey cert show <id>                   Show certificate details
krakenkey cert download <id> [--out path]  Download certificate PEM
krakenkey cert renew <id> [--wait]         Trigger manual renewal
krakenkey cert revoke <id> [--reason N]    Revoke a certificate (RFC 5280 reason code 0–10)
krakenkey cert retry <id> [--wait]         Retry failed issuance
krakenkey cert update <id>                 Update certificate settings
krakenkey cert delete <id>                 Delete a certificate (failed or revoked only)
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
| `--out` | `./<domain>.crt` | Certificate output path |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

`cert submit` flags:

| Flag | Default | Description |
|---|---|---|
| `--csr` | | Path to CSR PEM file — required |
| `--out` | `./<cn>.crt` | Certificate output path |
| `--auto-renew` | `false` | Enable automatic renewal |
| `--wait` | `false` | Wait for issuance to complete |
| `--poll-interval` | `15s` | How often to poll for status |
| `--poll-timeout` | `10m` | Maximum time to wait |

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
krakenkey endpoint region add <id> <region>           Add a hosted probe region
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
    args: cert issue --domain example.com --key-out ./example.com.key --out ./example.com.crt
```

**Generic shell**:

```bash
docker run --rm \
  -e KK_API_KEY \
  -e KK_OUTPUT=json \
  -v "$(pwd)/certs:/out" \
  ghcr.io/krakenkey/cli:latest \
  cert issue --domain example.com --key-out /out/example.com.key --out /out/example.com.crt
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
