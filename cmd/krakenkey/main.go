package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/account"
	"github.com/krakenkey/cli/internal/auth"
	"github.com/krakenkey/cli/internal/cert"
	"github.com/krakenkey/cli/internal/config"
	"github.com/krakenkey/cli/internal/domain"
	"github.com/krakenkey/cli/internal/output"
)

// version is injected at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]

	// Handle bare version/help before flag parsing.
	if len(args) == 0 {
		printUsage()
		return 0
	}
	if args[0] == "version" {
		fmt.Printf("krakenkey-cli %s\n", version)
		return 0
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage()
		return 0
	}

	// Global flags.
	globalFS := flag.NewFlagSet("krakenkey", flag.ContinueOnError)
	globalFS.SetOutput(os.Stderr)
	var (
		apiURL    string
		apiKey    string
		outputFmt string
		noColor   bool
		verbose   bool
	)
	globalFS.StringVar(&apiURL, "api-url", "", "API base URL (env: KK_API_URL)")
	globalFS.StringVar(&apiKey, "api-key", "", "API key (env: KK_API_KEY)")
	globalFS.StringVar(&outputFmt, "output", "", "Output format: text or json (env: KK_OUTPUT)")
	globalFS.BoolVar(&noColor, "no-color", false, "Disable colored output")
	globalFS.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	globalFS.Bool("version", false, "Print version and exit")

	if err := globalFS.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	// --version flag.
	if v, _ := globalFS.Lookup("version").Value.(interface{ IsBoolFlag() bool }); v != nil {
		if globalFS.Lookup("version").Value.String() == "true" {
			fmt.Printf("krakenkey-cli %s\n", version)
			return 0
		}
	}

	remaining := globalFS.Args()
	if len(remaining) == 0 {
		printUsage()
		return 0
	}

	// Load configuration.
	cfg, err := config.Load(config.Flags{
		APIURL:  apiURL,
		APIKey:  apiKey,
		Output:  outputFmt,
		NoColor: noColor,
		Verbose: verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load config: %s\n", err)
		return 5
	}

	printer := output.New(cfg.Output, noColor)
	client := api.NewClient(cfg.APIURL, cfg.APIKey, version, runtime.GOOS, runtime.GOARCH)
	ctx := context.Background()

	cmd := remaining[0]
	subArgs := remaining[1:]

	var cmdErr error
	switch cmd {
	case "auth":
		cmdErr = runAuth(ctx, client, printer, cfg, subArgs)
	case "domain":
		cmdErr = runDomain(ctx, client, printer, subArgs)
	case "account":
		cmdErr = runAccount(ctx, client, printer, subArgs)
	case "cert":
		cmdErr = runCert(ctx, client, printer, cfg, subArgs)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q — run 'krakenkey help'\n", cmd)
		return 1
	}

	return exitCode(printer, cmdErr)
}

// exitCode prints the error and returns the appropriate exit code.
func exitCode(printer *output.Printer, err error) int {
	if err == nil {
		return 0
	}
	printer.Error("%s", err)
	switch err.(type) {
	case *api.ErrAuth:
		return 2
	case *api.ErrNotFound:
		return 3
	case *api.ErrRateLimit:
		return 4
	case *api.ErrConfig:
		return 5
	default:
		return 1
	}
}

// requireAPIKey ensures cfg.APIKey is set, returning an ErrConfig if not.
func requireAPIKey(cfg *config.Config) error {
	if cfg.APIKey == "" {
		return &api.ErrConfig{Message: "not logged in — run 'krakenkey auth login' or set KK_API_KEY"}
	}
	return nil
}

// mustInt parses s as an int, printing usage and exiting on failure.
func mustInt(fs *flag.FlagSet, s, name string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s must be an integer, got %q\n", name, s)
		fs.Usage()
		return 0, false
	}
	return n, true
}

// stringsFlag accumulates repeated flag values (e.g. --san a --san b).
type stringsFlag []string

func (f *stringsFlag) String() string  { return strings.Join(*f, ",") }
func (f *stringsFlag) Set(v string) error { *f = append(*f, v); return nil }

// triBoolFlag is a *bool flag that is nil when not specified.
type triBoolFlag struct{ val *bool }

func (f *triBoolFlag) String() string {
	if f.val == nil {
		return ""
	}
	return strconv.FormatBool(*f.val)
}
func (f *triBoolFlag) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	f.val = &b
	return nil
}
func (f *triBoolFlag) IsBoolFlag() bool { return true }

// ── auth ─────────────────────────────────────────────────────────────────────

func runAuth(ctx context.Context, client *api.Client, printer *output.Printer, cfg *config.Config, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(authUsage)
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "login":
		fs := flag.NewFlagSet("auth login", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var key string
		fs.StringVar(&key, "api-key", "", "API key to save")
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey auth login [--api-key <key>]\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if key == "" {
			fmt.Fprint(os.Stderr, "Enter API key: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				key = strings.TrimSpace(scanner.Text())
			}
		}
		if key == "" {
			return &api.ErrConfig{Message: "API key cannot be empty"}
		}
		// Create a client with the key under test.
		tempClient := api.NewClient(cfg.APIURL, key, version, runtime.GOOS, runtime.GOARCH)
		return auth.RunLogin(ctx, tempClient, printer, key)

	case "logout":
		return auth.RunLogout(printer)

	case "status":
		if err := requireAPIKey(cfg); err != nil {
			return err
		}
		return auth.RunStatus(ctx, client, printer)

	case "keys":
		return runAuthKeys(ctx, client, printer, subArgs)

	default:
		return fmt.Errorf("unknown auth subcommand %q — run 'krakenkey auth --help'", sub)
	}
}

func runAuthKeys(ctx context.Context, client *api.Client, printer *output.Printer, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print("Usage: krakenkey auth keys <list|create|delete> [flags]\n")
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		return auth.RunKeysList(ctx, client, printer)

	case "create":
		fs := flag.NewFlagSet("auth keys create", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var name, expiresAt string
		fs.StringVar(&name, "name", "", "Name for the API key (required)")
		fs.StringVar(&expiresAt, "expires-at", "", "Expiry date in ISO 8601 format (optional)")
		fs.Usage = func() {
			fmt.Fprint(os.Stderr, "Usage: krakenkey auth keys create --name <name> [--expires-at <date>]\n")
		}
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if name == "" {
			return &api.ErrConfig{Message: "--name is required"}
		}
		var exp *string
		if expiresAt != "" {
			exp = &expiresAt
		}
		return auth.RunKeysCreate(ctx, client, printer, name, exp)

	case "delete":
		fs := flag.NewFlagSet("auth keys delete", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey auth keys delete <id>\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "API key ID is required"}
		}
		return auth.RunKeysDelete(ctx, client, printer, fs.Arg(0))

	default:
		return fmt.Errorf("unknown keys subcommand %q", sub)
	}
}

// ── domain ───────────────────────────────────────────────────────────────────

func runDomain(ctx context.Context, client *api.Client, printer *output.Printer, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(domainUsage)
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "add":
		fs := flag.NewFlagSet("domain add", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey domain add <hostname>\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "hostname is required"}
		}
		return domain.RunAdd(ctx, client, printer, fs.Arg(0))

	case "list":
		return domain.RunList(ctx, client, printer)

	case "show":
		fs := flag.NewFlagSet("domain show", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey domain show <id>\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "domain ID is required"}
		}
		return domain.RunShow(ctx, client, printer, fs.Arg(0))

	case "verify":
		fs := flag.NewFlagSet("domain verify", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey domain verify <id>\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "domain ID is required"}
		}
		return domain.RunVerify(ctx, client, printer, fs.Arg(0))

	case "delete":
		fs := flag.NewFlagSet("domain delete", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		fs.Usage = func() { fmt.Fprint(os.Stderr, "Usage: krakenkey domain delete <id>\n") }
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "domain ID is required"}
		}
		return domain.RunDelete(ctx, client, printer, fs.Arg(0))

	default:
		return fmt.Errorf("unknown domain subcommand %q — run 'krakenkey domain --help'", sub)
	}
}

// ── account ──────────────────────────────────────────────────────────────────

func runAccount(ctx context.Context, client *api.Client, printer *output.Printer, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(accountUsage)
		return nil
	}

	sub := args[0]

	switch sub {
	case "show":
		return account.RunShow(ctx, client, printer)
	case "plan":
		return account.RunPlan(ctx, client, printer)
	default:
		return fmt.Errorf("unknown account subcommand %q — run 'krakenkey account --help'", sub)
	}
}

// ── cert ─────────────────────────────────────────────────────────────────────

func runCert(ctx context.Context, client *api.Client, printer *output.Printer, cfg *config.Config, args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(certUsage)
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		fs := flag.NewFlagSet("cert list", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var status string
		fs.StringVar(&status, "status", "", "Filter by status (pending|issuing|issued|failed|renewing|revoking|revoked)")
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		return cert.RunList(ctx, client, printer, status)

	case "show":
		fs := flag.NewFlagSet("cert show", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunShow(ctx, client, printer, id)

	case "download":
		fs := flag.NewFlagSet("cert download", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var outPath string
		fs.StringVar(&outPath, "out", "", "Output file path (default: ./<cn>.crt)")
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunDownload(ctx, client, printer, id, outPath)

	case "issue":
		fs := flag.NewFlagSet("cert issue", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var (
			domainFlag   string
			sans         stringsFlag
			keyType      string
			org, ou      string
			locality     string
			state        string
			country      string
			keyOut       string
			csrOut       string
			out          string
			autoRenew    bool
			wait         bool
			pollInterval = 15 * time.Second
			pollTimeout  = 10 * time.Minute
		)
		fs.StringVar(&domainFlag, "domain", "", "Primary domain (CN) for the certificate (required)")
		fs.Var(&sans, "san", "Additional SAN (repeat for multiple)")
		fs.StringVar(&keyType, "key-type", "ecdsa-p256", "Key type: rsa-2048, rsa-4096, ecdsa-p256, ecdsa-p384")
		fs.StringVar(&org, "org", "", "Organization (O)")
		fs.StringVar(&ou, "ou", "", "Organizational unit (OU)")
		fs.StringVar(&locality, "locality", "", "Locality (L)")
		fs.StringVar(&state, "state", "", "State or province (ST)")
		fs.StringVar(&country, "country", "", "Country code (C, e.g. US)")
		fs.StringVar(&keyOut, "key-out", "", "Private key output path (default: ./<domain>.key)")
		fs.StringVar(&csrOut, "csr-out", "", "CSR output path (default: ./<domain>.csr)")
		fs.StringVar(&out, "out", "", "Certificate output path (default: ./<domain>.crt)")
		fs.BoolVar(&autoRenew, "auto-renew", false, "Enable automatic renewal")
		fs.BoolVar(&wait, "wait", false, "Wait for issuance to complete")
		fs.DurationVar(&pollInterval, "poll-interval", pollInterval, "How often to poll for status")
		fs.DurationVar(&pollTimeout, "poll-timeout", pollTimeout, "Maximum time to wait")
		fs.Usage = func() {
			fmt.Fprint(os.Stderr, "Usage: krakenkey cert issue --domain <domain> [flags]\n")
			fs.PrintDefaults()
		}
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if domainFlag == "" {
			return &api.ErrConfig{Message: "--domain is required"}
		}
		return cert.RunIssue(ctx, client, printer, cert.IssueOptions{
			Domain:       domainFlag,
			SANs:         []string(sans),
			KeyType:      keyType,
			Org:          org,
			OU:           ou,
			Locality:     locality,
			State:        state,
			Country:      country,
			KeyOut:       keyOut,
			CSROut:       csrOut,
			Out:          out,
			AutoRenew:    autoRenew,
			Wait:         wait,
			PollInterval: pollInterval,
			PollTimeout:  pollTimeout,
		})

	case "submit":
		fs := flag.NewFlagSet("cert submit", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var (
			csrPath      string
			out          string
			autoRenew    bool
			wait         bool
			pollInterval = 15 * time.Second
			pollTimeout  = 10 * time.Minute
		)
		fs.StringVar(&csrPath, "csr", "", "Path to CSR PEM file (required)")
		fs.StringVar(&out, "out", "", "Certificate output path (default: ./<cn>.crt)")
		fs.BoolVar(&autoRenew, "auto-renew", false, "Enable automatic renewal")
		fs.BoolVar(&wait, "wait", false, "Wait for issuance to complete")
		fs.DurationVar(&pollInterval, "poll-interval", pollInterval, "How often to poll for status")
		fs.DurationVar(&pollTimeout, "poll-timeout", pollTimeout, "Maximum time to wait")
		fs.Usage = func() {
			fmt.Fprint(os.Stderr, "Usage: krakenkey cert submit --csr <path> [flags]\n")
			fs.PrintDefaults()
		}
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if csrPath == "" {
			return &api.ErrConfig{Message: "--csr is required"}
		}
		return cert.RunSubmit(ctx, client, printer, cert.SubmitOptions{
			CSRPath:      csrPath,
			Out:          out,
			AutoRenew:    autoRenew,
			Wait:         wait,
			PollInterval: pollInterval,
			PollTimeout:  pollTimeout,
		})

	case "renew":
		fs := flag.NewFlagSet("cert renew", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var (
			wait         bool
			pollInterval = 15 * time.Second
			pollTimeout  = 10 * time.Minute
		)
		fs.BoolVar(&wait, "wait", false, "Wait for renewal to complete")
		fs.DurationVar(&pollInterval, "poll-interval", pollInterval, "How often to poll for status")
		fs.DurationVar(&pollTimeout, "poll-timeout", pollTimeout, "Maximum time to wait")
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunRenew(ctx, client, printer, id, wait, pollInterval, pollTimeout)

	case "revoke":
		fs := flag.NewFlagSet("cert revoke", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var reasonFlag int
		fs.IntVar(&reasonFlag, "reason", -1, "RFC 5280 revocation reason code (optional, 0–10)")
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		var reason *int
		if reasonFlag >= 0 {
			r := reasonFlag
			reason = &r
		}
		return cert.RunRevoke(ctx, client, printer, id, reason)

	case "retry":
		fs := flag.NewFlagSet("cert retry", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var (
			wait         bool
			pollInterval = 15 * time.Second
			pollTimeout  = 10 * time.Minute
		)
		fs.BoolVar(&wait, "wait", false, "Wait for issuance to complete")
		fs.DurationVar(&pollInterval, "poll-interval", pollInterval, "How often to poll for status")
		fs.DurationVar(&pollTimeout, "poll-timeout", pollTimeout, "Maximum time to wait")
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunRetry(ctx, client, printer, id, wait, pollInterval, pollTimeout)

	case "delete":
		fs := flag.NewFlagSet("cert delete", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunDelete(ctx, client, printer, id)

	case "update":
		fs := flag.NewFlagSet("cert update", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		var autoRenewFlag triBoolFlag
		fs.Var(&autoRenewFlag, "auto-renew", "Enable or disable auto-renewal (true/false)")
		fs.Usage = func() {
			fmt.Fprint(os.Stderr, "Usage: krakenkey cert update <id> [--auto-renew=true|false]\n")
		}
		if err := fs.Parse(subArgs); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			return &api.ErrConfig{Message: "certificate ID is required"}
		}
		id, ok := mustInt(fs, fs.Arg(0), "certificate ID")
		if !ok {
			return &api.ErrConfig{Message: "certificate ID must be an integer"}
		}
		return cert.RunUpdate(ctx, client, printer, id, autoRenewFlag.val)

	default:
		return fmt.Errorf("unknown cert subcommand %q — run 'krakenkey cert --help'", sub)
	}
}

// ── usage strings ─────────────────────────────────────────────────────────────

func printUsage() {
	fmt.Print(`krakenkey-cli — TLS certificate management from your terminal

Usage:
  krakenkey [global flags] <command> [subcommand] [flags]

Commands:
  auth        Manage authentication and API keys
  cert        Certificate lifecycle management
  domain      Domain registration and verification
  account     Account and subscription info
  version     Print version and exit

Global Flags:
  --api-url string    API base URL (env: KK_API_URL, default: https://api.krakenkey.io)
  --api-key string    API key (env: KK_API_KEY)
  --output string     Output format: text, json (env: KK_OUTPUT, default: text)
  --no-color          Disable colored output
  --verbose           Enable verbose logging
  --version           Print version and exit

Run 'krakenkey <command> --help' for command-specific help.
`)
}

const authUsage = `Manage authentication and API keys.

Usage:
  krakenkey auth <subcommand> [flags]

Subcommands:
  login             Save an API key to the config file
  logout            Remove the stored API key
  status            Show current user and resource counts
  keys list         List API keys
  keys create       Create a new API key
  keys delete       Delete an API key

Examples:
  krakenkey auth login --api-key kk_...
  krakenkey auth status
  krakenkey auth keys create --name ci-deploy
  krakenkey auth keys delete <id>
`

const domainUsage = `Register and verify domains.

Usage:
  krakenkey domain <subcommand> [flags]

Subcommands:
  add <hostname>    Register a domain and get the DNS TXT record
  list              List all registered domains
  show <id>         Show domain details
  verify <id>       Trigger DNS TXT verification
  delete <id>       Delete a domain

Examples:
  krakenkey domain add example.com
  krakenkey domain list
  krakenkey domain verify <id>
`

const accountUsage = `View account and subscription info.

Usage:
  krakenkey account <subcommand>

Subcommands:
  show    Show profile details
  plan    Show subscription and billing info
`

const certUsage = `Certificate lifecycle management.

Usage:
  krakenkey cert <subcommand> [flags]

Subcommands:
  issue     Generate a key + CSR locally, submit, and optionally wait
  submit    Submit an existing CSR file
  list      List certificates
  show      Show certificate details
  download  Download the certificate PEM
  renew     Trigger manual renewal
  revoke    Revoke a certificate
  retry     Retry a failed issuance
  update    Update certificate settings
  delete    Delete a certificate

Examples:
  krakenkey cert issue --domain example.com --wait
  krakenkey cert submit --csr ./example.csr --wait
  krakenkey cert list --status issued
  krakenkey cert download 42 --out ./example.crt
  krakenkey cert update 42 --auto-renew=true
`
