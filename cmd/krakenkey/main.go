package main

import (
	"fmt"
	"os"
)

// version is injected at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		printUsage()
		return 5
	}

	switch os.Args[1] {
	case "version", "--version":
		fmt.Printf("krakenkey-cli %s\n", version)
		return 0
	case "help", "--help", "-h":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q — run 'krakenkey help' for usage\n", os.Args[1])
		return 5
	}
}

func printUsage() {
	fmt.Print(`krakenkey-cli — TLS certificate management from your terminal

Usage:
  krakenkey <command> [subcommand] [flags]

Commands:
  auth        Manage authentication and API keys
  cert        Certificate lifecycle management
  domain      Domain registration and verification
  account     Account and subscription info

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
