// Package auth implements the `krakenkey auth` subcommands.
package auth

import (
	"context"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/config"
	"github.com/krakenkey/cli/internal/output"
)

// RunLogin sets the API key, validates it against the API, and saves it to the config file.
// If apiKey is empty the user is prompted interactively.
func RunLogin(ctx context.Context, client *api.Client, printer *output.Printer, cfg *config.Config, apiKey string) error {
	panic("not implemented")
}

// RunLogout removes the stored API key from the config file.
func RunLogout(printer *output.Printer) error {
	panic("not implemented")
}

// RunStatus prints the current authentication status and resource usage.
func RunStatus(ctx context.Context, client *api.Client, printer *output.Printer) error {
	panic("not implemented")
}

// RunKeysList lists all API keys for the authenticated user.
func RunKeysList(ctx context.Context, client *api.Client, printer *output.Printer) error {
	panic("not implemented")
}

// RunKeysCreate creates a new API key and prints the key secret (shown once).
func RunKeysCreate(ctx context.Context, client *api.Client, printer *output.Printer, name string, expiresAt *string) error {
	panic("not implemented")
}

// RunKeysDelete deletes an API key by ID.
func RunKeysDelete(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	panic("not implemented")
}
