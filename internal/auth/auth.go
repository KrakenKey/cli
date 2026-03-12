// Package auth implements the `krakenkey auth` subcommands.
package auth

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/config"
	"github.com/krakenkey/cli/internal/output"
)

// RunLogin sets the API key, validates it against the API, and saves it to the config file.
// If apiKey is empty the user is prompted interactively.
func RunLogin(ctx context.Context, client *api.Client, printer *output.Printer, cfg *config.Config, apiKey string) error {
	if apiKey == "" {
		fmt.Fprint(os.Stderr, "Enter API key: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			apiKey = strings.TrimSpace(scanner.Text())
		}
		if apiKey == "" {
			return &api.ErrConfig{Message: "API key cannot be empty"}
		}
	}

	// Validate the key by fetching the profile.
	profile, err := client.GetProfile(ctx)
	if err != nil {
		return err
	}

	if err := config.Save("", apiKey, ""); err != nil {
		return &api.ErrConfig{Message: fmt.Sprintf("save config: %s", err)}
	}

	printer.Success("Logged in as %s (%s)", profile.DisplayName, profile.Email)
	return nil
}

// RunLogout removes the stored API key from the config file.
func RunLogout(printer *output.Printer) error {
	if err := config.RemoveAPIKey(); err != nil {
		return fmt.Errorf("remove API key: %w", err)
	}
	printer.Success("Logged out — API key removed from config")
	return nil
}

// RunStatus prints the current authentication status and resource usage.
func RunStatus(ctx context.Context, client *api.Client, printer *output.Printer) error {
	profile, err := client.GetProfile(ctx)
	if err != nil {
		return err
	}

	printer.JSON(profile)
	printer.Println("User:         %s", profile.DisplayName)
	printer.Println("Email:        %s", profile.Email)
	printer.Println("Plan:         %s", profile.Plan)
	printer.Println("Domains:      %d", profile.ResourceCounts.Domains)
	printer.Println("Certificates: %d", profile.ResourceCounts.Certificates)
	printer.Println("API keys:     %d", profile.ResourceCounts.APIKeys)
	return nil
}

// RunKeysList lists all API keys for the authenticated user.
func RunKeysList(ctx context.Context, client *api.Client, printer *output.Printer) error {
	keys, err := client.ListAPIKeys(ctx)
	if err != nil {
		return err
	}

	printer.JSON(keys)

	if len(keys) == 0 {
		printer.Info("No API keys found")
		return nil
	}

	headers := []string{"ID", "Name", "Created", "Expires"}
	rows := make([][]string, len(keys))
	for i, k := range keys {
		exp := "never"
		if k.ExpiresAt != nil {
			exp = k.ExpiresAt.Format(time.RFC3339)
		}
		rows[i] = []string{k.ID, k.Name, k.CreatedAt.Format(time.RFC3339), exp}
	}
	printer.Table(headers, rows)
	return nil
}

// RunKeysCreate creates a new API key and prints the key secret (shown once).
func RunKeysCreate(ctx context.Context, client *api.Client, printer *output.Printer, name string, expiresAt *string) error {
	resp, err := client.CreateAPIKey(ctx, name, expiresAt)
	if err != nil {
		return err
	}

	printer.JSON(resp)
	printer.Success("API key created")
	printer.Println("ID:  %s", resp.ID)
	printer.Println("Key: %s", resp.APIKey)
	printer.Info("Store this key securely — it will not be shown again")
	return nil
}

// RunKeysDelete deletes an API key by ID.
func RunKeysDelete(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	if err := client.DeleteAPIKey(ctx, id); err != nil {
		return err
	}
	printer.Success("API key %s deleted", id)
	return nil
}
