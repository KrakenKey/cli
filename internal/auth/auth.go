// Package auth implements the `krakenkey auth` subcommands.
package auth

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/config"
	"github.com/krakenkey/cli/internal/output"
)

// RunLogin validates apiKey against the API and saves it to the config file.
// The client must be configured with apiKey already.
func RunLogin(ctx context.Context, client *api.Client, printer *output.Printer, apiKey string) error {
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

	headers := []string{"ID", "Name", "Access", "Created", "Expires", "Last used"}
	rows := make([][]string, len(keys))
	for i, k := range keys {
		exp := "never"
		if k.ExpiresAt != nil {
			exp = k.ExpiresAt.Format(time.RFC3339)
		}
		lastUsed := "never"
		if k.LastUsedAt != nil {
			lastUsed = k.LastUsedAt.Format(time.RFC3339)
		}
		rows[i] = []string{k.ID, k.Name, KeyAccess(k), k.CreatedAt.Format(time.RFC3339), exp, lastUsed}
	}
	printer.Table(headers, rows)
	return nil
}

// keyPresets mirrors API_KEY_PRESETS in the app's @krakenkey/shared package.
var keyPresets = []struct {
	name   string
	scopes []string
}{
	{"read-only", []string{"account:read", "certs:read", "domains:read", "endpoints:read"}},
	{"cert-renewal", []string{"account:read", "certs:read", "certs:renew"}},
	{"probe", []string{"probes:report"}},
}

// KeyAccess summarises what a key may do: "full", a preset name, or
// "custom: <scopes>", followed by any domain, certificate or IP limits.
func KeyAccess(k api.APIKey) string {
	access := "full"
	if k.Scopes != nil {
		sorted := append([]string(nil), k.Scopes...)
		sort.Strings(sorted)
		access = "custom: " + strings.Join(sorted, ",")
		for _, p := range keyPresets {
			if slices.Equal(sorted, p.scopes) {
				access = p.name
				break
			}
		}
	}
	var limits []string
	if n := len(k.AllowedDomainIDs); n > 0 {
		limits = append(limits, plural(n, "domain"))
	}
	if n := len(k.AllowedCertIDs); n > 0 {
		limits = append(limits, plural(n, "cert"))
	}
	if len(k.AllowedIPs) > 0 {
		limits = append(limits, "IPs "+strings.Join(k.AllowedIPs, ","))
	}
	if len(limits) > 0 {
		access += " (" + strings.Join(limits, "; ") + ")"
	}
	return access
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
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
