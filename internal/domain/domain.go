// Package domain implements the `krakenkey domain` subcommands.
package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunAdd registers a new domain and prints DNS TXT verification instructions.
func RunAdd(ctx context.Context, client *api.Client, printer *output.Printer, hostname string) error {
	d, err := client.CreateDomain(ctx, hostname)
	if err != nil {
		return err
	}

	printer.JSON(d)
	printer.Success("Domain registered: %s", d.Hostname)
	printer.Println("")
	printer.Println("Add a DNS TXT record to verify ownership:")
	printer.Println("  Name:  %s", d.Hostname)
	printer.Println("  Value: %s", d.VerificationCode)
	printer.Println("")
	printer.Info("Run `krakenkey domain verify %s` once the record has propagated", d.ID)
	return nil
}

// RunList lists all registered domains.
func RunList(ctx context.Context, client *api.Client, printer *output.Printer) error {
	domains, err := client.ListDomains(ctx)
	if err != nil {
		return err
	}

	printer.JSON(domains)

	if len(domains) == 0 {
		printer.Info("No domains registered")
		return nil
	}

	headers := []string{"ID", "Hostname", "Verified", "Created"}
	rows := make([][]string, len(domains))
	for i, d := range domains {
		verified := "no"
		if d.IsVerified {
			verified = "yes"
		}
		rows[i] = []string{d.ID, d.Hostname, verified, d.CreatedAt.Format(time.RFC3339)}
	}
	printer.Table(headers, rows)
	return nil
}

// RunShow prints full details for a domain, including the verification record.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	d, err := client.GetDomain(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(d)
	printer.Println("ID:                %s", d.ID)
	printer.Println("Hostname:          %s", d.Hostname)
	printer.Println("Verified:          %v", d.IsVerified)
	printer.Println("Verification code: %s", d.VerificationCode)
	printer.Println("TXT record name:   %s", d.Hostname)
	printer.Println("Created:           %s", d.CreatedAt.Format(time.RFC3339))
	return nil
}

// RunVerify triggers DNS TXT verification for a domain.
func RunVerify(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	d, err := client.VerifyDomain(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(d)
	if d.IsVerified {
		printer.Success("Domain %s verified", d.Hostname)
	} else {
		return fmt.Errorf("verification failed for %s — DNS TXT record not found or not yet propagated", d.Hostname)
	}
	return nil
}

// RunDelete deletes a domain by ID.
func RunDelete(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	if err := client.DeleteDomain(ctx, id); err != nil {
		return err
	}
	printer.Success("Domain %s deleted", id)
	return nil
}
