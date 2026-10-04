// Package domain implements the `krakenkey domain` subcommands.
package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunAdd registers a new domain and prints the DNS records it needs.
func RunAdd(ctx context.Context, client *api.Client, printer *output.Printer, hostname string) error {
	d, err := client.CreateDomain(ctx, hostname)
	if err != nil {
		return err
	}

	recordName, target := ChallengeRecord(d.Hostname, ACMEZone())
	printer.JSON(struct {
		*api.Domain
		DNSRecords []DNSRecord `json:"dnsRecords"`
	}{d, []DNSRecord{
		{Type: "TXT", Name: d.Hostname, Value: d.VerificationCode},
		{Type: "CNAME", Name: recordName, Value: target},
	}})
	printer.Success("Domain registered: %s", d.Hostname)
	printer.Println("")
	printer.Println("Add these DNS records:")
	printer.Println("  TXT    %s", d.Hostname)
	printer.Println("         %s", d.VerificationCode)
	printer.Println("  CNAME  %s", recordName)
	printer.Println("         %s", target)
	printer.Println("")
	printer.Println("The TXT proves ownership and stays in place. Every other name on a")
	printer.Println("certificate, such as a www subdomain, needs its own _acme-challenge CNAME;")
	printer.Println("`krakenkey domain check <name>...` lists them and what's still missing.")
	printer.Println("")
	printer.Info("Run `krakenkey domain verify %s` once the TXT record has propagated", d.ID)
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
