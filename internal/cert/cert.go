// Package cert implements the `krakenkey cert` subcommands.
package cert

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// terminalStatuses are the cert statuses that indicate processing has finished.
var terminalStatuses = map[string]bool{
	api.CertStatusIssued:  true,
	api.CertStatusFailed:  true,
	api.CertStatusRevoked: true,
}

// cnFromCert extracts the Common Name from the cert's parsed CSR subject.
func cnFromCert(c *api.TlsCert) string {
	if c.ParsedCsr == nil {
		return strconv.Itoa(c.ID)
	}
	for _, field := range c.ParsedCsr.Subject {
		if field.Name == "commonName" || field.Name == "CN" {
			return field.Value
		}
	}
	return strconv.Itoa(c.ID)
}

// RunList lists certificates, optionally filtered by status.
func RunList(ctx context.Context, client *api.Client, printer *output.Printer, status string) error {
	certs, err := client.ListCerts(ctx, status)
	if err != nil {
		return err
	}

	printer.JSON(certs)

	if len(certs) == 0 {
		printer.Info("No certificates found")
		return nil
	}

	headers := []string{"ID", "Domain", "Status", "Expires", "Auto-renew"}
	rows := make([][]string, len(certs))
	for i, c := range certs {
		exp := "—"
		if c.ExpiresAt != nil {
			exp = c.ExpiresAt.Format("2006-01-02")
		}
		autoRenew := "no"
		if c.AutoRenew {
			autoRenew = "yes"
		}
		rows[i] = []string{
			strconv.Itoa(c.ID),
			cnFromCert(&c),
			c.Status,
			exp,
			autoRenew,
		}
	}
	printer.Table(headers, rows)
	return nil
}

// RunShow prints full details for a certificate, including parsed cert fields if issued.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer, id int) error {
	c, err := client.GetCert(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(c)
	printer.Println("ID:          %d", c.ID)
	printer.Println("Status:      %s", c.Status)
	printer.Println("Domain:      %s", cnFromCert(c))
	printer.Println("Auto-renew:  %v", c.AutoRenew)
	printer.Println("Created:     %s", c.CreatedAt.Format(time.RFC3339))
	if c.ExpiresAt != nil {
		printer.Println("Expires:     %s", c.ExpiresAt.Format(time.RFC3339))
	}
	if c.LastRenewedAt != nil {
		printer.Println("Last renewed:%s", c.LastRenewedAt.Format(time.RFC3339))
	}
	if c.RenewalCount > 0 {
		printer.Println("Renewals:    %d", c.RenewalCount)
	}

	if c.ParsedCsr != nil && c.ParsedCsr.PublicKey != nil {
		printer.Println("Key type:    %s %d", c.ParsedCsr.PublicKey.KeyType, c.ParsedCsr.PublicKey.BitLength)
	}

	if c.Status == api.CertStatusIssued {
		details, err := client.GetCertDetails(ctx, id)
		if err == nil {
			printer.Println("")
			printer.Println("Serial:      %s", details.SerialNumber)
			printer.Println("Issuer:      %s", details.Issuer)
			printer.Println("Valid from:  %s", details.ValidFrom.Format(time.RFC3339))
			printer.Println("Valid to:    %s", details.ValidTo.Format(time.RFC3339))
			printer.Println("Fingerprint: %s", details.Fingerprint)
		}
	}
	return nil
}

// RunDownload saves the certificate PEM to outPath (default: ./<cn>.crt).
func RunDownload(ctx context.Context, client *api.Client, printer *output.Printer, id int, outPath string) error {
	c, err := client.GetCert(ctx, id)
	if err != nil {
		return err
	}

	if c.Status != api.CertStatusIssued {
		return fmt.Errorf("certificate %d is not issued (status: %s)", id, c.Status)
	}
	if c.CrtPem == "" {
		return fmt.Errorf("certificate %d has no PEM data", id)
	}

	if outPath == "" {
		outPath = cnFromCert(c) + ".crt"
	}

	if err := os.WriteFile(outPath, []byte(c.CrtPem), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	printer.JSON(map[string]string{"path": outPath})
	printer.Success("Certificate saved to %s", outPath)
	return nil
}

// RunRenew triggers manual renewal and optionally polls until complete.
func RunRenew(ctx context.Context, client *api.Client, printer *output.Printer, id int, wait bool, pollInterval, pollTimeout time.Duration) error {
	resp, err := client.RenewCert(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(resp)
	printer.Success("Renewal triggered for certificate %d (status: %s)", resp.ID, resp.Status)

	if !wait {
		return nil
	}
	cert, err := PollUntilDone(ctx, client, printer, resp.ID, pollInterval, pollTimeout)
	if err != nil {
		return err
	}
	if cert.Status == api.CertStatusFailed {
		return fmt.Errorf("renewal failed for certificate %d", id)
	}
	printer.Success("Certificate %d renewed", id)
	return nil
}

// RunRevoke revokes a certificate. reason is an RFC 5280 reason code (nil = unspecified).
func RunRevoke(ctx context.Context, client *api.Client, printer *output.Printer, id int, reason *int) error {
	resp, err := client.RevokeCert(ctx, id, reason)
	if err != nil {
		return err
	}
	printer.JSON(resp)
	printer.Success("Certificate %d revocation initiated (status: %s)", resp.ID, resp.Status)
	return nil
}

// RunRetry retries a failed certificate issuance.
func RunRetry(ctx context.Context, client *api.Client, printer *output.Printer, id int, wait bool, pollInterval, pollTimeout time.Duration) error {
	resp, err := client.RetryCert(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(resp)
	printer.Success("Retry triggered for certificate %d (status: %s)", resp.ID, resp.Status)

	if !wait {
		return nil
	}
	cert, err := PollUntilDone(ctx, client, printer, resp.ID, pollInterval, pollTimeout)
	if err != nil {
		return err
	}
	if cert.Status == api.CertStatusFailed {
		return fmt.Errorf("certificate %d issuance failed after retry", id)
	}
	printer.Success("Certificate %d issued", id)
	return nil
}

// RunDelete deletes a failed or revoked certificate.
func RunDelete(ctx context.Context, client *api.Client, printer *output.Printer, id int) error {
	if err := client.DeleteCert(ctx, id); err != nil {
		return err
	}
	printer.Success("Certificate %d deleted", id)
	return nil
}

// RunUpdate updates certificate settings (currently only auto-renewal).
func RunUpdate(ctx context.Context, client *api.Client, printer *output.Printer, id int, autoRenew *bool) error {
	c, err := client.UpdateCert(ctx, id, autoRenew)
	if err != nil {
		return err
	}
	printer.JSON(c)
	printer.Success("Certificate %d updated", id)
	if autoRenew != nil {
		printer.Println("Auto-renew: %v", c.AutoRenew)
	}
	return nil
}

// PollUntilDone polls GET /certs/:id until the cert reaches a terminal state
// (issued, failed, revoked) or pollTimeout is exceeded.
// It displays a spinner with status and elapsed time on stderr.
func PollUntilDone(ctx context.Context, client *api.Client, printer *output.Printer, certID int, pollInterval, pollTimeout time.Duration) (*api.TlsCert, error) {
	start := time.Now()
	spinner := printer.NewSpinner(fmt.Sprintf("Waiting for certificate %d [checking]", certID))
	spinner.Start()
	defer spinner.Stop()

	deadline := time.After(pollTimeout)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, fmt.Errorf("timed out after %s waiting for certificate %d", pollTimeout, certID)
		case <-tick.C:
			c, err := client.GetCert(ctx, certID)
			if err != nil {
				return nil, err
			}
			elapsed := time.Since(start).Round(time.Second)
			spinner.UpdateMsg(fmt.Sprintf("Waiting for certificate %d [%s] %s", certID, c.Status, elapsed))

			if terminalStatuses[c.Status] {
				return c, nil
			}
		}
	}
}
