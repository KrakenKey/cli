// Package cert implements the `krakenkey cert` subcommands.
package cert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	if c.Status == api.CertStatusFailed && c.FailureReason != "" {
		printer.Println("Reason:      %s", c.FailureReason)
	}

	if c.ParsedCsr != nil && c.ParsedCsr.PublicKey != nil {
		printer.Println("Key type:    %s %d", c.ParsedCsr.PublicKey.KeyType, c.ParsedCsr.PublicKey.BitLength)
	}

	if c.Status == api.CertStatusIssued {
		chain, err := client.GetCertChain(ctx, id)
		if err == nil {
			printer.Println("")
			printer.Println("Serial:      %s", chain.LeafCert.SerialNumber)
			printer.Println("Issuer:      %s", chain.LeafCert.Issuer)
			printer.Println("Valid from:  %s", chain.LeafCert.ValidFrom.Format(time.RFC3339))
			printer.Println("Valid to:    %s", chain.LeafCert.ValidTo.Format(time.RFC3339))
			printer.Println("Fingerprint: %s", chain.LeafCert.Fingerprint)

			if len(chain.Intermediates) > 0 {
				printer.Println("")
				printer.Println("Chain (%d intermediate%s):", len(chain.Intermediates), pluralS(len(chain.Intermediates)))
				for i, ic := range chain.Intermediates {
					printer.Println("  [%d] Subject:     %s", i+1, ic.Subject)
					printer.Println("      Issuer:      %s", ic.Issuer)
					printer.Println("      Fingerprint: %s", ic.Fingerprint)
				}
			}
		} else {
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
	}
	return nil
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// DownloadFormat controls which PEM content is written by RunDownload.
const (
	FormatCert      = "cert"
	FormatChain     = "chain"
	FormatFullchain = "fullchain"
)

// RunDownload saves the certificate PEM to outPath (default: ./<cn>.crt).
// format controls what is written: "cert" (leaf only), "chain" (intermediates only),
// or "fullchain" (leaf + intermediates).
func RunDownload(ctx context.Context, client *api.Client, printer *output.Printer, id int, outPath, format string) error {
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

	if format == "" {
		format = FormatCert
	}

	var pemData string
	switch format {
	case FormatCert:
		pemData = c.CrtPem
	case FormatChain:
		if c.ChainPem == "" {
			return fmt.Errorf("certificate %d has no intermediate chain data", id)
		}
		pemData = c.ChainPem
	case FormatFullchain:
		chain, err := client.GetCertChain(ctx, id)
		if err != nil {
			return fmt.Errorf("fetch chain: %w", err)
		}
		pemData = chain.FullChainPem
	default:
		return fmt.Errorf("invalid format %q: must be cert, chain, or fullchain", format)
	}

	if outPath == "" {
		var suffix string
		switch format {
		case FormatChain:
			suffix = ".chain.crt"
		case FormatFullchain:
			suffix = ".fullchain.crt"
		default:
			suffix = ".crt"
		}
		outPath = cnFromCert(c) + suffix
	}

	if err := os.WriteFile(outPath, []byte(pemData), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	printer.JSON(map[string]string{"path": outPath, "format": format})
	printer.Success("Certificate (%s) saved to %s", format, outPath)
	return nil
}

// RenewOptions holds parameters for the `cert renew` command.
type RenewOptions struct {
	Out          string // path for certificate PEM, default: ./<cn>.crt
	ChainOut     string // path for chain PEM, default: ./<cn>.chain.crt
	FullchainOut string // path for fullchain PEM, default: ./<cn>.fullchain.crt
	// IfDue asks the API to renew only when the certificate is inside the
	// plan's renewal window. Requires an API that supports ?ifDue=true;
	// older APIs ignore it and renew anyway.
	IfDue        bool
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunRenew triggers manual renewal. With opts.Wait it polls until the renewal
// finishes and saves the renewed certificate, chain and full chain the same
// way `cert issue --wait` does. With opts.IfDue a certificate outside the
// renewal window is left alone and nothing is polled or saved.
func RunRenew(ctx context.Context, client *api.Client, printer *output.Printer, id int, opts RenewOptions) error {
	resp, err := client.RenewCert(ctx, id, opts.IfDue)
	if err != nil {
		return err
	}

	if resp.WasSkipped() {
		printer.Info("%s", notDueMessage(resp))
		printer.JSON(resp)
		return nil
	}
	if opts.IfDue && resp.Skipped == nil {
		printer.Info("The API did not say whether certificate %d was due (it may not support --if-due yet), so a renewal was started", resp.ID)
	}

	printer.Success("Renewal triggered for certificate %d (status: %s)", resp.ID, resp.Status)

	if !opts.Wait {
		printer.JSON(resp)
		return nil
	}
	cert, err := PollUntilDone(ctx, client, printer, resp.ID, opts.PollInterval, opts.PollTimeout)
	if err != nil {
		return err
	}
	if cert.Status == api.CertStatusFailed {
		return failedError(cert, "renewal failed for certificate %d", id)
	}

	if err := saveIssuedCert(ctx, client, printer, cert, cnFromCert(cert), certOutputs{
		Out:          opts.Out,
		ChainOut:     opts.ChainOut,
		FullchainOut: opts.FullchainOut,
	}); err != nil {
		return err
	}

	printer.JSON(cert)
	printer.Success("Certificate %d renewed", cert.ID)
	return nil
}

// notDueMessage describes a renewal the API skipped because the certificate
// is outside the renewal window.
func notDueMessage(r *api.RenewResponse) string {
	var details []string
	if r.ExpiresAt != nil {
		details = append(details, "expires "+r.ExpiresAt.Format("2006-01-02"))
	}
	if r.RenewalWindowDays > 0 {
		details = append(details, fmt.Sprintf("renewal window %d day%s", r.RenewalWindowDays, pluralS(r.RenewalWindowDays)))
	}
	msg := fmt.Sprintf("Certificate %d is not due for renewal", r.ID)
	if len(details) > 0 {
		msg += " (" + strings.Join(details, ", ") + ")"
	}
	return msg
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
		return failedError(cert, "certificate %d issuance failed after retry", id)
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

// failedError builds the error for a certificate that ended in "failed",
// appending the API's failure reason when it returns one.
func failedError(c *api.TlsCert, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if c.FailureReason != "" {
		msg += ": " + c.FailureReason
	}
	return errors.New(msg)
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
