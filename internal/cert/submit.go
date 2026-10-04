package cert

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// SubmitOptions holds parameters for the `cert submit` command.
type SubmitOptions struct {
	CSRPath      string // path to existing CSR PEM file
	Out          string // path for certificate PEM output
	ChainOut     string // path for chain PEM output
	FullchainOut string // path for fullchain PEM output
	AutoRenew    bool
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunSubmit reads an existing CSR PEM from disk, submits it to the API, and
// optionally polls until the certificate is issued.
func RunSubmit(ctx context.Context, client *api.Client, printer *output.Printer, opts SubmitOptions) error {
	csrPem, err := os.ReadFile(opts.CSRPath)
	if err != nil {
		return fmt.Errorf("read CSR file %s: %w", opts.CSRPath, err)
	}

	resp, err := client.CreateCert(ctx, string(csrPem))
	if err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	}
	printer.Info("Certificate request submitted (ID: %d, status: %s)", resp.ID, resp.Status)

	// Set auto-renew if requested.
	if opts.AutoRenew {
		t := true
		if _, err := client.UpdateCert(ctx, resp.ID, &t); err != nil {
			printer.Error("Failed to enable auto-renew: %s", err)
		}
	}

	if !opts.Wait {
		printer.JSON(resp)
		printer.Success("Certificate %d submitted — run `krakenkey cert show %d` to check status", resp.ID, resp.ID)
		return nil
	}

	cert, err := PollUntilDone(ctx, client, printer, resp.ID, opts.PollInterval, opts.PollTimeout)
	if err != nil {
		return err
	}

	if cert.Status == api.CertStatusFailed {
		return failedError(cert, "certificate issuance failed")
	}

	if err := saveIssuedCert(ctx, client, printer, cert, cnFromCert(cert), certOutputs{
		Out:          opts.Out,
		ChainOut:     opts.ChainOut,
		FullchainOut: opts.FullchainOut,
	}); err != nil {
		return err
	}

	printer.JSON(cert)
	printer.Success("Certificate %d issued", cert.ID)
	return nil
}
