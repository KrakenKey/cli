// Package cert implements the `krakenkey cert` subcommands.
package cert

import (
	"context"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunList lists certificates, optionally filtered by status.
func RunList(ctx context.Context, client *api.Client, printer *output.Printer, status string) error {
	panic("not implemented")
}

// RunShow prints full details for a certificate, including parsed cert fields if issued.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer, id int) error {
	panic("not implemented")
}

// RunDownload saves the certificate PEM to outPath (default: ./<cn>.crt).
func RunDownload(ctx context.Context, client *api.Client, printer *output.Printer, id int, outPath string) error {
	panic("not implemented")
}

// RunRenew triggers manual renewal and optionally polls until complete.
func RunRenew(ctx context.Context, client *api.Client, printer *output.Printer, id int, wait bool, pollInterval, pollTimeout time.Duration) error {
	panic("not implemented")
}

// RunRevoke revokes a certificate. reason is an RFC 5280 reason code (nil = unspecified).
func RunRevoke(ctx context.Context, client *api.Client, printer *output.Printer, id int, reason *int) error {
	panic("not implemented")
}

// RunRetry retries a failed certificate issuance.
func RunRetry(ctx context.Context, client *api.Client, printer *output.Printer, id int, wait bool, pollInterval, pollTimeout time.Duration) error {
	panic("not implemented")
}

// RunDelete deletes a failed or revoked certificate.
func RunDelete(ctx context.Context, client *api.Client, printer *output.Printer, id int) error {
	panic("not implemented")
}

// RunUpdate updates certificate settings (currently only auto-renewal).
func RunUpdate(ctx context.Context, client *api.Client, printer *output.Printer, id int, autoRenew *bool) error {
	panic("not implemented")
}

// PollUntilDone polls GET /certs/tls/:id until the cert reaches a terminal state
// (issued, failed, revoked) or pollTimeout is exceeded.
// It displays a spinner with status and elapsed time.
func PollUntilDone(ctx context.Context, client *api.Client, printer *output.Printer, certID int, pollInterval, pollTimeout time.Duration) (*api.TlsCert, error) {
	panic("not implemented")
}
