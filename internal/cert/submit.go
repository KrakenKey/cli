package cert

import (
	"context"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// SubmitOptions holds parameters for the `cert submit` command.
type SubmitOptions struct {
	CSRPath      string // path to existing CSR PEM file
	Out          string // path for certificate PEM output
	AutoRenew    bool
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunSubmit reads an existing CSR PEM from disk, submits it to the API, and
// optionally polls until the certificate is issued.
func RunSubmit(ctx context.Context, client *api.Client, printer *output.Printer, opts SubmitOptions) error {
	panic("not implemented")
}
