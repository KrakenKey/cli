package cert

import (
	"context"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// IssueOptions holds parameters for the `cert issue` command.
type IssueOptions struct {
	Domain       string
	SANs         []string
	KeyType      string // "ecdsa-p256" by default
	Org          string
	OU           string
	Locality     string
	State        string
	Country      string
	KeyOut       string // path for private key PEM, default: ./<domain>.key
	CSROut       string // path for CSR PEM, default: ./<domain>.csr
	Out          string // path for certificate PEM, default: ./<domain>.crt
	AutoRenew    bool
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunIssue generates a CSR + private key locally, submits the CSR, and optionally
// polls until the certificate is issued.
func RunIssue(ctx context.Context, client *api.Client, printer *output.Printer, opts IssueOptions) error {
	panic("not implemented")
}
