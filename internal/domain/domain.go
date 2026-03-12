// Package domain implements the `krakenkey domain` subcommands.
package domain

import (
	"context"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunAdd registers a new domain and prints DNS TXT verification instructions.
func RunAdd(ctx context.Context, client *api.Client, printer *output.Printer, hostname string) error {
	panic("not implemented")
}

// RunList lists all registered domains.
func RunList(ctx context.Context, client *api.Client, printer *output.Printer) error {
	panic("not implemented")
}

// RunShow prints full details for a domain, including the verification record.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	panic("not implemented")
}

// RunVerify triggers DNS TXT verification for a domain.
func RunVerify(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	panic("not implemented")
}

// RunDelete deletes a domain by ID.
func RunDelete(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	panic("not implemented")
}
