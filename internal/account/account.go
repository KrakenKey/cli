// Package account implements the `krakenkey account` subcommands.
package account

import (
	"context"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunShow prints the authenticated user's profile.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer) error {
	panic("not implemented")
}

// RunPlan prints subscription details including plan limits vs. current usage.
func RunPlan(ctx context.Context, client *api.Client, printer *output.Printer) error {
	panic("not implemented")
}
