// Package account implements the `krakenkey account` subcommands.
package account

import (
	"context"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunShow prints the authenticated user's profile.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer) error {
	profile, err := client.GetProfile(ctx)
	if err != nil {
		return err
	}

	printer.JSON(profile)
	printer.Println("ID:           %s", profile.ID)
	printer.Println("Username:     %s", profile.Username)
	printer.Println("Email:        %s", profile.Email)
	printer.Println("Display name: %s", profile.DisplayName)
	printer.Println("Plan:         %s", profile.Plan)
	printer.Println("Domains:      %d", profile.ResourceCounts.Domains)
	printer.Println("Certificates: %d", profile.ResourceCounts.Certificates)
	printer.Println("API keys:     %d", profile.ResourceCounts.APIKeys)
	printer.Println("Member since: %s", profile.CreatedAt.Format(time.RFC3339))
	return nil
}

// RunPlan prints subscription details including plan limits vs. current usage.
func RunPlan(ctx context.Context, client *api.Client, printer *output.Printer) error {
	sub, err := client.GetSubscription(ctx)
	if err != nil {
		return err
	}

	printer.JSON(sub)
	printer.Println("Plan:                %s", sub.Plan)
	printer.Println("Status:              %s", sub.Status)
	if sub.CurrentPeriodEnd != nil {
		printer.Println("Current period ends: %s", sub.CurrentPeriodEnd.Format(time.RFC3339))
	}
	if sub.CancelAtPeriodEnd {
		printer.Info("Subscription is set to cancel at end of current period")
	}
	if !sub.CreatedAt.IsZero() {
		printer.Println("Subscribed:          %s", sub.CreatedAt.Format(time.RFC3339))
	}
	return nil
}
