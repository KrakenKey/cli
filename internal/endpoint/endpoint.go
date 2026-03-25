// Package endpoint implements the `krakenkey endpoint` subcommands.
package endpoint

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// RunAdd creates a new monitored endpoint.
func RunAdd(ctx context.Context, client *api.Client, printer *output.Printer, host string, port int, sni, label *string, probeIds []string) error {
	ep, err := client.CreateEndpoint(ctx, host, port, sni, label, probeIds)
	if err != nil {
		return err
	}

	printer.JSON(ep)
	printer.Success("Endpoint added: %s:%d", ep.Host, ep.Port)
	if ep.Label != nil && *ep.Label != "" {
		printer.Info("Label: %s", *ep.Label)
	}
	if len(ep.ProbeAssignments) > 0 {
		names := make([]string, len(ep.ProbeAssignments))
		for i, a := range ep.ProbeAssignments {
			if a.Probe != nil {
				names[i] = a.Probe.Name
			} else {
				names[i] = a.ProbeID
			}
		}
		printer.Info("Assigned probes: %s", strings.Join(names, ", "))
	}
	printer.Info("Run `krakenkey endpoint list` to see all monitored endpoints")
	return nil
}

// RunListProbes lists the user's connected probes available for assignment.
func RunListProbes(ctx context.Context, client *api.Client, printer *output.Printer) error {
	probes, err := client.ListUserProbes(ctx)
	if err != nil {
		return err
	}

	printer.JSON(probes)

	if len(probes) == 0 {
		printer.Info("No connected probes registered")
		printer.Println("")
		printer.Println("Set up a probe with KK_PROBE_MODE=connected and your API key to get started")
		return nil
	}

	headers := []string{"ID", "Name", "Region", "Status", "Last Seen"}
	rows := make([][]string, len(probes))
	for i, p := range probes {
		region := "-"
		if p.Region != nil {
			region = *p.Region
		}
		lastSeen := "-"
		if p.LastSeenAt != nil {
			lastSeen = p.LastSeenAt.Format(time.RFC3339)
		}
		rows[i] = []string{p.ID, p.Name, region, p.Status, lastSeen}
	}
	printer.Table(headers, rows)
	return nil
}

// RunList lists all monitored endpoints.
func RunList(ctx context.Context, client *api.Client, printer *output.Printer) error {
	endpoints, err := client.ListEndpoints(ctx)
	if err != nil {
		return err
	}

	printer.JSON(endpoints)

	if len(endpoints) == 0 {
		printer.Info("No endpoints registered")
		return nil
	}

	headers := []string{"ID", "Host", "Port", "Label", "Active", "Regions", "Created"}
	rows := make([][]string, len(endpoints))
	for i, ep := range endpoints {
		active := "yes"
		if !ep.IsActive {
			active = "no"
		}
		label := "-"
		if ep.Label != nil && *ep.Label != "" {
			label = *ep.Label
		}
		regions := "-"
		if len(ep.HostedRegions) > 0 {
			regionNames := make([]string, len(ep.HostedRegions))
			for j, r := range ep.HostedRegions {
				regionNames[j] = r.Region
			}
			regions = strings.Join(regionNames, ", ")
		}
		rows[i] = []string{
			ep.ID,
			ep.Host,
			fmt.Sprintf("%d", ep.Port),
			label,
			active,
			regions,
			ep.CreatedAt.Format(time.RFC3339),
		}
	}
	printer.Table(headers, rows)
	return nil
}

// RunShow prints full details for an endpoint.
func RunShow(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	ep, err := client.GetEndpoint(ctx, id)
	if err != nil {
		return err
	}

	printer.JSON(ep)
	printer.Println("ID:       %s", ep.ID)
	printer.Println("Host:     %s", ep.Host)
	printer.Println("Port:     %d", ep.Port)
	if ep.SNI != nil {
		printer.Println("SNI:      %s", *ep.SNI)
	}
	if ep.Label != nil {
		printer.Println("Label:    %s", *ep.Label)
	}
	printer.Println("Active:   %v", ep.IsActive)
	if len(ep.HostedRegions) > 0 {
		regionNames := make([]string, len(ep.HostedRegions))
		for i, r := range ep.HostedRegions {
			regionNames[i] = r.Region
		}
		printer.Println("Regions:  %s", strings.Join(regionNames, ", "))
	}
	printer.Println("Created:  %s", ep.CreatedAt.Format(time.RFC3339))
	return nil
}

// RunUpdate updates an endpoint's mutable fields.
func RunUpdate(ctx context.Context, client *api.Client, printer *output.Printer, id string, updates map[string]any) error {
	ep, err := client.UpdateEndpoint(ctx, id, updates)
	if err != nil {
		return err
	}

	printer.JSON(ep)
	printer.Success("Endpoint %s:%d updated", ep.Host, ep.Port)
	return nil
}

// RunDelete deletes an endpoint by ID.
func RunDelete(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	if err := client.DeleteEndpoint(ctx, id); err != nil {
		return err
	}
	printer.Success("Endpoint %s deleted", id)
	return nil
}

// RunEnable enables a disabled endpoint.
func RunEnable(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	return RunUpdate(ctx, client, printer, id, map[string]any{"isActive": true})
}

// RunDisable disables an endpoint.
func RunDisable(ctx context.Context, client *api.Client, printer *output.Printer, id string) error {
	return RunUpdate(ctx, client, printer, id, map[string]any{"isActive": false})
}

// RunAddRegion adds a hosted probe region to an endpoint.
func RunAddRegion(ctx context.Context, client *api.Client, printer *output.Printer, id, region string) error {
	ehr, err := client.AddEndpointRegion(ctx, id, region)
	if err != nil {
		return err
	}

	printer.JSON(ehr)
	printer.Success("Region %s added to endpoint %s", ehr.Region, id)
	return nil
}

// RunRemoveRegion removes a hosted probe region from an endpoint.
func RunRemoveRegion(ctx context.Context, client *api.Client, printer *output.Printer, id, region string) error {
	if err := client.RemoveEndpointRegion(ctx, id, region); err != nil {
		return err
	}
	printer.Success("Region %s removed from endpoint %s", region, id)
	return nil
}
