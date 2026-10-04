package domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/output"
)

// DefaultACMEZone is the zone KrakenKey answers DNS-01 challenges from.
// KK_ACME_ZONE overrides it for non-production APIs.
const DefaultACMEZone = "acme.krakenkey.io"

// ACMEZone returns the challenge delegation zone in use.
func ACMEZone() string {
	if z := strings.TrimSpace(os.Getenv("KK_ACME_ZONE")); z != "" {
		return strings.TrimSuffix(strings.ToLower(z), ".")
	}
	return DefaultACMEZone
}

// ChallengeRecord returns the CNAME KrakenKey expects for a certificate name:
// _acme-challenge.<name> -> <name with dots as dashes>.<zone>. A leading "*."
// is dropped, so a wildcard shares its parent's record.
func ChallengeRecord(name, zone string) (recordName, target string) {
	base := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*.")), ".")
	return "_acme-challenge." + base, strings.ReplaceAll(base, ".", "-") + "." + zone
}

// DNSRecord is a record the user needs to create.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Resolver is the subset of *net.Resolver used for checks.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// NewResolver returns the system resolver, or one that queries server
// (host or host:port) directly.
func NewResolver(server string) Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
}

// Record check statuses.
const (
	StatusOK       = "ok"
	StatusMissing  = "missing"
	StatusWrong    = "wrong"
	StatusConflict = "conflict"
	StatusUnknown  = "unregistered"
	StatusSkipped  = "skipped"
)

// RecordCheck is the result for one DNS record.
type RecordCheck struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Found    string `json:"found,omitempty"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

// CheckResult is the outcome of `domain check`.
type CheckResult struct {
	Ready   bool          `json:"ready"`
	Records []RecordCheck `json:"records"`
}

// CheckOptions configures RunCheck.
type CheckOptions struct {
	Names        []string
	Resolver     Resolver
	Zone         string
	Wait         bool
	PollInterval time.Duration
	PollTimeout  time.Duration
}

// RunCheck reports whether the DNS records for the given certificate names
// are in place: one challenge CNAME per name and, when the API key works,
// the ownership TXT for any covering domain that isn't verified yet.
func RunCheck(ctx context.Context, client *api.Client, printer *output.Printer, opts CheckOptions) error {
	if opts.Zone == "" {
		opts.Zone = ACMEZone()
	}
	if opts.Resolver == nil {
		opts.Resolver = NewResolver("")
	}

	res := Check(ctx, client, opts)
	if opts.Wait && !res.Ready {
		spinner := printer.NewSpinner("Waiting for DNS records")
		spinner.Start()
		deadline := time.After(opts.PollTimeout)
		tick := time.NewTicker(opts.PollInterval)
	poll:
		for {
			select {
			case <-ctx.Done():
				spinner.Stop()
				tick.Stop()
				return ctx.Err()
			case <-deadline:
				break poll
			case <-tick.C:
				res = Check(ctx, client, opts)
				if res.Ready {
					break poll
				}
				spinner.UpdateMsg(fmt.Sprintf("Waiting for DNS records (%d not ready)", notReady(res)))
			}
		}
		spinner.Stop()
		tick.Stop()
	}

	printer.JSON(res)
	rows := make([][]string, len(res.Records))
	for i, r := range res.Records {
		rows[i] = []string{r.Type, r.Name, r.Expected, r.Status, r.Detail}
	}
	printer.Table([]string{"Type", "Name", "Expected", "Status", "Detail"}, rows)

	if !res.Ready {
		return fmt.Errorf("%d DNS record(s) not ready", notReady(res))
	}
	printer.Success("DNS records are in place")
	return nil
}

func notReady(res CheckResult) int {
	n := 0
	for _, r := range res.Records {
		if r.Status != StatusOK && r.Status != StatusSkipped {
			n++
		}
	}
	return n
}

// Check runs one pass of the DNS checks.
func Check(ctx context.Context, client *api.Client, opts CheckOptions) CheckResult {
	var records []RecordCheck
	records = append(records, checkOwnership(ctx, client, opts)...)

	seen := map[string]bool{}
	for _, name := range opts.Names {
		recordName, target := ChallengeRecord(name, opts.Zone)
		if seen[recordName] {
			continue
		}
		seen[recordName] = true
		records = append(records, checkCNAME(ctx, opts.Resolver, recordName, target))
	}

	return CheckResult{Ready: notReady(CheckResult{Records: records}) == 0, Records: records}
}

func checkCNAME(ctx context.Context, r Resolver, name, target string) RecordCheck {
	rc := RecordCheck{Type: "CNAME", Name: name, Expected: target}

	found, err := r.LookupCNAME(ctx, name)
	found = strings.TrimSuffix(strings.ToLower(found), ".")
	if err == nil && found != "" && found != name {
		rc.Found = found
		if found == target {
			rc.Status = StatusOK
		} else {
			rc.Status = StatusWrong
			rc.Detail = "points to " + found
		}
		return rc
	}

	var dnsErr *net.DNSError
	if err != nil && (!errors.As(err, &dnsErr) || !dnsErr.IsNotFound) {
		rc.Status = StatusMissing
		rc.Detail = "lookup failed: " + err.Error()
		return rc
	}

	// No CNAME. A TXT already at this name would block adding one.
	if txt, err := r.LookupTXT(ctx, name); err == nil && len(txt) > 0 {
		rc.Status = StatusConflict
		rc.Detail = "TXT records exist at this name; delete them and add the CNAME"
		return rc
	}
	rc.Status = StatusMissing
	return rc
}

// checkOwnership finds the registered domain covering each name and checks
// its TXT record if it isn't verified. Without a working API key it reports
// a single skipped row instead.
func checkOwnership(ctx context.Context, client *api.Client, opts CheckOptions) []RecordCheck {
	if client == nil {
		return nil
	}
	domains, err := client.ListDomains(ctx)
	if err != nil {
		var authErr *api.ErrAuth
		if errors.As(err, &authErr) {
			return []RecordCheck{{Type: "TXT", Status: StatusSkipped, Detail: "no API key; ownership TXT not checked"}}
		}
		return []RecordCheck{{Type: "TXT", Status: StatusSkipped, Detail: "could not list domains: " + err.Error()}}
	}

	// Longest registered domain first, so the closest parent wins.
	sort.Slice(domains, func(i, j int) bool { return len(domains[i].Hostname) > len(domains[j].Hostname) })

	var records []RecordCheck
	seen := map[string]bool{}
	for _, name := range opts.Names {
		base := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*.")), ".")
		d := covering(domains, base)
		if d == nil {
			key := "none:" + base
			if !seen[key] {
				seen[key] = true
				records = append(records, RecordCheck{
					Type: "TXT", Name: base, Status: StatusUnknown,
					Detail: "no registered domain covers this name; run `krakenkey domain add`",
				})
			}
			continue
		}
		if seen[d.ID] {
			continue
		}
		seen[d.ID] = true

		rc := RecordCheck{Type: "TXT", Name: d.Hostname, Expected: d.VerificationCode}
		if d.IsVerified {
			rc.Status = StatusOK
			rc.Detail = "domain verified"
			records = append(records, rc)
			continue
		}
		txt, _ := opts.Resolver.LookupTXT(ctx, d.Hostname)
		rc.Status = StatusMissing
		for _, v := range txt {
			if strings.Contains(v, d.VerificationCode) {
				rc.Found = v
				rc.Status = StatusOK
				rc.Detail = fmt.Sprintf("found; run `krakenkey domain verify %s`", d.ID)
				break
			}
		}
		records = append(records, rc)
	}
	return records
}

func covering(domains []api.Domain, name string) *api.Domain {
	for i := range domains {
		h := strings.ToLower(domains[i].Hostname)
		if name == h || strings.HasSuffix(name, "."+h) {
			return &domains[i]
		}
	}
	return nil
}
