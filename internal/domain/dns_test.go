package domain_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/domain"
	"github.com/krakenkey/cli/internal/output"
)

const zone = "acme.krakenkey.io"

type fakeResolver struct {
	cname map[string]string
	txt   map[string][]string
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c, nil
	}
	return "", notFound(host)
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if t, ok := f.txt[name]; ok {
		return t, nil
	}
	return nil, notFound(name)
}

func domainsServer(t *testing.T, status int, domains []api.Domain) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != http.StatusOK {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{"statusCode": status, "message": "Unauthorized"})
			return
		}
		json.NewEncoder(w).Encode(domains)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func byName(res domain.CheckResult) map[string]domain.RecordCheck {
	m := map[string]domain.RecordCheck{}
	for _, r := range res.Records {
		m[r.Type+" "+r.Name] = r
	}
	return m
}

func TestChallengeRecord(t *testing.T) {
	tests := []struct{ in, name, target string }{
		{"example.com", "_acme-challenge.example.com", "example-com.acme.krakenkey.io"},
		{"www.example.com", "_acme-challenge.www.example.com", "www-example-com.acme.krakenkey.io"},
		{"*.example.com", "_acme-challenge.example.com", "example-com.acme.krakenkey.io"},
		{"WWW.Example.COM.", "_acme-challenge.www.example.com", "www-example-com.acme.krakenkey.io"},
	}
	for _, tt := range tests {
		name, target := domain.ChallengeRecord(tt.in, zone)
		if name != tt.name || target != tt.target {
			t.Errorf("ChallengeRecord(%q) = %q, %q; want %q, %q", tt.in, name, target, tt.name, tt.target)
		}
	}
}

func TestACMEZoneEnv(t *testing.T) {
	t.Setenv("KK_ACME_ZONE", "Acme-Dev.Example.NET.")
	if got := domain.ACMEZone(); got != "acme-dev.example.net" {
		t.Errorf("ACMEZone() = %q", got)
	}
	t.Setenv("KK_ACME_ZONE", "")
	if got := domain.ACMEZone(); got != domain.DefaultACMEZone {
		t.Errorf("ACMEZone() = %q, want default", got)
	}
}

func TestCheck_CNAMEStatuses(t *testing.T) {
	r := fakeResolver{
		cname: map[string]string{
			"_acme-challenge.example.com":     "example-com.acme.krakenkey.io.",
			"_acme-challenge.www.example.com": "elsewhere.example.net.",
			// No CNAME, but the name has address records: resolvers return the name itself.
			"_acme-challenge.api.example.com": "_acme-challenge.api.example.com.",
		},
		txt: map[string][]string{
			"_acme-challenge.old.example.com": {"leftover-token"},
		},
	}
	res := domain.Check(context.Background(), nil, domain.CheckOptions{
		Names:    []string{"example.com", "*.example.com", "www.example.com", "old.example.com", "new.example.com", "api.example.com"},
		Resolver: r,
		Zone:     zone,
	})

	if len(res.Records) != 5 {
		t.Fatalf("got %d records, want 5 (wildcard shares the apex record): %+v", len(res.Records), res.Records)
	}
	m := byName(res)
	want := map[string]string{
		"CNAME _acme-challenge.example.com":     domain.StatusOK,
		"CNAME _acme-challenge.www.example.com": domain.StatusWrong,
		"CNAME _acme-challenge.old.example.com": domain.StatusConflict,
		"CNAME _acme-challenge.new.example.com": domain.StatusMissing,
		"CNAME _acme-challenge.api.example.com": domain.StatusMissing,
	}
	for k, status := range want {
		if m[k].Status != status {
			t.Errorf("%s status = %q, want %q (%+v)", k, m[k].Status, status, m[k])
		}
	}
	if m["CNAME _acme-challenge.www.example.com"].Found != "elsewhere.example.net" {
		t.Errorf("wrong record should report what it points to: %+v", m["CNAME _acme-challenge.www.example.com"])
	}
	if res.Ready {
		t.Error("Ready = true with missing records")
	}
}

func TestCheck_Ownership(t *testing.T) {
	srv := domainsServer(t, http.StatusOK, []api.Domain{
		{ID: "d1", Hostname: "example.com", VerificationCode: "krakenkey-site-verification=aaa", IsVerified: false},
		{ID: "d2", Hostname: "verified.org", VerificationCode: "krakenkey-site-verification=bbb", IsVerified: true},
		{ID: "d3", Hostname: "other.net", VerificationCode: "krakenkey-site-verification=ccc", IsVerified: false},
	})
	r := fakeResolver{
		cname: map[string]string{
			"_acme-challenge.www.example.com": "www-example-com.acme.krakenkey.io.",
			"_acme-challenge.verified.org":    "verified-org.acme.krakenkey.io.",
			"_acme-challenge.other.net":       "other-net.acme.krakenkey.io.",
			"_acme-challenge.nobody.io":       "nobody-io.acme.krakenkey.io.",
		},
		txt: map[string][]string{
			// Stale codes from other accounts sit alongside the right one.
			"example.com": {"krakenkey-site-verification=zzz", "krakenkey-site-verification=aaa"},
			"other.net":   {"v=spf1 -all"},
		},
	}
	res := domain.Check(context.Background(), newTestClient(srv.URL), domain.CheckOptions{
		Names:    []string{"www.example.com", "verified.org", "other.net", "nobody.io"},
		Resolver: r,
		Zone:     zone,
	})
	m := byName(res)

	if got := m["TXT example.com"]; got.Status != domain.StatusOK || !strings.Contains(got.Detail, "domain verify d1") {
		t.Errorf("subdomain should map to unverified parent with TXT present: %+v", got)
	}
	if got := m["TXT verified.org"]; got.Status != domain.StatusOK || got.Detail != "domain verified" {
		t.Errorf("verified domain: %+v", got)
	}
	if got := m["TXT other.net"]; got.Status != domain.StatusMissing {
		t.Errorf("missing TXT: %+v", got)
	}
	if got := m["TXT nobody.io"]; got.Status != domain.StatusUnknown {
		t.Errorf("unregistered name: %+v", got)
	}
	if res.Ready {
		t.Error("Ready = true with a missing TXT and an unregistered name")
	}
}

func TestCheck_NoAPIKeySkipsOwnership(t *testing.T) {
	srv := domainsServer(t, http.StatusUnauthorized, nil)
	r := fakeResolver{cname: map[string]string{
		"_acme-challenge.example.com": "example-com.acme.krakenkey.io.",
	}}
	res := domain.Check(context.Background(), newTestClient(srv.URL), domain.CheckOptions{
		Names: []string{"example.com"}, Resolver: r, Zone: zone,
	})
	if len(res.Records) != 2 || res.Records[0].Status != domain.StatusSkipped {
		t.Fatalf("want a skipped TXT row then the CNAME: %+v", res.Records)
	}
	if !res.Ready {
		t.Error("Ready = false; a skipped TXT check shouldn't block")
	}
}

func TestRunCheck_ExitsNonZeroWhenNotReady(t *testing.T) {
	printer, out, _ := newPrinterFormat("json")
	err := domain.RunCheck(context.Background(), nil, printer, domain.CheckOptions{
		Names: []string{"example.com"}, Resolver: fakeResolver{}, Zone: zone,
	})
	if err == nil {
		t.Fatal("expected an error when records are missing")
	}
	var res domain.CheckResult
	if jerr := json.Unmarshal(out.Bytes(), &res); jerr != nil {
		t.Fatalf("JSON output: %v\n%s", jerr, out.String())
	}
	if res.Ready || len(res.Records) != 1 || res.Records[0].Expected != "example-com.acme.krakenkey.io" {
		t.Errorf("unexpected result: %+v", res)
	}
}

func TestRunAdd_JSONIncludesDNSRecords(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.Domain{ID: "d1", Hostname: "example.com", VerificationCode: "krakenkey-site-verification=abc"})
	}))
	defer srv.Close()

	printer, out, _ := newPrinterFormat("json")
	if err := domain.RunAdd(context.Background(), newTestClient(srv.URL), printer, "example.com"); err != nil {
		t.Fatalf("RunAdd: %v", err)
	}
	var got struct {
		ID         string             `json:"id"`
		Hostname   string             `json:"hostname"`
		DNSRecords []domain.DNSRecord `json:"dnsRecords"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("JSON output: %v\n%s", err, out.String())
	}
	want := []domain.DNSRecord{
		{Type: "TXT", Name: "example.com", Value: "krakenkey-site-verification=abc"},
		{Type: "CNAME", Name: "_acme-challenge.example.com", Value: "example-com.acme.krakenkey.io"},
	}
	if got.ID != "d1" || len(got.DNSRecords) != 2 || got.DNSRecords[0] != want[0] || got.DNSRecords[1] != want[1] {
		t.Errorf("unexpected output: %+v", got)
	}
}

func newPrinterFormat(format string) (*output.Printer, *bytes.Buffer, *bytes.Buffer) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	return output.NewWithWriters(format, true, out, errOut), out, errOut
}
