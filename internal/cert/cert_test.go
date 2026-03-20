package cert_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/cert"
	"github.com/krakenkey/cli/internal/output"
)

func newTestClient(baseURL string) *api.Client {
	return api.NewClient(baseURL, "kk_test", "v0.0.0", "linux", "amd64")
}

func newPrinter() (*output.Printer, *bytes.Buffer, *bytes.Buffer) {
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	return output.NewWithWriters("text", true, out, errOut), out, errOut
}

func TestRunList_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]api.TlsCert{})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunList(context.Background(), client, printer, "")
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}
	if !strings.Contains(out.String(), "No certificates") {
		t.Errorf("output = %q, want 'No certificates' message", out.String())
	}
}

func TestRunList_WithCerts(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	exp := now.Add(90 * 24 * time.Hour)
	certs := []api.TlsCert{
		{
			ID:        1,
			Status:    "issued",
			ExpiresAt: &exp,
			AutoRenew: true,
			CreatedAt: now,
			ParsedCsr: &api.ParsedCsr{
				Subject: []api.CsrSubjectField{{Name: "commonName", Value: "example.com"}},
			},
		},
		{
			ID:        2,
			Status:    "pending",
			AutoRenew: false,
			CreatedAt: now,
			ParsedCsr: &api.ParsedCsr{
				Subject: []api.CsrSubjectField{{Name: "commonName", Value: "test.io"}},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certs)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunList(context.Background(), client, printer, "")
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}

	got := out.String()
	for _, want := range []string{"example.com", "test.io", "issued", "pending", "yes", "no"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunList_StatusFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]api.TlsCert{})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	_ = cert.RunList(context.Background(), client, printer, "issued")
	if gotQuery != "status=issued" {
		t.Errorf("query = %q, want status=issued", gotQuery)
	}
}

func TestRunShow_Success(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	exp := now.Add(90 * 24 * time.Hour)
	tlsCert := api.TlsCert{
		ID:        42,
		Status:    "issued",
		ExpiresAt: &exp,
		AutoRenew: true,
		CreatedAt: now,
		ParsedCsr: &api.ParsedCsr{
			Subject:   []api.CsrSubjectField{{Name: "commonName", Value: "example.com"}},
			PublicKey: &api.CsrPublicKey{KeyType: "ECDSA", BitLength: 256},
		},
	}
	details := api.TlsCertDetails{
		SerialNumber: "ABCDEF",
		Issuer:       "Let's Encrypt",
		ValidFrom:    now,
		ValidTo:      exp,
		Fingerprint:  "AA:BB:CC",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/certs/tls/42/details" {
			json.NewEncoder(w).Encode(details)
			return
		}
		json.NewEncoder(w).Encode(tlsCert)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunShow(context.Background(), client, printer, 42)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}

	got := out.String()
	for _, want := range []string{"42", "issued", "example.com", "ECDSA 256", "ABCDEF", "Let's Encrypt", "AA:BB:CC"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunDownload_Success(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "test.crt")

	certPem := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	tlsCert := api.TlsCert{
		ID:     1,
		Status: "issued",
		CrtPem: certPem,
		ParsedCsr: &api.ParsedCsr{
			Subject: []api.CsrSubjectField{{Name: "commonName", Value: "example.com"}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tlsCert)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunDownload(context.Background(), client, printer, 1, outPath)
	if err != nil {
		t.Fatalf("RunDownload: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(data) != certPem {
		t.Errorf("file content = %q, want PEM", string(data))
	}
	if !strings.Contains(out.String(), "saved") {
		t.Errorf("output = %q, want 'saved'", out.String())
	}
}

func TestRunDownload_NotIssued(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: "pending"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunDownload(context.Background(), client, printer, 1, "")
	if err == nil {
		t.Fatal("expected error for non-issued cert")
	}
	if !strings.Contains(err.Error(), "not issued") {
		t.Errorf("error = %q, want to contain 'not issued'", err.Error())
	}
}

func TestRunDownload_DefaultFilename(t *testing.T) {
	dir := t.TempDir()
	// Change to temp dir so default filename writes there.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	certPem := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
	tlsCert := api.TlsCert{
		ID:     1,
		Status: "issued",
		CrtPem: certPem,
		ParsedCsr: &api.ParsedCsr{
			Subject: []api.CsrSubjectField{{Name: "commonName", Value: "mysite.com"}},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tlsCert)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err = cert.RunDownload(context.Background(), client, printer, 1, "")
	if err != nil {
		t.Fatalf("RunDownload: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "mysite.com.crt")); err != nil {
		t.Errorf("expected default output file mysite.com.crt: %v", err)
	}
}

func TestRunRenew_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CertResponse{ID: 5, Status: "renewing"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunRenew(context.Background(), client, printer, 5, false, 0, 0)
	if err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if !strings.Contains(out.String(), "Renewal triggered") {
		t.Errorf("output = %q, want 'Renewal triggered'", out.String())
	}
}

func TestRunRevoke_Success(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CertResponse{ID: 3, Status: "revoking"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	reason := 1
	err := cert.RunRevoke(context.Background(), client, printer, 3, &reason)
	if err != nil {
		t.Fatalf("RunRevoke: %v", err)
	}
	if !strings.Contains(out.String(), "revocation") {
		t.Errorf("output = %q, want 'revocation'", out.String())
	}
	if gotBody["reason"] != float64(1) {
		t.Errorf("request body reason = %v, want 1", gotBody["reason"])
	}
}

func TestRunRevoke_NoReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CertResponse{ID: 3, Status: "revoking"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunRevoke(context.Background(), client, printer, 3, nil)
	if err != nil {
		t.Fatalf("RunRevoke with nil reason: %v", err)
	}
}

func TestRunRetry_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CertResponse{ID: 7, Status: "pending"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunRetry(context.Background(), client, printer, 7, false, 0, 0)
	if err != nil {
		t.Fatalf("RunRetry: %v", err)
	}
	if gotPath != "/certs/tls/7/retry" {
		t.Errorf("path = %q, want /certs/tls/7/retry", gotPath)
	}
	if !strings.Contains(out.String(), "Retry triggered") {
		t.Errorf("output = %q, want 'Retry triggered'", out.String())
	}
}

func TestRunDelete_Success(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunDelete(context.Background(), client, printer, 10)
	if err != nil {
		t.Fatalf("RunDelete: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/certs/tls/10" {
		t.Errorf("path = %q, want /certs/tls/10", gotPath)
	}
	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("output = %q, want 'deleted'", out.String())
	}
}

func TestRunUpdate_AutoRenew(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{
			ID:        4,
			AutoRenew: body["autoRenew"].(bool),
			Status:    "issued",
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	enable := true
	err := cert.RunUpdate(context.Background(), client, printer, 4, &enable)
	if err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "updated") {
		t.Errorf("output missing 'updated':\n%s", got)
	}
	if !strings.Contains(got, "true") {
		t.Errorf("output missing auto-renew value:\n%s", got)
	}
}

func TestPollUntilDone_ImmediateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: "issued"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	c, err := cert.PollUntilDone(context.Background(), client, printer, 1, 50*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	if c.Status != "issued" {
		t.Errorf("status = %q, want issued", c.Status)
	}
}

func TestPollUntilDone_TransitionsToIssued(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		status := "pending"
		if n >= 3 {
			status = "issued"
		}
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: status})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	c, err := cert.PollUntilDone(context.Background(), client, printer, 1, 50*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	if c.Status != "issued" {
		t.Errorf("status = %q, want issued", c.Status)
	}
	if callCount.Load() < 3 {
		t.Errorf("expected at least 3 poll calls, got %d", callCount.Load())
	}
}

func TestPollUntilDone_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: "pending"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	_, err := cert.PollUntilDone(context.Background(), client, printer, 1, 50*time.Millisecond, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want to contain 'timed out'", err.Error())
	}
}

func TestPollUntilDone_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: "pending"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := cert.PollUntilDone(ctx, client, printer, 1, 50*time.Millisecond, 5*time.Second)
	if err == nil {
		t.Fatal("expected context cancelled error, got nil")
	}
}

func TestPollUntilDone_Failed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{ID: 1, Status: "failed"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	c, err := cert.PollUntilDone(context.Background(), client, printer, 1, 50*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatalf("PollUntilDone: %v", err)
	}
	// Failed is a terminal status — PollUntilDone returns it, caller decides the error.
	if c.Status != "failed" {
		t.Errorf("status = %q, want failed", c.Status)
	}
}

func TestCnFromCert_NoParsedCsr(t *testing.T) {
	// Use RunShow to indirectly verify cnFromCert returns the ID as fallback.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.TlsCert{
			ID:        99,
			Status:    "pending",
			CreatedAt: time.Now(),
		})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunShow(context.Background(), client, printer, 99)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}
	// When parsedCsr is nil, domain should show as the cert ID "99".
	if !strings.Contains(out.String(), fmt.Sprintf("Domain:      %d", 99)) {
		t.Errorf("expected fallback domain '99' in output:\n%s", out.String())
	}
}
