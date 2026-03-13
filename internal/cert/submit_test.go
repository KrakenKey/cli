package cert_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/cert"
)

func writeCSRFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0o644); err != nil {
		t.Fatalf("write CSR file: %v", err)
	}
	return p
}

func TestRunSubmit_NoWait(t *testing.T) {
	dir := t.TempDir()
	csrPath := filepath.Join(dir, "test.csr")
	csrPem := "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----\n"
	if err := os.WriteFile(csrPath, []byte(csrPem), 0o644); err != nil {
		t.Fatalf("write CSR: %v", err)
	}

	var gotCSR string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			gotCSR = body["csrPem"]
			json.NewEncoder(w).Encode(api.CertResponse{ID: 20, Status: "pending"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunSubmit(context.Background(), client, printer, cert.SubmitOptions{
		CSRPath: csrPath,
		Wait:    false,
	})
	if err != nil {
		t.Fatalf("RunSubmit: %v", err)
	}

	if gotCSR != csrPem {
		t.Errorf("submitted CSR = %q, want original PEM", gotCSR)
	}
	if !strings.Contains(out.String(), "submitted") {
		t.Errorf("output missing 'submitted':\n%s", out.String())
	}
}

func TestRunSubmit_WithWait(t *testing.T) {
	dir := t.TempDir()
	csrPath := writeCSRFile(t, dir, "test.csr")

	certPem := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			json.NewEncoder(w).Encode(api.CertResponse{ID: 20, Status: "pending"})
		case http.MethodGet:
			json.NewEncoder(w).Encode(api.TlsCert{
				ID:     20,
				Status: "issued",
				CrtPem: certPem,
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "submit.example.com"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunSubmit(context.Background(), client, printer, cert.SubmitOptions{
		CSRPath:      csrPath,
		Out:          filepath.Join(dir, "result.crt"),
		Wait:         true,
		PollInterval: 50 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunSubmit: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "result.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(data) != certPem {
		t.Errorf("cert content = %q, want PEM", string(data))
	}
	if !strings.Contains(out.String(), "issued") {
		t.Errorf("output missing 'issued':\n%s", out.String())
	}
}

func TestRunSubmit_FileNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("API should not be called when CSR file is missing")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunSubmit(context.Background(), client, printer, cert.SubmitOptions{
		CSRPath: "/nonexistent/path/test.csr",
	})
	if err == nil {
		t.Fatal("expected error for missing CSR file")
	}
	if !strings.Contains(err.Error(), "read CSR file") {
		t.Errorf("error = %q, want to contain 'read CSR file'", err.Error())
	}
}

func TestRunSubmit_WithAutoRenew(t *testing.T) {
	dir := t.TempDir()
	csrPath := writeCSRFile(t, dir, "test.csr")

	var autoRenewSet bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			json.NewEncoder(w).Encode(api.CertResponse{ID: 20, Status: "pending"})
		case http.MethodPatch:
			autoRenewSet = true
			json.NewEncoder(w).Encode(api.TlsCert{ID: 20, AutoRenew: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunSubmit(context.Background(), client, printer, cert.SubmitOptions{
		CSRPath:   csrPath,
		AutoRenew: true,
		Wait:      false,
	})
	if err != nil {
		t.Fatalf("RunSubmit: %v", err)
	}
	if !autoRenewSet {
		t.Error("auto-renew PATCH was not called")
	}
}

func TestRunSubmit_IssuanceFailed(t *testing.T) {
	dir := t.TempDir()
	csrPath := writeCSRFile(t, dir, "test.csr")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			json.NewEncoder(w).Encode(api.CertResponse{ID: 20, Status: "pending"})
		case http.MethodGet:
			json.NewEncoder(w).Encode(api.TlsCert{ID: 20, Status: "failed"})
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunSubmit(context.Background(), client, printer, cert.SubmitOptions{
		CSRPath:      csrPath,
		Wait:         true,
		PollInterval: 50 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for failed issuance")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("error = %q, want to contain 'failed'", err.Error())
	}
}
