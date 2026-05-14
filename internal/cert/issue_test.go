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

func TestRunIssue_NoWait(t *testing.T) {
	dir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certs/tls") {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["csrPem"] == "" {
				t.Error("csrPem is empty in request body")
			}
			json.NewEncoder(w).Encode(api.CertResponse{ID: 10, Status: "pending"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain:  "test.example.com",
		KeyType: "ecdsa-p256",
		KeyOut:  filepath.Join(dir, "test.key"),
		CSROut:  filepath.Join(dir, "test.csr"),
		Out:     filepath.Join(dir, "test.crt"),
		Wait:    false,
	})
	if err != nil {
		t.Fatalf("RunIssue: %v", err)
	}

	// Verify private key was written with restricted permissions.
	keyInfo, err := os.Stat(filepath.Join(dir, "test.key"))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}

	// Verify CSR file exists.
	if _, err := os.Stat(filepath.Join(dir, "test.csr")); err != nil {
		t.Errorf("CSR file not found: %v", err)
	}

	// Cert file should NOT exist (no --wait, cert not issued yet).
	if _, err := os.Stat(filepath.Join(dir, "test.crt")); !os.IsNotExist(err) {
		t.Errorf("cert file should not exist without --wait, err = %v", err)
	}

	if !strings.Contains(out.String(), "submitted") {
		t.Errorf("output missing 'submitted':\n%s", out.String())
	}
}

func TestRunIssue_WithWait(t *testing.T) {
	dir := t.TempDir()
	certPem := "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certs/tls"):
			json.NewEncoder(w).Encode(api.CertResponse{ID: 10, Status: "pending"})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/certs/tls/10"):
			json.NewEncoder(w).Encode(api.TlsCert{
				ID:     10,
				Status: "issued",
				CrtPem: certPem,
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "test.example.com"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, out, _ := newPrinter()

	err := cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain:       "test.example.com",
		KeyType:      "ecdsa-p256",
		KeyOut:       filepath.Join(dir, "test.key"),
		CSROut:       filepath.Join(dir, "test.csr"),
		Out:          filepath.Join(dir, "test.crt"),
		Wait:         true,
		PollInterval: 50 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunIssue: %v", err)
	}

	// Verify cert was written.
	data, err := os.ReadFile(filepath.Join(dir, "test.crt"))
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	if string(data) != certPem {
		t.Errorf("cert content = %q, want PEM", string(data))
	}

	if !strings.Contains(out.String(), "issued") {
		t.Errorf("output missing 'issued':\n%s", out.String())
	}
}

func TestRunIssue_WithAutoRenew(t *testing.T) {
	dir := t.TempDir()
	var autoRenewSet bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certs/tls"):
			json.NewEncoder(w).Encode(api.CertResponse{ID: 10, Status: "pending"})
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/certs/tls/10"):
			autoRenewSet = true
			json.NewEncoder(w).Encode(api.TlsCert{ID: 10, AutoRenew: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain:    "example.com",
		KeyOut:    filepath.Join(dir, "test.key"),
		CSROut:    filepath.Join(dir, "test.csr"),
		Out:       filepath.Join(dir, "test.crt"),
		AutoRenew: true,
		Wait:      false,
	})
	if err != nil {
		t.Fatalf("RunIssue: %v", err)
	}
	if !autoRenewSet {
		t.Error("auto-renew PATCH was not called")
	}
}

func TestRunIssue_DefaultFilenames(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(api.CertResponse{ID: 1, Status: "pending"})
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err = cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain: "mysite.io",
		Wait:   false,
	})
	if err != nil {
		t.Fatalf("RunIssue: %v", err)
	}

	// Default filenames should be <domain>.key and <domain>.csr.
	for _, name := range []string{"mysite.io.key", "mysite.io.csr"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected default file %s: %v", name, err)
		}
	}
}

func TestRunIssue_WithWait_WritesChainFiles(t *testing.T) {
	dir := t.TempDir()
	certPem := "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
	chainPem := "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n"
	fullChainPem := certPem + chainPem

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certs/tls"):
			json.NewEncoder(w).Encode(api.CertResponse{ID: 10, Status: "pending"})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/chain"):
			json.NewEncoder(w).Encode(api.TlsCertChainInfo{FullChainPem: fullChainPem})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/certs/tls/10"):
			json.NewEncoder(w).Encode(api.TlsCert{
				ID:       10,
				Status:   "issued",
				CrtPem:   certPem,
				ChainPem: chainPem,
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "test.example.com"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain:       "test.example.com",
		KeyType:      "ecdsa-p256",
		KeyOut:       filepath.Join(dir, "test.key"),
		CSROut:       filepath.Join(dir, "test.csr"),
		Out:          filepath.Join(dir, "test.crt"),
		ChainOut:     filepath.Join(dir, "test.chain.crt"),
		FullchainOut: filepath.Join(dir, "test.fullchain.crt"),
		Wait:         true,
		PollInterval: 50 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunIssue: %v", err)
	}

	// Verify cert file
	data, err := os.ReadFile(filepath.Join(dir, "test.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(data) != certPem {
		t.Errorf("cert content = %q, want leaf PEM", string(data))
	}

	// Verify chain file
	data, err = os.ReadFile(filepath.Join(dir, "test.chain.crt"))
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	if string(data) != chainPem {
		t.Errorf("chain content = %q, want chain PEM", string(data))
	}

	// Verify fullchain file
	data, err = os.ReadFile(filepath.Join(dir, "test.fullchain.crt"))
	if err != nil {
		t.Fatalf("read fullchain: %v", err)
	}
	if string(data) != fullChainPem {
		t.Errorf("fullchain content = %q, want fullchain PEM", string(data))
	}
}

func TestRunIssue_InvalidKeyType(t *testing.T) {
	dir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("API should not be called for invalid key type")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	printer, _, _ := newPrinter()

	err := cert.RunIssue(context.Background(), client, printer, cert.IssueOptions{
		Domain:  "example.com",
		KeyType: "rsa-1024",
		KeyOut:  filepath.Join(dir, "test.key"),
		CSROut:  filepath.Join(dir, "test.csr"),
	})
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}
