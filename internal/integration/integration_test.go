//go:build integration

// Package integration contains end-to-end tests that run against a live
// KrakenKey API. They are skipped in normal CI runs.
//
// Usage:
//
//	KK_API_URL=https://api-dev.krakenkey.io KK_API_KEY=kk_... go test -tags integration ./internal/integration/ -v
package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krakenkey/cli/internal/api"
	"github.com/krakenkey/cli/internal/auth"
	"github.com/krakenkey/cli/internal/account"
	"github.com/krakenkey/cli/internal/cert"
	"github.com/krakenkey/cli/internal/csr"
	"github.com/krakenkey/cli/internal/domain"
	"github.com/krakenkey/cli/internal/output"
)

func envOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("skipping: %s not set", key)
	}
	return v
}

func setup(t *testing.T) (*api.Client, *output.Printer, *bytes.Buffer) {
	t.Helper()
	apiURL := envOrSkip(t, "KK_API_URL")
	apiKey := envOrSkip(t, "KK_API_KEY")
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	printer := output.NewWithWriters("text", true, out, errOut)
	client := api.NewClient(apiURL, apiKey, "test", "linux", "amd64")
	return client, printer, out
}

// TestIntegration_AuthStatus verifies that the API key is valid and returns
// profile data.
func TestIntegration_AuthStatus(t *testing.T) {
	client, printer, out := setup(t)

	err := auth.RunStatus(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "User:") {
		t.Errorf("expected user info in output:\n%s", got)
	}
	if !strings.Contains(got, "Plan:") {
		t.Errorf("expected plan info in output:\n%s", got)
	}
	t.Logf("Auth status output:\n%s", got)
}

// TestIntegration_AccountShow verifies account profile retrieval.
func TestIntegration_AccountShow(t *testing.T) {
	client, printer, out := setup(t)

	err := account.RunShow(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}

	got := out.String()
	for _, field := range []string{"ID:", "Username:", "Email:", "Plan:"} {
		if !strings.Contains(got, field) {
			t.Errorf("output missing %q:\n%s", field, got)
		}
	}
	t.Logf("Account show output:\n%s", got)
}

// TestIntegration_AccountPlan verifies billing subscription retrieval.
func TestIntegration_AccountPlan(t *testing.T) {
	client, printer, out := setup(t)

	err := account.RunPlan(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "Plan:") || !strings.Contains(got, "Status:") {
		t.Errorf("output missing plan/status:\n%s", got)
	}
	t.Logf("Account plan output:\n%s", got)
}

// TestIntegration_DomainLifecycle tests add, list, show, and delete for a domain.
// It uses a throwaway subdomain to avoid conflicts.
func TestIntegration_DomainLifecycle(t *testing.T) {
	client, printer, out := setup(t)
	ctx := context.Background()

	hostname := "cli-test-" + time.Now().Format("20060102150405") + ".example.com"

	// Add domain.
	out.Reset()
	err := domain.RunAdd(ctx, client, printer, hostname)
	if err != nil {
		t.Fatalf("RunAdd: %v", err)
	}
	addOutput := out.String()
	if !strings.Contains(addOutput, hostname) {
		t.Errorf("RunAdd output missing hostname:\n%s", addOutput)
	}
	if !strings.Contains(addOutput, "krakenkey-site-verification=") {
		t.Errorf("RunAdd output missing verification code:\n%s", addOutput)
	}
	t.Logf("Domain add output:\n%s", addOutput)

	// List domains — should contain the newly added one.
	out.Reset()
	err = domain.RunList(ctx, client, printer)
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}
	if !strings.Contains(out.String(), hostname) {
		t.Errorf("RunList output missing new domain:\n%s", out.String())
	}

	// Get the domain ID from the API for show/delete.
	domains, err := client.ListDomains(ctx)
	if err != nil {
		t.Fatalf("client.ListDomains: %v", err)
	}
	var domainID string
	for _, d := range domains {
		if d.Hostname == hostname {
			domainID = d.ID
			break
		}
	}
	if domainID == "" {
		t.Fatalf("could not find domain %s in list", hostname)
	}

	// Show domain.
	out.Reset()
	err = domain.RunShow(ctx, client, printer, domainID)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}
	if !strings.Contains(out.String(), hostname) {
		t.Errorf("RunShow output missing hostname:\n%s", out.String())
	}

	// Delete domain (cleanup).
	out.Reset()
	err = domain.RunDelete(ctx, client, printer, domainID)
	if err != nil {
		t.Fatalf("RunDelete: %v", err)
	}
	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("RunDelete output missing confirmation:\n%s", out.String())
	}

	t.Log("Domain lifecycle test passed")
}

// TestIntegration_CertList verifies certificate listing works.
func TestIntegration_CertList(t *testing.T) {
	client, printer, out := setup(t)

	err := cert.RunList(context.Background(), client, printer, "")
	if err != nil {
		t.Fatalf("RunList: %v", err)
	}
	// Output should either show a table or "No certificates" — both are valid.
	t.Logf("Cert list output:\n%s", out.String())
}

// TestIntegration_CertIssueAndCleanup generates a CSR locally, submits it,
// checks status, then deletes. It does NOT wait for issuance (that requires
// a verified domain with real DNS).
func TestIntegration_CertIssueAndCleanup(t *testing.T) {
	client, printer, out := setup(t)
	ctx := context.Background()
	dir := t.TempDir()

	// Generate a CSR locally.
	result, err := csr.Generate(csr.KeyTypeECDSAP256, csr.Subject{
		CommonName: "cli-integration-test.example.com",
	}, nil)
	if err != nil {
		t.Fatalf("csr.Generate: %v", err)
	}

	// Verify the generated CSR is valid.
	block, _ := pem.Decode(result.CSRPem)
	if block == nil {
		t.Fatal("generated CSR is not valid PEM")
	}
	if _, err := x509.ParseCertificateRequest(block.Bytes); err != nil {
		t.Fatalf("invalid CSR: %v", err)
	}

	// Write CSR to file for submit command.
	csrPath := filepath.Join(dir, "test.csr")
	if err := os.WriteFile(csrPath, result.CSRPem, 0o644); err != nil {
		t.Fatalf("write CSR: %v", err)
	}

	// Write key to file.
	keyPath := filepath.Join(dir, "test.key")
	if err := os.WriteFile(keyPath, result.PrivateKeyPem, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// Verify key permissions.
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("key permissions = %o, want 0600", perm)
	}

	// Submit the CSR (without waiting).
	out.Reset()
	err = cert.RunSubmit(ctx, client, printer, cert.SubmitOptions{
		CSRPath: csrPath,
		Wait:    false,
	})
	if err != nil {
		t.Fatalf("RunSubmit: %v", err)
	}
	submitOutput := out.String()
	if !strings.Contains(submitOutput, "submitted") {
		t.Errorf("RunSubmit output missing 'submitted':\n%s", submitOutput)
	}
	t.Logf("Submit output:\n%s", submitOutput)

	// List certs to find the one we just submitted.
	certs, err := client.ListCerts(ctx, "")
	if err != nil {
		t.Fatalf("client.ListCerts: %v", err)
	}

	var certID int
	for _, c := range certs {
		if c.ParsedCsr != nil {
			for _, f := range c.ParsedCsr.Subject {
				if (f.Name == "commonName" || f.Name == "CN") && f.Value == "cli-integration-test.example.com" {
					certID = c.ID
					break
				}
			}
		}
		if certID > 0 {
			break
		}
	}
	if certID == 0 {
		t.Fatal("could not find submitted cert in list")
	}

	// Show the cert.
	out.Reset()
	err = cert.RunShow(ctx, client, printer, certID)
	if err != nil {
		t.Fatalf("RunShow: %v", err)
	}
	t.Logf("Cert show output:\n%s", out.String())

	// Delete the cert (cleanup). The cert will likely be in "failed" state
	// since the domain is unverified, which should be deletable.
	// Wait briefly for the async processing to move past pending.
	time.Sleep(2 * time.Second)

	out.Reset()
	err = cert.RunDelete(ctx, client, printer, certID)
	if err != nil {
		// If delete fails (e.g. cert in non-deletable state), just log it.
		t.Logf("RunDelete failed (may be in non-deletable state): %v", err)
	} else {
		t.Log("Cert deleted successfully")
	}
}

// TestIntegration_APIKeysLifecycle creates, lists, and deletes an API key.
func TestIntegration_APIKeysLifecycle(t *testing.T) {
	client, printer, out := setup(t)
	ctx := context.Background()

	keyName := "cli-test-" + time.Now().Format("150405")

	// Create a key.
	out.Reset()
	err := auth.RunKeysCreate(ctx, client, printer, keyName, nil)
	if err != nil {
		t.Fatalf("RunKeysCreate: %v", err)
	}
	createOutput := out.String()
	if !strings.Contains(createOutput, "kk_") {
		t.Errorf("RunKeysCreate output missing key secret:\n%s", createOutput)
	}
	t.Logf("Key create output:\n%s", createOutput)

	// List keys — should contain the new one.
	out.Reset()
	err = auth.RunKeysList(ctx, client, printer)
	if err != nil {
		t.Fatalf("RunKeysList: %v", err)
	}
	if !strings.Contains(out.String(), keyName) {
		t.Errorf("RunKeysList output missing new key:\n%s", out.String())
	}

	// Find the key ID.
	keys, err := client.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("client.ListAPIKeys: %v", err)
	}
	var keyID string
	for _, k := range keys {
		if k.Name == keyName {
			keyID = k.ID
			break
		}
	}
	if keyID == "" {
		t.Fatalf("could not find key %s in list", keyName)
	}

	// Delete the key.
	out.Reset()
	err = auth.RunKeysDelete(ctx, client, printer, keyID)
	if err != nil {
		t.Fatalf("RunKeysDelete: %v", err)
	}
	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("RunKeysDelete output missing confirmation:\n%s", out.String())
	}

	t.Log("API key lifecycle test passed")
}

// TestIntegration_JSONOutput verifies JSON mode works end-to-end.
func TestIntegration_JSONOutput(t *testing.T) {
	apiURL := envOrSkip(t, "KK_API_URL")
	apiKey := envOrSkip(t, "KK_API_KEY")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, errOut)
	client := api.NewClient(apiURL, apiKey, "test", "linux", "amd64")

	err := auth.RunStatus(context.Background(), client, printer)
	if err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	// In JSON mode, output should be valid JSON.
	got := strings.TrimSpace(out.String())
	if !strings.HasPrefix(got, "{") {
		t.Errorf("JSON output doesn't start with '{': %q", got)
	}
	if !strings.HasSuffix(got, "}") {
		t.Errorf("JSON output doesn't end with '}': %q", got)
	}
	t.Logf("JSON output:\n%s", got)
}

// TestIntegration_InvalidKey verifies that an invalid API key returns ErrAuth.
func TestIntegration_InvalidKey(t *testing.T) {
	apiURL := envOrSkip(t, "KK_API_URL")

	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	printer := output.NewWithWriters("text", true, out, errOut)
	client := api.NewClient(apiURL, "kk_invalid_key_12345", "test", "linux", "amd64")

	err := auth.RunStatus(context.Background(), client, printer)
	if err == nil {
		t.Fatal("expected auth error with invalid key")
	}
	if _, ok := err.(*api.ErrAuth); !ok {
		t.Errorf("err type = %T, want *api.ErrAuth", err)
	}
}
