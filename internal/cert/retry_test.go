package cert_test

import (
	"bytes"
	"context"
	"encoding/json"
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

const (
	retriedLeafPem  = "-----BEGIN CERTIFICATE-----\nretried-leaf\n-----END CERTIFICATE-----\n"
	retriedChainPem = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n"
)

// retryServer simulates POST /certs/tls/42/retry followed by polling: the
// first GET reports "issuing", later GETs report "issued" (or finalStatus).
func retryServer(t *testing.T, finalStatus string, retryCalled *atomic.Bool) *httptest.Server {
	t.Helper()
	var gets atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/certs/tls/42/retry":
			retryCalled.Store(true)
			json.NewEncoder(w).Encode(api.CertResponse{ID: 42, Status: "pending"})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42/chain":
			json.NewEncoder(w).Encode(api.TlsCertChainInfo{FullChainPem: retriedLeafPem + retriedChainPem})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42":
			c := api.TlsCert{
				ID:     42,
				Status: "issuing",
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "retry.example.com"}},
				},
			}
			if gets.Add(1) > 1 {
				c.Status = finalStatus
				if finalStatus == "issued" {
					c.CrtPem = retriedLeafPem
					c.ChainPem = retriedChainPem
				} else {
					c.FailureReason = "ACME challenge delegation missing"
				}
			}
			json.NewEncoder(w).Encode(c)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRunRetry_WaitSavesCert(t *testing.T) {
	dir := t.TempDir()
	var retryCalled atomic.Bool
	srv := retryServer(t, "issued", &retryCalled)
	defer srv.Close()

	printer, out, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRetry: %v", err)
	}
	if !retryCalled.Load() {
		t.Fatal("retry endpoint was not called")
	}

	if got := mustReadFile(t, filepath.Join(dir, "site.crt")); got != retriedLeafPem {
		t.Errorf("cert = %q, want issued leaf", got)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.chain.crt")); got != retriedChainPem {
		t.Errorf("chain = %q, want intermediates", got)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.fullchain.crt")); got != retriedLeafPem+retriedChainPem {
		t.Errorf("fullchain = %q, want leaf + intermediates", got)
	}
	if !strings.Contains(out.String(), "Certificate 42 issued") {
		t.Errorf("output = %q, want 'Certificate 42 issued'", out.String())
	}
}

func TestRunRetry_WaitDefaultFilenames(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var retryCalled atomic.Bool
	srv := retryServer(t, "issued", &retryCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRetry: %v", err)
	}

	want := map[string]string{
		"retry.example.com.crt":           retriedLeafPem,
		"retry.example.com.chain.crt":     retriedChainPem,
		"retry.example.com.fullchain.crt": retriedLeafPem + retriedChainPem,
	}
	for name, content := range want {
		if got := mustReadFile(t, filepath.Join(dir, name)); got != content {
			t.Errorf("%s = %q, want %q", name, got, content)
		}
	}
}

func TestRunRetry_NoWaitWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var retryCalled atomic.Bool
	srv := retryServer(t, "issued", &retryCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	if err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out: filepath.Join(dir, "site.crt"),
	}); err != nil {
		t.Fatalf("RunRetry: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("retry without --wait wrote %d file(s), want none", len(entries))
	}
}

func TestRunRetry_WaitFailedWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var retryCalled atomic.Bool
	srv := retryServer(t, "failed", &retryCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for failed retry")
	}
	if !strings.Contains(err.Error(), "issuance failed after retry: ACME challenge delegation missing") {
		t.Errorf("error = %q, want failure reason", err)
	}

	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("ReadDir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("failed retry wrote %d file(s), want none", len(entries))
	}
}

func TestRunRetry_WaitJSONOutputsIssuedCert(t *testing.T) {
	dir := t.TempDir()
	var retryCalled atomic.Bool
	srv := retryServer(t, "issued", &retryCalled)
	defer srv.Close()

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRetry: %v", err)
	}

	var got api.TlsCert
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v\n%s", err, out.String())
	}
	if got.Status != "issued" || got.CrtPem != retriedLeafPem {
		t.Errorf("JSON = %+v, want the issued certificate", got)
	}
}

func TestRunRetry_NoWaitJSONOutputsResponse(t *testing.T) {
	var retryCalled atomic.Bool
	srv := retryServer(t, "issued", &retryCalled)
	defer srv.Close()

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	if err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{}); err != nil {
		t.Fatalf("RunRetry: %v", err)
	}

	var got api.CertResponse
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v\n%s", err, out.String())
	}
	if got.ID != 42 || got.Status != "pending" {
		t.Errorf("JSON = %+v, want the retry response", got)
	}
}

func TestRunRetry_WaitFullchainRequested_ChainFetchFails(t *testing.T) {
	dir := t.TempDir()
	var retryCalled atomic.Bool
	inner := retryServer(t, "issued", &retryCalled)
	defer inner.Close()
	// Same flow as retryServer, but the chain endpoint fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/certs/tls/42/chain" {
			http.Error(w, `{"statusCode":500,"message":"chain unavailable"}`, http.StatusInternalServerError)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	out := filepath.Join(dir, "site.crt")
	fullchainOut := filepath.Join(dir, "site.fullchain.crt")
	printer, _, _ := newPrinter()
	err := cert.RunRetry(context.Background(), newTestClient(srv.URL), printer, 42, cert.RetryOptions{
		Out:          out,
		FullchainOut: fullchainOut,
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error when --fullchain-out was requested and the chain fetch failed")
	}
	if want := "krakenkey cert download 42 --format fullchain --out " + fullchainOut; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q missing %q", err.Error(), want)
	}
	if got := mustReadFile(t, out); got != retriedLeafPem {
		t.Errorf("cert = %q, want leaf saved before the chain error", got)
	}
	if _, statErr := os.Stat(fullchainOut); !os.IsNotExist(statErr) {
		t.Errorf("fullchain file should not exist, stat err = %v", statErr)
	}
}
