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
	renewedLeafPem  = "-----BEGIN CERTIFICATE-----\nrenewed-leaf\n-----END CERTIFICATE-----\n"
	renewedChainPem = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n"
)

// renewServer simulates POST /certs/tls/42/renew followed by polling: the
// first GET reports "renewing", later GETs report "issued" (or finalStatus).
func renewServer(t *testing.T, finalStatus string, renewCalled *atomic.Bool) *httptest.Server {
	t.Helper()
	var gets atomic.Int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/certs/tls/42/renew":
			renewCalled.Store(true)
			json.NewEncoder(w).Encode(api.CertResponse{ID: 42, Status: "renewing"})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42/chain":
			json.NewEncoder(w).Encode(api.TlsCertChainInfo{FullChainPem: renewedLeafPem + renewedChainPem})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/42":
			c := api.TlsCert{
				ID:     42,
				Status: "renewing",
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "renew.example.com"}},
				},
			}
			if gets.Add(1) > 1 {
				c.Status = finalStatus
				if finalStatus == "issued" {
					c.CrtPem = renewedLeafPem
					c.ChainPem = renewedChainPem
				} else {
					c.FailureReason = "ACME order failed"
				}
			}
			json.NewEncoder(w).Encode(c)
		default:
			http.NotFound(w, r)
		}
	}))
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestRunRenew_WaitSavesRenewedCert(t *testing.T) {
	dir := t.TempDir()
	var renewCalled atomic.Bool
	srv := renewServer(t, "issued", &renewCalled)
	defer srv.Close()

	printer, out, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRenew: %v", err)
	}
	if !renewCalled.Load() {
		t.Fatal("renew endpoint was not called")
	}

	if got := mustReadFile(t, filepath.Join(dir, "site.crt")); got != renewedLeafPem {
		t.Errorf("cert = %q, want renewed leaf", got)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.chain.crt")); got != renewedChainPem {
		t.Errorf("chain = %q, want intermediates", got)
	}
	if got := mustReadFile(t, filepath.Join(dir, "site.fullchain.crt")); got != renewedLeafPem+renewedChainPem {
		t.Errorf("fullchain = %q, want leaf + intermediates", got)
	}
	if !strings.Contains(out.String(), "Certificate 42 renewed") {
		t.Errorf("output = %q, want 'Certificate 42 renewed'", out.String())
	}
}

func TestRunRenew_WaitDefaultFilenames(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var renewCalled atomic.Bool
	srv := renewServer(t, "issued", &renewCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRenew: %v", err)
	}

	want := map[string]string{
		"renew.example.com.crt":           renewedLeafPem,
		"renew.example.com.chain.crt":     renewedChainPem,
		"renew.example.com.fullchain.crt": renewedLeafPem + renewedChainPem,
	}
	for name, content := range want {
		if got := mustReadFile(t, filepath.Join(dir, name)); got != content {
			t.Errorf("%s = %q, want %q", name, got, content)
		}
	}
}

func TestRunRenew_NoWaitWritesNothing(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	var renewCalled atomic.Bool
	srv := renewServer(t, "issued", &renewCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	if err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		Out: filepath.Join(dir, "site.crt"),
	}); err != nil {
		t.Fatalf("RunRenew: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("renew without --wait wrote %d file(s), want none", len(entries))
	}
}

func TestRunRenew_WaitFailedWritesNothing(t *testing.T) {
	dir := t.TempDir()
	var renewCalled atomic.Bool
	srv := renewServer(t, "failed", &renewCalled)
	defer srv.Close()

	printer, _, _ := newPrinter()
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		Out:          filepath.Join(dir, "site.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for failed renewal")
	}
	if !strings.Contains(err.Error(), "ACME order failed") {
		t.Errorf("error = %q, want failure reason", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "site.crt")); !os.IsNotExist(statErr) {
		t.Errorf("certificate file written after failed renewal (stat err: %v)", statErr)
	}
}

func TestRunRenew_WaitJSONOutputsRenewedCert(t *testing.T) {
	dir := t.TempDir()
	var renewCalled atomic.Bool
	srv := renewServer(t, "issued", &renewCalled)
	defer srv.Close()

	out := &bytes.Buffer{}
	printer := output.NewWithWriters("json", true, out, &bytes.Buffer{})
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
		Out:          filepath.Join(dir, "site.crt"),
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: filepath.Join(dir, "site.fullchain.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunRenew: %v", err)
	}

	var got api.TlsCert
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v\n%s", err, out.String())
	}
	if got.Status != "issued" || got.CrtPem != renewedLeafPem {
		t.Errorf("JSON = %+v, want the issued, renewed certificate", got)
	}
}

func TestRunRenew_WaitFullchainRequested_ChainFetchFails(t *testing.T) {
	dir := t.TempDir()
	var renewCalled atomic.Bool
	inner := renewServer(t, "issued", &renewCalled)
	defer inner.Close()
	// Same flow as renewServer, but the chain endpoint fails.
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
	err := cert.RunRenew(context.Background(), newTestClient(srv.URL), printer, 42, cert.RenewOptions{
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
	if got := mustReadFile(t, out); got != renewedLeafPem {
		t.Errorf("cert = %q, want renewed leaf saved before the chain error", got)
	}
	if _, statErr := os.Stat(fullchainOut); !os.IsNotExist(statErr) {
		t.Errorf("fullchain file should not exist, stat err = %v", statErr)
	}
}
