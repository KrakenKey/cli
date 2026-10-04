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

const (
	chainTestLeafPem  = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
	chainTestInterPem = "-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----\n"
)

// chainTestServer serves an issued certificate 10 for issue/submit --wait.
// chainOK controls whether GET /certs/tls/10/chain succeeds or returns 500;
// chainPem is what GET /certs/tls/10 returns as the intermediate chain.
func chainTestServer(t *testing.T, chainOK bool, chainPem string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/certs/tls":
			json.NewEncoder(w).Encode(api.CertResponse{ID: 10, Status: "pending"})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/10/chain":
			if !chainOK {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{"statusCode": 500, "message": "chain unavailable"})
				return
			}
			json.NewEncoder(w).Encode(api.TlsCertChainInfo{FullChainPem: chainTestLeafPem + chainTestInterPem})
		case r.Method == http.MethodGet && r.URL.Path == "/certs/tls/10":
			json.NewEncoder(w).Encode(api.TlsCert{
				ID:       10,
				Status:   "issued",
				CrtPem:   chainTestLeafPem,
				ChainPem: chainPem,
				ParsedCsr: &api.ParsedCsr{
					Subject: []api.CsrSubjectField{{Name: "commonName", Value: "chain.example.com"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func issueOpts(dir string) cert.IssueOptions {
	return cert.IssueOptions{
		Domain:       "chain.example.com",
		KeyType:      "ecdsa-p256",
		KeyOut:       filepath.Join(dir, "site.key"),
		CSROut:       filepath.Join(dir, "site.csr"),
		Out:          filepath.Join(dir, "site.crt"),
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Errorf("%s = %q, want %q", path, string(data), want)
	}
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s exists, want it absent (stat err: %v)", path, err)
	}
}

func TestRunIssue_FullchainRequested_ChainFetchFails(t *testing.T) {
	dir := t.TempDir()
	srv := chainTestServer(t, false, chainTestInterPem)
	defer srv.Close()

	opts := issueOpts(dir)
	opts.FullchainOut = filepath.Join(dir, "site.fullchain.crt")

	printer, _, _ := newPrinter()
	err := cert.RunIssue(context.Background(), newTestClient(srv.URL), printer, opts)
	if err == nil {
		t.Fatal("expected an error when --fullchain-out was requested and the chain fetch failed")
	}
	msg := err.Error()
	for _, want := range []string{
		"certificate 10 was saved to " + opts.Out,
		"full chain was not",
		"chain unavailable",
		"krakenkey cert download 10 --format fullchain --out " + opts.FullchainOut,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}

	// The leaf is still saved so the user only needs to fetch the chain.
	assertFileContent(t, opts.Out, chainTestLeafPem)
	assertNoFile(t, opts.FullchainOut)
}

func TestRunIssue_FullchainNotRequested_ChainFetchFailsWarns(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	srv := chainTestServer(t, false, chainTestInterPem)
	defer srv.Close()

	printer, _, errOut := newPrinter()
	if err := cert.RunIssue(context.Background(), newTestClient(srv.URL), printer, issueOpts(dir)); err != nil {
		t.Fatalf("RunIssue: %v (want success with a warning when no fullchain output was requested)", err)
	}

	if !strings.Contains(errOut.String(), "Warning: full chain not saved") ||
		!strings.Contains(errOut.String(), "krakenkey cert download 10 --format fullchain") {
		t.Errorf("stderr = %q, want a full chain warning with the download command", errOut.String())
	}
	assertFileContent(t, filepath.Join(dir, "site.crt"), chainTestLeafPem)
	assertNoFile(t, filepath.Join(dir, "chain.example.com.fullchain.crt"))
}

func TestRunIssue_ChainRequested_NoChainInResponse(t *testing.T) {
	dir := t.TempDir()
	srv := chainTestServer(t, true, "")
	defer srv.Close()

	opts := issueOpts(dir)
	opts.ChainOut = filepath.Join(dir, "site.chain.crt")
	opts.FullchainOut = filepath.Join(dir, "site.fullchain.crt")

	printer, _, _ := newPrinter()
	err := cert.RunIssue(context.Background(), newTestClient(srv.URL), printer, opts)
	if err == nil {
		t.Fatal("expected an error when --chain-out was requested and no chain was returned")
	}
	if !strings.Contains(err.Error(), "intermediate chain was not") ||
		!strings.Contains(err.Error(), "krakenkey cert download 10 --format chain --out "+opts.ChainOut) {
		t.Errorf("error = %q, want intermediate chain message with download command", err)
	}
	assertNoFile(t, opts.ChainOut)
	// The full chain could still be fetched, so it is written.
	assertFileContent(t, opts.FullchainOut, chainTestLeafPem+chainTestInterPem)
}

func TestRunSubmit_FullchainRequested_ChainFetchFails(t *testing.T) {
	dir := t.TempDir()
	srv := chainTestServer(t, false, chainTestInterPem)
	defer srv.Close()

	out := filepath.Join(dir, "site.crt")
	fullchainOut := filepath.Join(dir, "site.fullchain.crt")
	printer, _, _ := newPrinter()
	err := cert.RunSubmit(context.Background(), newTestClient(srv.URL), printer, cert.SubmitOptions{
		CSRPath:      writeCSRFile(t, dir, "site.csr"),
		Out:          out,
		ChainOut:     filepath.Join(dir, "site.chain.crt"),
		FullchainOut: fullchainOut,
		Wait:         true,
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error when --fullchain-out was requested and the chain fetch failed")
	}
	if !strings.Contains(err.Error(), "certificate 10 was saved to "+out) ||
		!strings.Contains(err.Error(), "krakenkey cert download 10 --format fullchain --out "+fullchainOut) {
		t.Errorf("error = %q, want saved-leaf message with download command", err)
	}
	assertFileContent(t, out, chainTestLeafPem)
	assertFileContent(t, filepath.Join(dir, "site.chain.crt"), chainTestInterPem)
	assertNoFile(t, fullchainOut)
}
